// This implements userspace semantics of "sticky sockets", modeled after
// WireGuard's kernelspace implementation. This is more or less a straight port
// of the sticky-sockets.c example code:
// https://git.zx2c4.com/WireGuard/tree/contrib/examples/sticky-sockets/sticky-sockets.c

// Currently there is no way to achieve this within the net package:
// See e.g. https://github.com/golang/go/issues/17930
// So this code remains platform dependent.
package device

import (
	"sync"
	"unsafe"

	"github.com/muhtutorials/wireguard/conn"
	"github.com/muhtutorials/wireguard/rwcancel"
	"golang.org/x/sys/unix"
)

func (d *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	if !conn.NetSupportsStickySockets {
		return nil, nil
	}
	if _, ok := bind.(*conn.NetBind); !ok {
		return nil, nil
	}
	netlinkSock, err := createNetlinkRouteSocket()
	if err != nil {
		return nil, err
	}
	netlinkCancel, err := rwcancel.New(netlinkSock)
	if err != nil {
		unix.Close(netlinkSock)
		return nil, err
	}
	go d.routineRouteListener(bind, netlinkSock, netlinkCancel)
	return netlinkCancel, nil
}

func createNetlinkRouteSocket() (int, error) {
	sock, err := unix.Socket(
		unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC,
		unix.NETLINK_ROUTE,
	)
	if err != nil {
		return -1, err
	}
	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_IPV4_ROUTE,
	}
	if err = unix.Bind(sock, addr); err != nil {
		unix.Close(sock)
		return -1, err
	}
	return sock, nil
}

type peerEndpoint struct {
	peer     *Peer
	endpoint *conn.Endpoint
}

type peerEndpointMap map[uint32]peerEndpoint

// netlinkMsg is used by the Linux kernel's WireGuard module to
// communicate configuration details (like interface addresses,
// routes, and routing marks) between user space and kernel space.
type netlinkMsg struct {
	// The standard Netlink message header. It contains fields like
	// message length and type, which are essential for the kernel
	// to parse the rest of the message.
	hdr unix.NlMsghdr
	// The main routing message header. This struct holds the core
	// information for a routing-related Netlink request,
	// such as the address family (e.g., IPv4), the route's scope,
	// and the routing table ID.
	msg unix.RtMsg
	// A header for a Netlink attribute that describes
	// the destination address.
	dsthdr unix.RtAttr
	// The actual destination IPv4 address.
	dst [4]byte
	// A header for a Netlink attribute that describes
	// the source address.
	srchdr unix.RtAttr
	// The actual source IPv4 address.
	src [4]byte
	// A header for a Netlink attribute that describes
	// the routing mark (fwmark).
	markhdr unix.RtAttr
	// The actual 32-bit routing mark value. This is used for
	// policy routing, allowing the system to make routing
	// decisions based on this mark.
	mark uint32
}

// routineRouteListener monitors network routing changes and updates
// peer endpoints with the correct source interface index.
// Implemented only for IPv4.
//
// Example Scenario
// Initial state: Peer endpoint uses interface eth0 (ifidx=2).
// Route change: User switches to WiFi (wlan0, ifidx=3).
// Kernel notification: RTM_NEWROUTE message received.
// Query: Listener queries kernel for each peer's new route.
// Response: Kernel indicates wlan0 (ifidx=3) should now be used.
// Update: clearSrcOnTx flag set, next packet will use correct interface.
func (d *Device) routineRouteListener(
	_ conn.Bind,
	netlinkSock int,
	netlinkCancel *rwcancel.RWCancel,
) {
	defer unix.Close(netlinkSock)
	defer netlinkCancel.Close()
	var peerEndpoints peerEndpointMap
	var peerEndpointsMu sync.Mutex
	msg := make([]byte, 1<<16) // 65536 bytes
	for {
		var n int
		var err error
		for {
			n, _, _, _, err = unix.Recvmsg(netlinkSock, msg[:], nil, 0)
			if err == nil || !rwcancel.RetriableError(err) {
				break
			}
			if !netlinkCancel.ReadyRead() {
				return
			}
		}
		if err != nil {
			return
		}
		// parse msg
		// msg[:n] = [SizeofNlMsghdr+SizeofRtMsg+SizeofRtAttr]
		for remainder := msg[:n]; len(remainder) >= unix.SizeofNlMsghdr; {
			hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remainder[0]))
			// hdr.Len = NlMsghdr + RtMsg + all attributes
			if uint(hdr.Len) > uint(len(remainder)) {
				break
			}
			switch hdr.Type {
			case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
				// hdr.Seq is the sequence number field in the netlink message header.
				// It's used to match requests with responses in netlink communication.
				if hdr.Seq <= MaxPeers && hdr.Seq > 0 {
					// RtMsg is a route message header
					if hdr.Len > unix.SizeofNlMsghdr+unix.SizeofRtMsg {
						rtAttrSlice := remainder[unix.SizeofNlMsghdr+unix.SizeofRtMsg:]
						for {
							// SizeofRtAttr is the size of a routing attribute header
							if uint(len(rtAttrSlice)) < uint(unix.SizeofRtAttr) {
								break
							}
							// route attribute header
							rtAttrHdr := *(*unix.RtAttr)(unsafe.Pointer(&rtAttrSlice[0]))
							// rtAttrHdr.Len = header + payload
							if rtAttrHdr.Len < unix.SizeofRtAttr || uint(len(rtAttrSlice)) < uint(rtAttrHdr.Len) {
								break
							}
							// unix.SizeofRtAttr+4 is the size of rtAttrHdr plus the size of
							// payload (output interface index) which is an uint32 (4 bytes).
							// RTA_OIF is output interface index.
							if rtAttrHdr.Type == unix.RTA_OIF && rtAttrHdr.Len == unix.SizeofRtAttr+4 {
								ifidx := *(*uint32)(unsafe.Pointer(&rtAttrSlice[unix.SizeofRtAttr]))
								peerEndpointsMu.Lock()
								if peerEndpoints == nil {
									peerEndpointsMu.Unlock()
									break
								}
								pe, ok := peerEndpoints[hdr.Seq]
								peerEndpointsMu.Unlock()
								if !ok {
									break
								}
								pe.peer.endpoint.Lock()
								// compare memory addresses to check if the endpoint is still the same one we queried
								if &pe.peer.endpoint.val != pe.endpoint {
									// endpoint changed (stale response)
									pe.peer.endpoint.Unlock()
									break
								}
								if uint32(pe.peer.endpoint.val.(*conn.NetEndpoint).SrcIfidx()) == ifidx {
									pe.peer.endpoint.Unlock()
									break
								}
								pe.peer.endpoint.clearSrcOnTx = true
								pe.peer.endpoint.Unlock()
							}
							rtAttrSlice = rtAttrSlice[rtAttrHdr.Len:]
						}
					}
					break
				}
				peerEndpointsMu.Lock()
				peerEndpoints = make(peerEndpointMap)
				peerEndpointsMu.Unlock()
				go func() {
					d.peers.RLock()
					defer d.peers.RUnlock()
					var i uint32 = 1
					for _, peer := range d.peers.val {
						peer.endpoint.Lock()
						if peer.endpoint.val == nil {
							peer.endpoint.Unlock()
							continue
						}
						nativeEndpoint, _ := peer.endpoint.val.(*conn.NetEndpoint)
						if nativeEndpoint == nil {
							peer.endpoint.Unlock()
							continue
						}
						if nativeEndpoint.DstIP().Is6() || nativeEndpoint.SrcIfidx() == 0 {
							peer.endpoint.Unlock()
							break
						}
						nlmsg := netlinkMsg{
							hdr: unix.NlMsghdr{
								Type:  uint16(unix.RTM_GETROUTE),
								Flags: unix.NLM_F_REQUEST,
								Seq:   i,
							},
							msg: unix.RtMsg{
								Family:  unix.AF_INET,
								Dst_len: 32,
								Src_len: 32,
							},
							dsthdr: unix.RtAttr{
								Len:  8,
								Type: unix.RTA_DST,
							},
							dst: nativeEndpoint.DstIP().As4(),
							srchdr: unix.RtAttr{
								Len:  8,
								Type: unix.RTA_SRC,
							},
							src: nativeEndpoint.SrcIP().As4(),
							markhdr: unix.RtAttr{
								Len:  8,
								Type: unix.RTA_MARK,
							},
							mark: d.net.fwmark,
						}
						nlmsg.hdr.Len = uint32(unsafe.Sizeof(nlmsg))
						peerEndpointsMu.Lock()
						peerEndpoints[i] = peerEndpoint{
							peer: peer,
							// captures the specific endpoint value, not just current one
							endpoint: &peer.endpoint.val,
						}
						peerEndpointsMu.Unlock()
						peer.endpoint.Unlock()
						i++
						_, err := netlinkCancel.Write((*[unsafe.Sizeof(nlmsg)]byte)(unsafe.Pointer(&nlmsg))[:])
						if err != nil {
							break
						}
					}
				}()
			}
			remainder = remainder[hdr.Len:]
		}
	}
}
