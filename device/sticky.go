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

type netlinkMsg struct {
	hdr     unix.NlMsghdr
	msg     unix.RtMsg
	dsthdr  unix.RtAttr
	dst     [4]byte
	srchdr  unix.RtAttr
	src     [4]byte
	markhdr unix.RtAttr
	mark    uint32
}

// routineRouteListener monitors network routing changes and updates
// peer endpoints with the correct source interface index.
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
	var reqPeer peerEndpointMap
	var reqPeerMu sync.Mutex
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
								reqPeerMu.Lock()
								if reqPeer == nil {
									reqPeerMu.Unlock()
									break
								}
								pe, ok := reqPeer[hdr.Seq]
								reqPeerMu.Unlock()
								if !ok {
									break
								}
								pe.peer.endpoint.Lock()
								if &pe.peer.endpoint.val != pe.endpoint {
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
				reqPeerMu.Lock()
				reqPeer = make(peerEndpointMap)
				reqPeerMu.Unlock()
				go func() {
					d.peers.RLock()
					var i uint32 = 1
					for _, peer := range d.peers.val {
						peer.endpoint.Lock()
						if peer.endpoint.val == nil {
							peer.endpoint.Unlock()
							continue
						}
						nativeEP, _ := peer.endpoint.val.(*conn.NetEndpoint)
						if nativeEP == nil {
							peer.endpoint.Unlock()
							continue
						}
						if nativeEP.DstIP().Is6() || nativeEP.SrcIfidx() == 0 {
							peer.endpoint.Unlock()
							break
						}
						nlmsg := netlinkMsg{
							unix.NlMsghdr{
								Type:  uint16(unix.RTM_GETROUTE),
								Flags: unix.NLM_F_REQUEST,
								Seq:   i,
							},
							unix.RtMsg{
								Family:  unix.AF_INET,
								Dst_len: 32,
								Src_len: 32,
							},
							unix.RtAttr{
								Len:  8,
								Type: unix.RTA_DST,
							},
							nativeEP.DstIP().As4(),
							unix.RtAttr{
								Len:  8,
								Type: unix.RTA_SRC,
							},
							nativeEP.SrcIP().As4(),
							unix.RtAttr{
								Len:  8,
								Type: unix.RTA_MARK,
							},
							d.net.fwmark,
						}
						nlmsg.hdr.Len = uint32(unsafe.Sizeof(nlmsg))
						reqPeerMu.Lock()
						reqPeer[i] = peerEndpoint{
							peer:     peer,
							endpoint: &peer.endpoint.val,
						}
						reqPeerMu.Unlock()
						peer.endpoint.Unlock()
						i++
						_, err := netlinkCancel.Write((*[unsafe.Sizeof(nlmsg)]byte)(unsafe.Pointer(&nlmsg))[:])
						if err != nil {
							break
						}
					}
					d.peers.RUnlock()
				}()
			}
			remainder = remainder[hdr.Len:]
		}
	}
}
