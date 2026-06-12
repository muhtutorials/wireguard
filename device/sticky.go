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
	if _, ok := bind.(*conn.NetBind); !ok {
		return nil, nil
	}
	netlinkSock, err := createNetlinkRouteSocket()
	if err != nil {
		return nil, err
	}
	netlinkRWCancel, err := rwcancel.New(netlinkSock)
	if err != nil {
		unix.Close(netlinkSock)
		return nil, err
	}
	go d.routineRouteListener(netlinkSock, netlinkRWCancel)
	return netlinkRWCancel, nil
}

func createNetlinkRouteSocket() (int, error) {
	sock, err := unix.Socket(
		// Protocol family constant (Address Family) used to create
		// a netlink socket for communication between userspace
		// processes and the Linux kernel.
		unix.AF_NETLINK,
		// SOCK_RAW: provides direct access to network packets at the
		// transport layer (TCP/UDP) or network layer (IP/ICMP).
		// SOCK_CLOEXEC: socket creation flag that automatically sets
		// the FD_CLOEXEC (close-on-exec) flag on the newly created file
		// descriptor. Flag ensures that the socket (or any file descriptor)
		// is automatically closed when a process calls exec() to execute
		// a new program.
		unix.SOCK_RAW|unix.SOCK_CLOEXEC,
		// subscribe to routing/network events
		unix.NETLINK_ROUTE,
	)
	if err != nil {
		return -1, err
	}
	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		// Multicast group constant used for routing sockets.
		// Whenever the system's IPv4 routing table changes
		// (e.g., a route is added, deleted, or modified),
		// the kernel broadcasts a message through the
		// RTMGRP_IPV4_ROUTE multicast channel. Any userspace
		// program subscribed to this group can receive these
		// updates in real-time, avoiding the need for
		// inefficient polling of the routing table.
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
// communicate configuration details (interface addresses, routes,
// and routing marks) between userspace and kernelspace.
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
// Implemented only for IPv4. IPv6 has native sticky socket support.
// IPv6 was designed with advanced socket APIs that solve this
// problem without netlink hacks.
//
// Example Scenario
// Initial state: Peer endpoint uses interface eth0 (ifidx=2).
// Route change: User switches to Wi-Fi (wlan0, ifidx=3).
// Kernel notification: RTM_NEWROUTE message received.
// Query: Listener queries kernel for each peer's new route.
// Response: Kernel indicates wlan0 (ifidx=3) should now be used.
// Update: clearSrcOnTx flag set, next packet will use correct interface.
//
// TIME    EVENT                           SOURCE IP       DESTINATION     RESULT
// ─────────────────────────────────────────────────────────────────────────────────
// T0      Initial connection
//
//   - Laptop on ethernet
//
//   - Peer at 203.0.113.5
//
//     WireGuard sends handshake      192.168.1.100   203.0.113.5     ✓ Sent
//     (eth0, ifidx=2)
//
//     Peer responds                  203.0.113.5     192.168.1.100   ✓ Received
//     Handshake complete
//     Session established
//
// ─────────────────────────────────────────────────────────────────────────────────
// T1      Normal operation
//
//	Both sides communicating
//
//	WireGuard → Peer               192.168.1.100   203.0.113.5     ✓ OK
//	Peer → WireGuard               203.0.113.5     192.168.1.100   ✓ OK
//
// ─────────────────────────────────────────────────────────────────────────────────
// T2      USER DISCONNECTS ETHERNET
//
//   - eth0 goes down
//
//   - Kernel removes route via eth0
//
//   - Kernel adds route via wlan0
//
//   - wlan0 IP: 192.168.2.100
//
//   - ifidx changes: 2 → 3
//
//     KERNEL SENDS NETLINK NOTIFICATION
//     RTM_DELROUTE (eth0 route)
//     RTM_NEWROUTE (wlan0 route)
//     ↓
//     WireGuard route listener receives update
//
// ─────────────────────────────────────────────────────────────────────────────────
// T3      WITHOUT STICKY SOCKETS (broken)
//
//	WireGuard sends next packet    192.168.2.100   203.0.113.5     ✗ Sent
//	(kernel auto-chooses wlan0)    (WRONG IP!)
//
//	Peer receives packet
//	Peer checks: "Expected from    192.168.2.100   203.0.113.5     ✗ DROPPED
//	192.168.1.100, got 192.168.2.100"   (MISMATCH)
//
//	Peer drops packet as spoofed
//	Connection dies
//
// ─────────────────────────────────────────────────────────────────────────────────
// T3      WITH STICKY SOCKETS (works)
//
//	Route listener wakes up
//
//	For each peer (203.0.113.5):
//	Query kernel: "What's best route to 203.0.113.5?"
//	Kernel responds: "Use wlan0, ifidx=3, src=192.168.2.100"
//
//	WireGuard updates peer endpoint:
//	Old: src=192.168.1.100, ifidx=2
//	New: src=192.168.2.100, ifidx=3
//	Set flag: clearSrcOnTx = true
//
//	Next packet to send:
//	Check clearSrcOnTx flag → true
//	Re-bind socket to 192.168.2.100
//	Send packet                    192.168.2.100   203.0.113.5    ✓ Sent
//
//	Peer receives packet:
//	"Packet from 192.168.2.100 -
//	that's the new source IP"    192.168.2.100   203.0.113.5    ✓ ACCEPT
//
//	Connection continues seamlessly
//
// ─────────────────────────────────────────────────────────────────────────────────
// routineRouteListener only used for setting `clearSrcOnTx`
// to true in case of interface change.
func (d *Device) routineRouteListener(
	netlinkSock int,
	netlinkRWCancel *rwcancel.RWCancel,
) {
	defer unix.Close(netlinkSock)
	defer netlinkRWCancel.Close()
	var (
		peerEndpoints   peerEndpointMap
		peerEndpointsMu sync.Mutex
	)
	msg := make([]byte, 1<<16) // 65536 bytes
	for {
		var (
			n   int
			err error
		)
		for {
			n, _, _, _, err = unix.Recvmsg(netlinkSock, msg[:], nil, 0)
			if err == nil || !rwcancel.RetriableError(err) {
				break
			}
			if !netlinkRWCancel.ReadyRead() {
				return
			}
		}
		if err != nil {
			return
		}
		// parse msg
		// msg[:n] = [SizeofNlMsghdr+SizeofRtMsg+SizeofRtAttr]
		for remainder := msg[:n]; len(remainder) >= unix.SizeofNlMsghdr; {
			// NlMsghdr: netlink message header
			nlmsghdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remainder[0]))
			// nlmsghdr.Len = NlMsghdr + RtMsg + all attributes
			if uint(nlmsghdr.Len) > uint(len(remainder)) {
				break
			}
			switch nlmsghdr.Type {
			// RTM_NEWROUTE: signal that a routing table entry (route)
			// is being created or has been updated.
			// RTM_DELROUTE: signal that a routing table entry (route)
			// has been deleted.
			case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
				// nlmsghdr.Seq is the sequence number field in the netlink message header.
				// It's used to match requests with responses in netlink communication.
				if nlmsghdr.Seq > 0 && nlmsghdr.Seq <= MaxPeers {
					// RtMsg: route message header
					if nlmsghdr.Len > unix.SizeofNlMsghdr+unix.SizeofRtMsg {
						rtAttrSlice := remainder[unix.SizeofNlMsghdr+unix.SizeofRtMsg:]
						for {
							// SizeofRtAttr: size of a routing attribute header
							if len(rtAttrSlice) < unix.SizeofRtAttr {
								break
							}
							// RtAttr: route attribute header
							rtAttr := *(*unix.RtAttr)(unsafe.Pointer(&rtAttrSlice[0]))
							// rtAttr.Len = header + payload
							if rtAttr.Len < unix.SizeofRtAttr ||
								uint(rtAttr.Len) > uint(len(rtAttrSlice)) {
								break
							}
							// `unix.SizeofRtAttr+4` is the size of rtAttr plus the size of
							// payload (output interface index) which is an uint32 (4 bytes).
							// RTA_OIF: output interface index.
							if rtAttr.Type == unix.RTA_OIF &&
								rtAttr.Len == unix.SizeofRtAttr+4 {
								ifidx := *(*uint32)(unsafe.Pointer(&rtAttrSlice[unix.SizeofRtAttr]))
								peerEndpointsMu.Lock()
								if peerEndpoints == nil {
									peerEndpointsMu.Unlock()
									break
								}
								pe, ok := peerEndpoints[nlmsghdr.Seq]
								peerEndpointsMu.Unlock()
								if !ok {
									break
								}
								pe.peer.endpoint.Lock()
								// compare memory addresses to check if the endpoint
								// is still the same one we queried
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
							rtAttrSlice = rtAttrSlice[rtAttr.Len:]
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
					// starts at 1 because 0 is reserved for asynchronous,
					// unsolicited kernel messages (notifications)
					var seq uint32 = 1
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
							continue
						}
						nlmsg := netlinkMsg{
							hdr: unix.NlMsghdr{
								// request route information from the kernel
								Type: uint16(unix.RTM_GETROUTE),
								// message requires a response
								Flags: unix.NLM_F_REQUEST,
								Seq:   seq,
							},
							msg: unix.RtMsg{
								// Address family - internet. Uses IPv4 addresses for networking.
								Family:  unix.AF_INET,
								Dst_len: 32,
								Src_len: 32,
							},
							dsthdr: unix.RtAttr{
								Len: 8,
								// RTA_DST: route attribute destination. Indicates that the attribute's
								// data contains the destination IP address for the route.
								Type: unix.RTA_DST,
							},
							dst: nativeEndpoint.DstIP().As4(),
							srchdr: unix.RtAttr{
								Len: 8,
								// RTA_SRC: route attribute source. Indicates that the attribute's
								// data contains the source IP address for the route.
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
						peerEndpoints[seq] = peerEndpoint{
							peer: peer,
							// captures the specific endpoint value, not just current one
							endpoint: &peer.endpoint.val,
						}
						peerEndpointsMu.Unlock()
						peer.endpoint.Unlock()
						seq++
						_, err := netlinkRWCancel.Write(
							unsafe.Slice((*byte)(unsafe.Pointer(&nlmsg)), unsafe.Sizeof(nlmsg)),
						)
						if err != nil {
							break
						}
					}
				}()
			}
			remainder = remainder[nlmsghdr.Len:]
		}
	}
}
