// sticky sockets is preservation and reuse of source address information
// (IP address and interface index) across multiple send operations.

package conn

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

const NetSupportsStickySockets = true

// stickyControlSize returns the recommended buffer size for pooling sticky
// offloading control data.
var stickyControlSize = unix.CmsgSpace(unix.SizeofInet6Pktinfo)

func (e *NetEndpoint) SrcIP() netip.Addr {
	switch len(e.src) {
	// 1. Ifindex (Interface Index)
	//     Identifies which network interface received the packet
	//     Each interface has a unique index (e.g., 1 for lo, 2 for eth0)
	//     Use unix.IfNametoindex("eth0") to get index by name
	// 2. Spec_dst (Specific Destination)
	//     The local IP address that should be used for replies
	//     Critical for multi-homed hosts (multiple IPs on one interface)
	//     Helps determine which source address to use
	// 3. Addr (Header Destination)
	//     The destination IP address from the IP header
	//     Usually the same as what you'd see in regular socket operations
	case unix.CmsgSpace(unix.SizeofInet4Pktinfo):
		info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&e.src[unix.CmsgLen(0)]))
		return netip.AddrFrom4(info.Spec_dst)
	case unix.CmsgSpace(unix.SizeofInet6Pktinfo):
		info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&e.src[unix.CmsgLen(0)]))
		// TODO: set zone. in order to do so we need to check if the address is
		// link local, and if it is perform a syscall to turn the ifindex into a
		// zone string because netip uses string zones.
		return netip.AddrFrom16(info.Addr)
	}
	return netip.Addr{}
}

func (e *NetEndpoint) SrcIfidx() int32 {
	switch len(e.src) {
	case unix.CmsgSpace(unix.SizeofInet4Pktinfo):
		info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&e.src[unix.CmsgLen(0)]))
		return info.Ifindex
	case unix.CmsgSpace(unix.SizeofInet6Pktinfo):
		info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&e.src[unix.CmsgLen(0)]))
		return int32(info.Ifindex)
	}
	return 0
}

func (e *NetEndpoint) SrcToString() string {
	return e.SrcIP().String()
}

// getSrcFromControl parses the control for PKTINFO and if found updates ep with
// the source information found.
func getSrcFromControl(control []byte, ep *NetEndpoint) {
	ep.ClearSrc()
	var (
		hdr       unix.Cmsghdr
		data      []byte
		remaining []byte = control
		err       error
	)
	for len(remaining) > unix.SizeofCmsghdr {
		hdr, data, remaining, err = unix.ParseOneSocketControlMessage(remaining)
		if err != nil {
			return
		}
		if hdr.Level == unix.IPPROTO_IP &&
			hdr.Type == unix.IP_PKTINFO {
			if ep.src == nil || cap(ep.src) < unix.CmsgSpace(unix.SizeofInet4Pktinfo) {
				ep.src = make([]byte, 0, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
			}
			ep.src = ep.src[:unix.CmsgSpace(unix.SizeofInet4Pktinfo)]
			hdrBuf := unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), unix.SizeofCmsghdr)
			copy(ep.src, hdrBuf)
			copy(ep.src[unix.CmsgLen(0):], data)
			return
		}
		if hdr.Level == unix.IPPROTO_IPV6 &&
			hdr.Type == unix.IPV6_PKTINFO {
			if ep.src == nil || cap(ep.src) < unix.CmsgSpace(unix.SizeofInet6Pktinfo) {
				ep.src = make([]byte, 0, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
			}
			ep.src = ep.src[:unix.CmsgSpace(unix.SizeofInet6Pktinfo)]
			hdrBuf := unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), unix.SizeofCmsghdr)
			copy(ep.src, hdrBuf)
			copy(ep.src[unix.CmsgLen(0):], data)
			return
		}
	}
}

// setSrcControl sets an IP{V6}_PKTINFO in control based on the source address
// and source ifindex found in ep.
// control's len will be set to 0 in the event that ep is a default value.
func setSrcControl(control *[]byte, ep *NetEndpoint) {
	if cap(*control) < len(ep.src) {
		return
	}
	*control = (*control)[:0]
	*control = append(*control, ep.src...)
}
