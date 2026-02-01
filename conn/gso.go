// GSO: generic segmentation offload.
// Application combines several packets into one,
// sends to kernel, kernel sends to NIC,
// NIC splits one packet into standard several packets,
// and sends them over the network.
package conn

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// size of value containing the size of GSO data
	sizeOfGSOData = 2
)

// gsoControlSize returns the recommended buffer size for pooling UDP
// offloading control data.
var gsoControlSize = unix.CmsgSpace(sizeOfGSOData)

// type Cmsghdr struct {
//     Len   uint64 // total length of the control message (including header and data)
//     Level int32  // originating protocol level (e.g., SOL_SOCKET, SOL_UDP)
//     Type  int32  // protocol-specific type (e.g., UDP_SEGMENT, UDP_GRO)
// }

// getGSOSize parses control for UDP_GRO and if found returns its GSO size data.
// control is Message.OOB.
func getGSOSize(control []byte) (int, error) {
	var (
		hdr       unix.Cmsghdr
		data      []byte
		remainder = control
		err       error
	)
	for len(remainder) > unix.SizeofCmsghdr {
		hdr, data, remainder, err = unix.ParseOneSocketControlMessage(remainder)
		if err != nil {
			return 0, fmt.Errorf("error parsing socket control message: %w", err)
		}
		// SOL_UDP: socket option level for UDP.
		// UDP_GRO: generic receive offload (GRO).
		// 	NIC combines multiple incoming packets into one large packet.
		// 	Kernel delivers them as a single datagram to userspace.
		// 	Opposite of GSO (which splits on transmit).
		if hdr.Level == unix.SOL_UDP && hdr.Type == unix.UDP_GRO && len(data) >= sizeOfGSOData {
			var gso uint16
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&gso)), sizeOfGSOData), data[:sizeOfGSOData])
			return int(gso), nil
		}
	}
	return 0, nil
}

// setGSOSize sets a UDP_SEGMENT in control based on gsoSize. It leaves existing
// data in control untouched.
func setGSOSize(control *[]byte, gsoSize uint16) {
	length := len(*control)
	capacity := cap(*control)
	available := capacity - length
	// func CmsgSpace(datalen int) int {
	// 	return cmsgAlignOf(SizeofCmsghdr) + cmsgAlignOf(datalen)
	// }
	space := unix.CmsgSpace(sizeOfGSOData)
	if available < space {
		return
	}
	*control = (*control)[:capacity]
	gsoControl := (*control)[length:]
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&gsoControl[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	// func (cmsg *Cmsghdr) SetLen(length int) {
	// 	cmsg.Len = uint64(length)
	// }
	// func CmsgLen(datalen int) int {
	// 	return cmsgAlignOf(SizeofCmsghdr) + datalen
	// }
	hdr.SetLen(unix.CmsgLen(sizeOfGSOData))
	copy(gsoControl[unix.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&gsoSize)), sizeOfGSOData))
	*control = (*control)[:length+space]
}
