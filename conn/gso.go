// GSO (Generic Segmentation Offload):
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
	// length of value containing the size of GSO data
	gsoDataLen = 2
)

// gsoControlSize returns the recommended buffer size
// for pooling UDP offloading control data.
var gsoControlSize = unix.CmsgSpace(gsoDataLen)

// type Cmsghdr struct {
//     // total length of the control message (including header and data)
//     Len   uint64
//     // originating protocol level (e.g., SOL_SOCKET, SOL_UDP)
//     Level int32
// 	   // protocol-specific type (e.g., UDP_SEGMENT, UDP_GRO)
//     Type  int32
// }

// getGSOSize parses control for UDP_GRO and if found returns
// its GSO size data. `control` is msg.OOB[:msg.NN].
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
			return 0, fmt.Errorf(
				"error parsing socket control message: %w",
				err,
			)
		}
		// SOL_UDP: socket option level for UDP.
		// UDP_GRO: generic receive offload (GRO).
		// 	NIC combines multiple incoming packets into one large packet.
		// 	Kernel delivers them as a single datagram to userspace.
		// 	Application splits large datagram into multiple standard packets.
		if hdr.Level == unix.SOL_UDP &&
			hdr.Type == unix.UDP_GRO &&
			len(data) >= gsoDataLen {
			var gso uint16
			copy(
				unsafe.Slice((*byte)(unsafe.Pointer(&gso)), gsoDataLen),
				data[:gsoDataLen],
			)
			return int(gso), nil
		}
	}
	return 0, nil
}

// setGSOSize sets UDP_SEGMENT in control based on gsoSize.
// It leaves existing data in control untouched.
func setGSOSize(control *[]byte, gsoSize uint16) {
	length := len(*control)
	capacity := cap(*control)
	available := capacity - length
	// func CmsgSpace(datalen int) int {
	// 	return cmsgAlignOf(SizeofCmsghdr) + cmsgAlignOf(datalen)
	// }
	space := unix.CmsgSpace(gsoDataLen)
	if space > available {
		return
	}
	// TODO: not sure why it isn't `*control = (*control)[:length+space]`.
	// Defensive programming?
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
	hdr.SetLen(unix.CmsgLen(gsoDataLen))
	// copy gsoSize size into CmsgLen payload
	copy(
		// unix.CmsgLen(0) gives header length (payload start index)
		gsoControl[unix.CmsgLen(0):],
		unsafe.Slice((*byte)(unsafe.Pointer(&gsoSize)), gsoDataLen),
	)
	*control = (*control)[:length+space]
}
