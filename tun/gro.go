// GRO (Generic Receive Offload)
package tun

import (
	"encoding/binary"
	"io"
	"unsafe"

	"github.com/muhtutorials/wireguard/conn"
)

// flags are in the 14th byte of a TCP header
const tcpFlagsOffset = 13

//	            14th byte
//		   |0 1 2 3 4 5 6 7|
//
// +-+-+-+-+-+-+-+-+-+-+-+-+
// |           |U|A|P|R|S|F|
// | Reserved  |R|C|S|S|Y|I|
// |           |G|K|H|T|N|N|
// +-+-+-+-+-+-+-+-+-+-+-+-+
const (
	tcpFlagFIN uint8 = 0x01 // 1 (first bit is set)
	tcpFlagPSH uint8 = 0x08 // 8 (4th bit is set)
	tcpFlagACK uint8 = 0x10 // 16 (5th bit is set)
)

const (
	// virtioNetHdrLen is the length in bytes of virtioNetHdr. This matches the
	// shape of the C ABI for its kernel counterpart -- sizeof(virtio_net_hdr).
	virtioNetHdrLen = int(unsafe.Sizeof(virtioNetHdr{}))
)

// virtioNetHdr is defined in the kernel in include/uapi/linux/virtio_net.h.
// The kernel symbol is virtio_net_hdr.
type virtioNetHdr struct {
	// Bitmask of features/packet attributes:
	// Bit 0 (VIRTIO_NET_HDR_F_NEEDS_CSUM): packet needs checksum calculation
	// Bit 1 (VIRTIO_NET_HDR_F_DATA_VALID): checksum is already valid (host→guest)
	// Bit 2 (VIRTIO_NET_HDR_F_RSC_INFO): receive Segment Coalescing info present
	// Bit 3 (VIRTIO_NET_HDR_F_MRG_RXBUF): mergeable RX buffers supported
	flags uint8
	// Generic Segmentation Offload type - indicates how to segment large packets:
	// VIRTIO_NET_HDR_GSO_NONE: No GSO (normal packet)
	// VIRTIO_NET_HDR_GSO_TCPV4: TCP/IPv4 segmentation
	// VIRTIO_NET_HDR_GSO_UDP: UDP segmentation (UFO)
	// VIRTIO_NET_HDR_GSO_TCPV6: TCP/IPv6 segmentation
	// VIRTIO_NET_HDR_GSO_ECN: TCP with ECN (Explicit Congestion Notification)
	gsoType uint8
	// Header length - for GSO packets:
	// Length of headers before payload starts
	// Includes Ethernet + IP + TCP/UDP headers
	// Device should copy these headers to each segment
	hdrLen uint16
	// Maximum Segment Size for GSO:
	// Maximum size of each segment after segmentation
	// Excludes headers (payload only)
	// Example: gsoSize = 1448 for MTU 1500 (1500 - 52 headers)
	gsoSize uint16
	// Checksum start offset from beginning of packet:
	// Position where checksum calculation should begin
	// Usually points to IP header (after Ethernet header)
	// Example: Ethernet(14) → csumStart = 14
	csumStart uint16
	// Checksum field offset from csumStart:
	// Position of checksum field within the protocol header
	// For TCP/UDP: Offset to checksum field in transport header
	// Example: TCP checksum is at offset 16 from TCP start → csumOffset = 16
	csumOffset uint16
}

func (v *virtioNetHdr) decode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen), b[:virtioNetHdrLen])
	return nil
}

func (v *virtioNetHdr) encode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(b[:virtioNetHdrLen], unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen))
	return nil
}

// tcpFlowKey represents the key for a TCP flow.
type tcpFlowKey struct {
	srcAddr, dstAddr [16]byte
	srcPort, dstPort uint16
	// varying ack values should not be coalesced. Treat them as separate flows.
	rxAck uint32
	isV6  bool
}

func newTCPFlowKey(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset int) tcpFlowKey {
	key := tcpFlowKey{}
	addrSize := dstAddrOffset - srcAddrOffset
	copy(key.srcAddr[:], pkt[srcAddrOffset:dstAddrOffset])
	copy(key.dstAddr[:], pkt[dstAddrOffset:dstAddrOffset+addrSize])
	key.srcPort = binary.BigEndian.Uint16(pkt[tcphOffset:])
	key.dstPort = binary.BigEndian.Uint16(pkt[tcphOffset+2:])
	// acknowledgment number (9th byte in TCP header)
	key.rxAck = binary.BigEndian.Uint32(pkt[tcphOffset+8:])
	key.isV6 = addrSize == 16
	return key
}

// tcpGROItem represents bookkeeping data for a TCP packet during the lifetime
// of a GRO evaluation across a vector of packets.
type tcpGROItem struct {
	key       tcpFlowKey
	sentSeq   uint32 // the sequence number
	bufsIndex uint16 // the index into the original bufs slice
	numMerged uint16 // the number of packets merged into this item
	gsoSize   uint16 // payload size
	iphLen    uint8  // ip header len
	tcphLen   uint8  // tcp header len
	// PSH flag: push data immediately to application
	pshSet bool // psh flag is set
}

// tcpGROTable holds flow and coalescing information for the purposes of TCP GRO.
type tcpGROTable struct {
	itemsByFlow map[tcpFlowKey][]tcpGROItem
	itemsPool   [][]tcpGROItem
}

func newTCPGROTable() *tcpGROTable {
	t := &tcpGROTable{
		itemsByFlow: make(map[tcpFlowKey][]tcpGROItem, conn.IdealBatchSize),
		itemsPool:   make([][]tcpGROItem, conn.IdealBatchSize),
	}
	for i := range t.itemsPool {
		t.itemsPool[i] = make([]tcpGROItem, 0, conn.IdealBatchSize)
	}
	return t
}

func (t *tcpGROTable) newItems() []tcpGROItem {
	var items []tcpGROItem
	items, t.itemsPool = t.itemsPool[len(t.itemsPool)-1], t.itemsPool[:len(t.itemsPool)-1]
	return items
}

func (t *tcpGROTable) reset() {
	for k, items := range t.itemsByFlow {
		items = items[:0]
		t.itemsPool = append(t.itemsPool, items)
		delete(t.itemsByFlow, k)
	}
}

// lookupOrInsert looks up a flow for the provided packet and metadata,
// returning the packets found for the flow, or inserting a new one if none
// is found.
func (t *tcpGROTable) lookupOrInsert(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex int) ([]tcpGROItem, bool) {
	key := newTCPFlowKey(pkt, srcAddrOffset, dstAddrOffset, tcphOffset)
	items, ok := t.itemsByFlow[key]
	if ok {
		return items, ok
	}
	// TODO: insert() performs another map lookup. This could be rearranged to avoid.
	t.insert(pkt, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex)
	return nil, false
}

// insert an item in the table for the provided packet and packet metadata.
func (t *tcpGROTable) insert(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex int) {
	key := newTCPFlowKey(pkt, srcAddrOffset, dstAddrOffset, tcphOffset)
	item := tcpGROItem{
		key:       key,
		bufsIndex: uint16(bufsIndex),
		gsoSize:   uint16(len(pkt[tcphOffset+tcphLen:])),
		iphLen:    uint8(tcphOffset),
		tcphLen:   uint8(tcphLen),
		// sequence number (5th byte in TCP header)
		sentSeq: binary.BigEndian.Uint32(pkt[tcphOffset+4:]),
		pshSet:  pkt[tcphOffset+tcpFlagsOffset]&tcpFlagPSH != 0,
	}
	items, ok := t.itemsByFlow[key]
	if !ok {
		items = t.newItems()
	}
	items = append(items, item)
	t.itemsByFlow[key] = items
}

func (t *tcpGROTable) updateAt(item tcpGROItem, i int) {
	items, _ := t.itemsByFlow[item.key]
	items[i] = item
}

func (t *tcpGROTable) deleteAt(key tcpFlowKey, i int) {
	items, _ := t.itemsByFlow[key]
	items = append(items[:i], items[i+1:]...)
	t.itemsByFlow[key] = items
}

const (
	udphLen = 8
)

// udpFlowKey represents the key for a UDP flow.
type udpFlowKey struct {
	srcAddr, dstAddr [16]byte
	srcPort, dstPort uint16
	isV6             bool
}

func newUDPFlowKey(pkt []byte, srcAddrOffset, dstAddrOffset, udphOffset int) udpFlowKey {
	key := udpFlowKey{}
	addrSize := dstAddrOffset - srcAddrOffset
	copy(key.srcAddr[:], pkt[srcAddrOffset:dstAddrOffset])
	copy(key.dstAddr[:], pkt[dstAddrOffset:dstAddrOffset+addrSize])
	key.srcPort = binary.BigEndian.Uint16(pkt[udphOffset:])
	key.dstPort = binary.BigEndian.Uint16(pkt[udphOffset+2:])
	key.isV6 = addrSize == 16
	return key
}

// udpGROItem represents bookkeeping data for a UDP packet during the lifetime
// of a GRO evaluation across a vector of packets.
type udpGROItem struct {
	key udpFlowKey
	// the index into the original bufs slice
	bufsIndex uint16
	// the number of packets merged into this item
	numMerged uint16
	// payload size
	gsoSize uint16
	// ip header len
	iphLen uint8
	// UDP header checksum validity.
	// A false value DOES NOT imply valid, just unknown.
	cSumKnownInvalid bool
}

// udpGROTable holds flow and coalescing information for the purposes of UDP GRO.
type udpGROTable struct {
	itemsByFlow map[udpFlowKey][]udpGROItem
	itemsPool   [][]udpGROItem
}

func (u *udpGROTable) newItems() []udpGROItem {
	var items []udpGROItem
	items, u.itemsPool = u.itemsPool[len(u.itemsPool)-1], u.itemsPool[:len(u.itemsPool)-1]
	return items
}

func (u *udpGROTable) reset() {
	for k, items := range u.itemsByFlow {
		items = items[:0]
		u.itemsPool = append(u.itemsPool, items)
		delete(u.itemsByFlow, k)
	}
}

// lookupOrInsert looks up a flow for the provided packet and metadata,
// returning the packets found for the flow, or inserting a new one if none
// is found.
func (u *udpGROTable) lookupOrInsert(pkt []byte, srcAddrOffset, dstAddrOffset, udphOffset, bufsIndex int) ([]udpGROItem, bool) {
	key := newUDPFlowKey(pkt, srcAddrOffset, dstAddrOffset, udphOffset)
	items, ok := u.itemsByFlow[key]
	if ok {
		return items, ok
	}
	// TODO: insert() performs another map lookup. This could be rearranged to avoid.
	u.insert(pkt, srcAddrOffset, dstAddrOffset, udphOffset, bufsIndex, false)
	return nil, false
}

// insert an item in the table for the provided packet and packet metadata.
func (u *udpGROTable) insert(pkt []byte, srcAddrOffset, dstAddrOffset, udphOffset, bufsIndex int, cSumKnownInvalid bool) {
	key := newUDPFlowKey(pkt, srcAddrOffset, dstAddrOffset, udphOffset)
	item := udpGROItem{
		key:              key,
		bufsIndex:        uint16(bufsIndex),
		gsoSize:          uint16(len(pkt[udphOffset+udphLen:])),
		iphLen:           uint8(udphOffset),
		cSumKnownInvalid: cSumKnownInvalid,
	}
	items, ok := u.itemsByFlow[key]
	if !ok {
		items = u.newItems()
	}
	items = append(items, item)
	u.itemsByFlow[key] = items
}

func (u *udpGROTable) updateAt(item udpGROItem, i int) {
	items, _ := u.itemsByFlow[item.key]
	items[i] = item
}

// canCoalesce represents the outcome of checking if two TCP packets are
// candidates for coalescing.
type canCoalesce int

const (
	coalescePrepend     canCoalesce = -1
	coalesceUnavailable canCoalesce = 0
	coalesceAppend      canCoalesce = 1
)

// ipHeadersCanCoalesce returns true if the IP headers found in pktA and pktB
// meet all requirements to be merged as part of a GRO operation, otherwise it
// returns false.
func ipHeadersCanCoalesce(pktA, pktB []byte) bool {
	if len(pktA) < 9 || len(pktB) < 9 {
		return false
	}
	// check for IP version
	if pktA[0]>>4 == 6 {
		if pktA[0] != pktB[0] || pktA[1]>>4 != pktB[1]>>4 {
			// cannot coalesce with unequal Traffic class values
			return false
		}
		if pktA[7] != pktB[7] {
			// cannot coalesce with unequal Hop limit values
			return false
		}
	} else {
		if pktA[1] != pktB[1] {
			// cannot coalesce with unequal ToS values
			return false
		}
		if pktA[6]>>5 != pktB[6]>>5 {
			// cannot coalesce with unequal DF or reserved bits. MF is checked
			// further up the stack.
			return false
		}
		if pktA[8] != pktB[8] {
			// cannot coalesce with unequal TTL values
			return false
		}
	}
	return true
}

// udpPacketsCanCoalesce evaluates if pkt can be coalesced with the packet
// described by item. iphLen and gsoSize describe pkt. bufs is the vector of
// packets involved in the current GRO evaluation. bufsOffset is the offset at
// which packet data begins within bufs.
func udpPacketsCanCoalesce(pkt []byte, iphLen uint8, gsoSize uint16, item udpGROItem, bufs [][]byte, bufsOffset int) canCoalesce {
	pktTarget := bufs[item.bufsIndex][bufsOffset:]
	if !ipHeadersCanCoalesce(pkt, pktTarget) {
		return coalesceUnavailable
	}
	// TODO: look into gso sizes and how payloads coalesce
	// If a "short" packet (smaller than GSO size) is at the end,
	// it indicates the end of a message.
	if len(pktTarget[iphLen+udphLen:])%int(item.gsoSize) != 0 {
		// A smaller than gsoSize packet has been appended previously.
		// Nothing can come after a smaller packet on the end.
		return coalesceUnavailable
	}
	if gsoSize > item.gsoSize {
		// We cannot have a larger packet following a smaller one.
		return coalesceUnavailable
	}
	return coalesceAppend
}
