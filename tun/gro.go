// GSO (Generic Segmentation Offload):
// Application combines several packets into one,
// sends them to kernel, kernel sends them to NIC,
// NIC splits combined packet into standard packets,
// and sends them over the network.
//
// GRO (Generic Receive Offload):
// NIC combines incoming from network packets
// into one large packet, kernel delivers
// them as a single datagram to userspace.
package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"unsafe"

	"github.com/muhtutorials/wireguard/conn"
	"golang.org/x/sys/unix"
)

// flags are in the 14th byte of the TCP header
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
	tcpFlagFIN uint8 = 0x01 // 1 (1st bit is set)
	tcpFlagPSH uint8 = 0x08 // 8 (4th bit is set)
	tcpFlagACK uint8 = 0x10 // 16 (5th bit is set)
)

// virtioNetHdr is defined in linux kernel's `include/uapi/linux/virtio_net.h`.
type virtioNetHdr struct {
	// Bitmask of features/packet attributes:
	// Bit 0 (VIRTIO_NET_HDR_F_NEEDS_CSUM): packet needs checksum calculation
	// Bit 1 (VIRTIO_NET_HDR_F_DATA_VALID): checksum is already valid (host→guest)
	// Bit 2 (VIRTIO_NET_HDR_F_RSC_INFO): receive Segment Coalescing info present
	// Bit 3 (VIRTIO_NET_HDR_F_MRG_RXBUF): mergeable RX buffers supported
	flags uint8
	// Generic Segmentation Offload type - indicates how to segment large packets:
	// VIRTIO_NET_HDR_GSO_NONE: No GSO (normal packet)
	// VIRTIO_NET_HDR_GSO_TCPV4: TCP/IPv4 segmentation offload
	// VIRTIO_NET_HDR_GSO_UDP: UDP segmentation offload (UFO)
	// VIRTIO_NET_HDR_GSO_TCPV6: TCP/IPv6 segmentation offload
	// VIRTIO_NET_HDR_GSO_ECN: TCP with ECN (Explicit Congestion Notification)
	gsoType uint8
	// IP header + TCP/UDP header length
	hdrLen uint16
	// Maximum Segment Size for GSO:
	// Maximum size of each segment after segmentation
	// Excludes headers (payload only)
	// Example: gsoSize = 1448 for MTU 1500 (1500 - 52 headers)
	gsoSize uint16
	// TCP/UDP header start (IP header length)
	csumStart uint16
	// checksum field offset from csumStart
	csumOffset uint16
}

// virtioNetHdrLen is the length in bytes of virtioNetHdr. This matches the
// shape of the C ABI for its kernel counterpart - sizeof(virtio_net_hdr).
const virtioNetHdrLen = int(unsafe.Sizeof(virtioNetHdr{}))

func (v *virtioNetHdr) encode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(
		b[:virtioNetHdrLen],
		unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen),
	)
	return nil
}

func (v *virtioNetHdr) decode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(
		unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen),
		b[:virtioNetHdrLen],
	)
	return nil
}

// TODO: why do we need to sort packet by flow,
// why not just send them randomly in batches?
// tcpFlowKey represents the key for a TCP flow.
type tcpFlowKey struct {
	srcAddr, dstAddr [16]byte
	srcPort, dstPort uint16
	// Acknowledgment number which means all previous bytes are received.
	// Example: ff you get SEQ = 1500 with 400 bytes of data
	// (bytes 1500–1899), you reply with ACK = 1900.
	// Different acknowledgment numbers should not be coalesced.
	// Treat them as separate flows.
	ackNum uint32
	// IPv4 addresses are often represented as IPv6-mapped
	// addresses (::ffff:192.0.2.1). Thus, we avoid a check:
	// 	`srcAddr[10] == 0xff && srcAddr[11] == 0xff`
	isV6 bool
}

func newTCPFlowKey(
	pkt []byte,
	srcAddrOffset,
	dstAddrOffset,
	tcphOffset int, // iphLen
) tcpFlowKey {
	key := tcpFlowKey{}
	addrSize := dstAddrOffset - srcAddrOffset
	copy(key.srcAddr[:], pkt[srcAddrOffset:dstAddrOffset])
	copy(key.dstAddr[:], pkt[dstAddrOffset:dstAddrOffset+addrSize])
	key.srcPort = binary.BigEndian.Uint16(pkt[tcphOffset:])
	key.dstPort = binary.BigEndian.Uint16(pkt[tcphOffset+2:])
	// acknowledgment number (9th byte in TCP header)
	key.ackNum = binary.BigEndian.Uint32(pkt[tcphOffset+8:])
	key.isV6 = addrSize == 16
	return key
}

// tcpGROItem represents bookkeeping data for a TCP packet during
// the lifetime of a GRO evaluation across a vector of packets.
type tcpGROItem struct {
	key tcpFlowKey
	// Sequence number: byte number of the first data
	// byte sent in the current TCP packet.
	// Example:
	// If a connection sends 1000 bytes in 2 segments (500 bytes each):
	// Segment 1 → SEQ = 1000 (first byte = byte 1000)
	// Segment 2 → SEQ = 1500 (NEXT byte after 1499)
	seqNum    uint32
	bufsIndex uint16 // index into the original bufs slice
	numMerged uint16 // number of packets merged into this item
	gsoSize   uint16 // payload size
	iphLen    uint8  // IP header length
	// TCP header length. Length is variable
	// because of the `Options` field.
	tcphLen uint8
	// PSH flag: push data immediately to application
	pshSet bool
}

// tcpGROTable holds flow and coalescing information
// for the purposes of TCP GRO.
type tcpGROTable struct {
	itemsByFlow map[tcpFlowKey][]tcpGROItem
	itemsPool   [][]tcpGROItem
}

func newTCPGROTable() *tcpGROTable {
	t := &tcpGROTable{
		itemsByFlow: make(map[tcpFlowKey][]tcpGROItem, conn.BatchSize),
		itemsPool:   make([][]tcpGROItem, conn.BatchSize),
	}
	for i := range t.itemsPool {
		t.itemsPool[i] = make([]tcpGROItem, 0, conn.BatchSize)
	}
	return t
}

func (t *tcpGROTable) newItems() []tcpGROItem {
	var items []tcpGROItem
	// "pop" last element from `itemsPool` by indexing
	// into it and reducing its length by one
	items, t.itemsPool =
		t.itemsPool[len(t.itemsPool)-1], t.itemsPool[:len(t.itemsPool)-1]
	return items
}

func (t *tcpGROTable) reset() {
	for key, items := range t.itemsByFlow {
		items = items[:0]
		t.itemsPool = append(t.itemsPool, items)
		delete(t.itemsByFlow, key)
	}
}

// getOrInsert gets a flow for the provided packet and metadata,
// returning the packets found for the flow, or inserting a new
// one if none is found.
func (t *tcpGROTable) getOrInsert(
	pkt []byte,
	srcAddrOffset,
	dstAddrOffset,
	tcphOffset,
	tcphLen,
	bufsIndex int,
) ([]tcpGROItem, bool) {
	key := newTCPFlowKey(pkt, srcAddrOffset, dstAddrOffset, tcphOffset)
	items, ok := t.itemsByFlow[key]
	if ok {
		return items, ok
	}
	// TODO: insert() performs another map lookup.
	// This could be rearranged to avoid.
	t.insert(pkt, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex)
	return nil, false
}

// insert an item in the table for the provided packet and packet metadata.
func (t *tcpGROTable) insert(
	pkt []byte,
	srcAddrOffset,
	dstAddrOffset,
	tcphOffset, // iphLen
	tcphLen,
	bufsIndex int,
) {
	key := newTCPFlowKey(pkt, srcAddrOffset, dstAddrOffset, tcphOffset)
	item := tcpGROItem{
		key:       key,
		bufsIndex: uint16(bufsIndex),
		gsoSize:   uint16(len(pkt[tcphOffset+tcphLen:])),
		iphLen:    uint8(tcphOffset),
		tcphLen:   uint8(tcphLen),
		// sequence number (5th byte in TCP header)
		seqNum: binary.BigEndian.Uint32(pkt[tcphOffset+4:]),
		pshSet: pkt[tcphOffset+tcpFlagsOffset]&tcpFlagPSH != 0,
	}
	items, ok := t.itemsByFlow[key]
	if !ok {
		items = t.newItems()
	}
	items = append(items, item)
	t.itemsByFlow[key] = items
}

// TODO: why no check for existence?
func (t *tcpGROTable) updateAt(item tcpGROItem, i int) {
	items, _ := t.itemsByFlow[item.key]
	items[i] = item
}

// TODO: why no check for existence?
func (t *tcpGROTable) deleteAt(key tcpFlowKey, i int) {
	items, _ := t.itemsByFlow[key]
	items = append(items[:i], items[i+1:]...)
	t.itemsByFlow[key] = items
}

const udphLen = 8

// udpFlowKey represents the key for a UDP flow.
type udpFlowKey struct {
	srcAddr, dstAddr [16]byte
	srcPort, dstPort uint16
	// IPv4 addresses are often represented as IPv6-mapped
	// addresses (::ffff:192.0.2.1). Thus, we avoid a check:
	// 	`srcAddr[10] == 0xff && srcAddr[11] == 0xff`
	isV6 bool
}

func newUDPFlowKey(
	pkt []byte,
	srcAddrOffset,
	dstAddrOffset,
	udphOffset int, // iphLen
) udpFlowKey {
	key := udpFlowKey{}
	addrSize := dstAddrOffset - srcAddrOffset
	copy(key.srcAddr[:], pkt[srcAddrOffset:dstAddrOffset])
	copy(key.dstAddr[:], pkt[dstAddrOffset:dstAddrOffset+addrSize])
	key.srcPort = binary.BigEndian.Uint16(pkt[udphOffset:])
	key.dstPort = binary.BigEndian.Uint16(pkt[udphOffset+2:])
	key.isV6 = addrSize == 16
	return key
}

// udpGROItem represents bookkeeping data for a UDP packet during
// the lifetime of a GRO evaluation across a vector of packets.
type udpGROItem struct {
	key udpFlowKey
	// index into the original bufs slice
	bufsIndex uint16
	// number of packets merged into this item
	numMerged uint16
	// payload size
	gsoSize uint16
	// IP header length
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

func newUDPGROTable() *udpGROTable {
	u := &udpGROTable{
		itemsByFlow: make(map[udpFlowKey][]udpGROItem, conn.BatchSize),
		itemsPool:   make([][]udpGROItem, conn.BatchSize),
	}
	for i := range u.itemsPool {
		u.itemsPool[i] = make([]udpGROItem, 0, conn.BatchSize)
	}
	return u
}

func (u *udpGROTable) newItems() []udpGROItem {
	var items []udpGROItem
	// "pop" last element from `itemsPool` by indexing
	// into it and reducing its length by one
	items, u.itemsPool =
		u.itemsPool[len(u.itemsPool)-1], u.itemsPool[:len(u.itemsPool)-1]
	return items
}

func (u *udpGROTable) reset() {
	for key, items := range u.itemsByFlow {
		items = items[:0]
		u.itemsPool = append(u.itemsPool, items)
		delete(u.itemsByFlow, key)
	}
}

// getOrInsert gets a flow for the provided packet and metadata,
// returning the packets found for the flow, or inserting a new
// one if none is found.
func (u *udpGROTable) getOrInsert(
	pkt []byte,
	srcAddrOffset,
	dstAddrOffset,
	udphOffset,
	bufsIndex int,
) ([]udpGROItem, bool) {
	key := newUDPFlowKey(pkt, srcAddrOffset, dstAddrOffset, udphOffset)
	items, ok := u.itemsByFlow[key]
	if ok {
		return items, ok
	}
	// TODO: insert() performs another map lookup.
	// This could be rearranged to avoid.
	u.insert(pkt, srcAddrOffset, dstAddrOffset, udphOffset, bufsIndex, false)
	return nil, false
}

// insert an item in the table for the provided packet and packet metadata.
func (u *udpGROTable) insert(
	pkt []byte,
	srcAddrOffset,
	dstAddrOffset,
	udphOffset,
	bufsIndex int,
	cSumKnownInvalid bool,
) {
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

// canCoalesce represents the outcome of checking
// if two TCP packets are candidates for coalescing.
type canCoalesce int

const (
	coalescePrepend     canCoalesce = -1
	coalesceUnavailable canCoalesce = 0
	coalesceAppend      canCoalesce = 1
)

// ipHeadersCanCoalesce returns true if the IP headers found
// in pktA and pktB meet all requirements to be merged as part
// of a GRO operation, otherwise it returns false.
// pktA and pktB are IP packets.
func ipHeadersCanCoalesce(pktA, pktB []byte) bool {
	// Make sure packets have at least 9 bytes of length,
	// because of this `pktA[8] != pktB[8]` comparison.
	if len(pktA) < 9 || len(pktB) < 9 {
		return false
	}
	// extract IP version
	if pktA[0]>>4 == 6 { // IPv6
		// check Traffic Class equality
		if pktA[0] != pktB[0] || pktA[1]>>4 != pktB[1]>>4 {
			// cannot coalesce with unequal Traffic Class values
			return false
		}
		if pktA[7] != pktB[7] {
			// cannot coalesce with unequal Hop Limit values
			return false
		}
	} else { // IPv4
		if pktA[1] != pktB[1] {
			// cannot coalesce with unequal Type of Service values
			return false
		}
		// check Flags equality
		if pktA[6]>>5 != pktB[6]>>5 {
			// Cannot coalesce with unequal Don’t Fragment (DF)
			// or reserved bits. More Fragments (MF) is checked
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

// tcpPacketsCanCoalesce evaluates if `pkt` can be coalesced
// with the packet described by `item`. This function makes
// considerations that match the kernel's GRO self tests,
// which can be found in tools/testing/selftests/net/gro.c.
func tcpPacketsCanCoalesce(
	pkt []byte, // IP packet
	iphLen,
	tcphLen uint8,
	seqNum uint32,
	pshSet bool,
	gsoSize uint16,
	// TCP flow items are iterated in reverse in `tcpGRO`
	// and `pkt` is checked if it can coalesce to `item`.
	item tcpGROItem,
	bufs [][]byte,
	offset int,
) canCoalesce {
	pktTarget := bufs[item.bufsIndex][offset:]
	if tcphLen != item.tcphLen {
		// cannot coalesce with unequal TCP options length
		return coalesceUnavailable
	}
	// check if header has options (options start at 21 byte)
	if tcphLen > 20 {
		// check if options are equal
		if !bytes.Equal(
			pkt[iphLen+20:iphLen+tcphLen],
			pktTarget[item.iphLen+20:iphLen+tcphLen],
		) {
			// cannot coalesce with unequal TCP options
			return coalesceUnavailable
		}
	}
	if !ipHeadersCanCoalesce(pkt, pktTarget) {
		return coalesceUnavailable
	}
	// Sequence number adjacency.
	// lhsLen: left-hand side length.
	// numMerged: number of packets merged into item packet.
	lhsLen := item.gsoSize + item.gsoSize*item.numMerged
	if seqNum == item.seqNum+uint32(lhsLen) {
		// pkt aligns following item from a seqNum perspective.
		// The PSH (Push) flag is a 1-bit field in the TCP header
		// that signals the receiver to immediately deliver the
		// data to the application layer instead of buffering it.
		if item.pshSet {
			// We cannot append to a segment that has the PSH flag set, PSH
			// can only be set on the final segment in a reassembled group.
			return coalesceUnavailable
		}
		// check if the last appended packet's payload is smaller than gsoSize
		if len(pktTarget[iphLen+tcphLen:])%int(item.gsoSize) != 0 {
			// A smaller than gsoSize packet has been appended previously.
			// Nothing can come after a smaller packet on the end.
			return coalesceUnavailable
		}
		// gsoSize can be equal or smaller than item.gsoSize.
		// Smaller only if it's the last packet:
		// Buffer: [1460][1460][800] (gsoSize = 1460)
		if gsoSize > item.gsoSize {
			// We cannot have a larger packet following a smaller one.
			return coalesceUnavailable
		}
		return coalesceAppend
	} else if seqNum+uint32(gsoSize) == item.seqNum {
		// pkt aligns in front of item from a seqNum perspective.
		if pshSet {
			// We cannot prepend with a segment that has the PSH flag set, PSH
			// can only be set on the final segment in a reassembled group.
			return coalesceUnavailable
		}
		if gsoSize < item.gsoSize {
			// We cannot have a larger packet following a smaller one.
			return coalesceUnavailable
		}
		if gsoSize > item.gsoSize && item.numMerged > 0 {
			// There's at least one previous merge, and we're larger than all
			// previous. This would put multiple smaller packets on the end.
			return coalesceUnavailable
		}
		return coalescePrepend
	}
	return coalesceUnavailable
}

// udpPacketsCanCoalesce evaluates if `pkt` can be coalesced
// with the packet described by `item`. `iphLen` and `gsoSize`
// describe `pkt`. `bufs` is the vector of packets involved in
// the current GRO evaluation. offset is the index at which
// packet begins within bufs (offset = MessageTransportHeaderSize).
func udpPacketsCanCoalesce(
	pkt []byte, // IP packet
	iphLen uint8,
	gsoSize uint16,
	// Last item in a udpFlow, which has the same key as pkt.
	item udpGROItem,
	bufs [][]byte,
	offset int,
) canCoalesce {
	pktTarget := bufs[item.bufsIndex][offset:]
	if !ipHeadersCanCoalesce(pkt, pktTarget) {
		return coalesceUnavailable
	}
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

const (
	ipv4SrcAddrOffset = 12
	ipv6SrcAddrOffset = 8
	maxUint16         = 1<<16 - 1
)

// TODO: check whole algorithm of checksum calculation
func checksumValid(pkt []byte, iphLen, protocol uint8, isV6 bool) bool {
	srcAddrAt := ipv4SrcAddrOffset
	addrSize := 4
	if isV6 {
		srcAddrAt = ipv6SrcAddrOffset
		addrSize = 16
	}
	srcAddr := pkt[srcAddrAt : srcAddrAt+addrSize]
	dstAddr := pkt[srcAddrAt+addrSize : srcAddrAt+addrSize+addrSize]
	// TCP/UDP packet length
	totalLen := uint16(len(pkt) - int(iphLen))
	// protocol arg is TCP or UDP
	headerChecksum :=
		pseudoHeaderChecksumNoFold(srcAddr, dstAddr, protocol, totalLen)
	return ^checksum(pkt[iphLen:], headerChecksum) == 0
}

// coalesceResult represents the result of
// attempting to coalesce two TCP packets.
type coalesceResult int

const (
	coalesceInsufficientCap coalesceResult = iota
	coalescePSHEnding
	coalesceItemInvalidChecksum
	coalescePktInvalidChecksum
	coalesceSuccess
)

// coalesceTCPPackets attempts to coalesce pkt with the packet
// described by item, and returns the outcome. This function
// may swap bufs elements in the event of a prepend as item's
// bufs index is already being tracked for writing to a Device.
func coalesceTCPPackets(
	mode canCoalesce,
	pkt []byte,
	bufsIndex int,
	gsoSize uint16,
	seqNum uint32,
	pshSet bool,
	item *tcpGROItem,
	bufs [][]byte,
	offset int,
	isV6 bool,
) coalesceResult {
	var pktHead []byte // packet that will be at the front
	headersLen := item.iphLen + item.tcphLen
	pktPayloadLen := len(pkt) - int(headersLen)
	newLen := len(bufs[item.bufsIndex][offset:]) + pktPayloadLen
	// copy data
	if mode == coalescePrepend {
		pktHead = pkt
		// pkt = bufs[bufsIndex][offset:]
		// NOTE: It was `cap(pkt)-offset < newLen`. Probably a bug.
		if cap(pkt) < newLen {
			// We don't want to allocate a new underlying
			// array if capacity is too small.
			return coalesceInsufficientCap
		}
		if pshSet {
			return coalescePSHEnding
		}
		if item.numMerged == 0 {
			if !checksumValid(
				bufs[item.bufsIndex][offset:],
				item.iphLen,
				unix.IPPROTO_TCP,
				isV6,
			) {
				return coalesceItemInvalidChecksum
			}
		}
		if !checksumValid(pkt, item.iphLen, unix.IPPROTO_TCP, isV6) {
			return coalescePktInvalidChecksum
		}
		item.seqNum = seqNum
		extendBy := newLen - len(pktHead)
		bufs[bufsIndex] = append(
			bufs[bufsIndex],
			make([]byte, extendBy)...,
		)
		copy(
			bufs[bufsIndex][offset+len(pkt):],
			bufs[item.bufsIndex][offset+int(headersLen):],
		)
		// Flip the slice headers in bufs as part of prepend.
		// The index of item is already being tracked for writing.
		// TODO: Look into this later.
		bufs[item.bufsIndex], bufs[bufsIndex] =
			bufs[bufsIndex], bufs[item.bufsIndex]
	} else {
		pktHead = bufs[item.bufsIndex][offset:]
		// NOTE: It was `cap(pkt)-offset < newLen`. Probably a bug.
		if cap(pktHead) < newLen {
			// We don't want to allocate a new underlying
			// array if capacity is too small.
			return coalesceInsufficientCap
		}
		if item.numMerged == 0 {
			if !checksumValid(
				bufs[item.bufsIndex][offset:],
				item.iphLen,
				unix.IPPROTO_TCP,
				isV6,
			) {
				return coalesceItemInvalidChecksum
			}
		}
		if !checksumValid(pkt, item.iphLen, unix.IPPROTO_TCP, isV6) {
			return coalescePktInvalidChecksum
		}
		if pshSet {
			// We are appending a segment with PSH set.
			item.pshSet = pshSet
			pktHead[item.iphLen+tcpFlagsOffset] |= tcpFlagPSH
		}
		extendBy := len(pkt) - int(headersLen)
		bufs[item.bufsIndex] = append(
			bufs[item.bufsIndex],
			make([]byte, extendBy)...,
		)
		copy(bufs[item.bufsIndex][offset+len(pktHead):], pkt[headersLen:])
	}
	// TODO: Why is this allowed? It contradicts tcpPacketsCanCoalesce.
	if gsoSize > item.gsoSize {
		item.gsoSize = gsoSize
	}
	item.numMerged++
	return coalesceSuccess
}

// coalesceUDPPackets attempts to coalesce pkt with the
// packet described by item, and returns the outcome.
func coalesceUDPPackets(
	pkt []byte,
	item *udpGROItem,
	bufs [][]byte,
	offset int,
	isV6 bool,
) coalesceResult {
	// bufsOffset is the index at which item (coalesced packets) starts.
	// pktHead are packets that have already been merged.
	pktHead := bufs[item.bufsIndex][offset:]
	headersLen := item.iphLen + udphLen
	// previous coalesced packets plus new packet without headers (just payload)
	newLen := len(pktHead) + len(pkt) - int(headersLen)
	// TODO: Why do we subtract bufsOffset? Is this a bug?
	if cap(pktHead)-offset < newLen {
		// We don't want to allocate a new underlying
		// array if capacity is too small.
		return coalesceInsufficientCap
	}
	// Only validate checksum once per flow item.
	// Cache the result (cSumKnownInvalid) to avoid recomputation.
	// Skip validation for already-merged packets
	// (they were validated when first added).
	if item.numMerged == 0 {
		if item.cSumKnownInvalid ||
			!checksumValid(pktHead, item.iphLen, unix.IPPROTO_UDP, isV6) {
			return coalesceItemInvalidChecksum
		}
	}
	if !checksumValid(pkt, item.iphLen, unix.IPPROTO_UDP, isV6) {
		return coalescePktInvalidChecksum
	}
	extendBy := len(pkt) - int(headersLen)
	bufs[item.bufsIndex] = append(bufs[item.bufsIndex], make([]byte, extendBy)...)
	copy(bufs[item.bufsIndex][offset+len(pktHead):], pkt[headersLen:])
	item.numMerged++
	return coalesceSuccess
}

const (
	ipv4FlagMoreFragments uint8 = 0x20
)

type groResult int

const (
	groResultNoop groResult = iota
	groResultTableInsert
	groResultCoalesced
)

// tcpGRO evaluates the TCP packet at bufsIndex in bufs
// for coalescing with existing packets tracked in table.
// It returns a groResultNoop when no action was taken,
// groResultTableInsert when the evaluated packet was
// (insert)ed into table, and groResultCoalesced when the
// evaluated packet was coalesced with another packet in table.
func tcpGRO(
	bufs [][]byte,
	offset int,
	bufsIndex int,
	table *tcpGROTable,
	isV6 bool,
) groResult {
	pkt := bufs[bufsIndex][offset:]
	// IP header's total length (header + payload) field is 16 bits
	// which have max value of 65535
	if len(pkt) > maxUint16 {
		// A valid IPv4 or IPv6 packet will never exceed this.
		return groResultNoop
	}
	// Extract IHL from IPv4 header which is the 1st 4 bits in the 1st byte:
	// 			0
	//  0 1 2 3 4 5 6 7
	// +-+-+-+-+-+-+-+-+
	// |Version|  IHL  |
	// +-+-+-+-+-+-+-+-+
	// iphLen = IHL × 4
	iphLen := int((pkt[0] & 0x0F) * 4)
	if isV6 {
		// header is always 40 bytes in IPv6
		iphLen = 40
		ipv6PayloadLen := int(binary.BigEndian.Uint16(pkt[4:]))
		if ipv6PayloadLen != len(pkt)-iphLen {
			return groResultNoop
		}
	} else {
		// extract total length (header + data) from IPv4 header
		totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
		if totalLen != len(pkt) {
			return groResultNoop
		}
	}
	if len(pkt) < iphLen {
		return groResultNoop
	}
	// Extract Data Offset field which is 13th byte in the header.
	// The field occupies four high bits in the byte.
	tcphLen := int((pkt[iphLen+12] >> 4) * 4)
	if tcphLen < 20 || tcphLen > 60 {
		return groResultNoop
	}
	if len(pkt) < iphLen+tcphLen {
		return groResultNoop
	}
	if !isV6 {
		if pkt[6]&ipv4FlagMoreFragments != 0 || pkt[6]<<3 != 0 || pkt[7] != 0 {
			// no GRO support for fragmented segments for now
			return groResultNoop
		}
	}
	tcpFlags := pkt[iphLen+tcpFlagsOffset]
	var pshSet bool
	// When ACK=1:
	// 	Acknowledgment Number field is valid.
	// 	Receiver is acknowledging received data.
	// 	Normal data transfer mode.
	// When ACK=0:
	// 	Acknowledgment Number field should be ignored.
	// 	Only during connection initiation (SYN) or termination (RST).
	//
	// not a candidate if any non-ACK flags (except PSH+ACK) are set
	if tcpFlags != tcpFlagACK {
		if tcpFlags != tcpFlagACK|tcpFlagPSH {
			return groResultNoop
		}
		pshSet = true
	}
	gsoSize := uint16(len(pkt) - iphLen - tcphLen)
	// not a candidate if payload len is 0
	if gsoSize < 1 {
		return groResultNoop
	}
	seqNum := binary.BigEndian.Uint32(pkt[iphLen+4:])
	srcAddrOffset := ipv4SrcAddrOffset
	addrLen := 4
	if isV6 {
		srcAddrOffset = ipv6SrcAddrOffset
		addrLen = 16
	}
	items, existing := table.getOrInsert(
		pkt,
		srcAddrOffset,
		srcAddrOffset+addrLen,
		iphLen,
		tcphLen,
		bufsIndex,
	)
	if !existing {
		return groResultTableInsert
	}
	for i := len(items) - 1; i >= 0; i-- {
		// In the best case of packets arriving in order iterating
		// in reverse is more efficient if there are multiple
		// items for a given flow. This also enables a natural
		// table.deleteAt() in the coalesceItemInvalidChecksum case
		// without the need for index tracking. This algorithm makes
		// the best effort to coalesce in the event of unordered
		// packets, where pkt may land anywhere in items from a
		// sequence number perspective, however once an item is inserted
		// into the table it is never compared across other items later.
		item := items[i]
		can := tcpPacketsCanCoalesce(
			pkt,
			uint8(iphLen),
			uint8(tcphLen),
			seqNum,
			pshSet,
			gsoSize,
			item,
			bufs,
			offset,
		)
		if can != coalesceUnavailable {
			result := coalesceTCPPackets(
				can,
				pkt,
				bufsIndex,
				gsoSize,
				seqNum,
				pshSet,
				&item,
				bufs,
				offset,
				isV6,
			)
			switch result {
			case coalesceSuccess:
				table.updateAt(item, i)
				return groResultCoalesced
			case coalesceItemInvalidChecksum:
				// delete the item with an invalid checksum
				table.deleteAt(item.key, i)
			case coalescePktInvalidChecksum:
				// no point in inserting an item that we can't coalesce
				return groResultNoop
			}
		}
	}
	// failed to coalesce with any other packets; store the item in the flow
	table.insert(
		pkt,
		srcAddrOffset,
		srcAddrOffset+addrLen,
		iphLen,
		tcphLen,
		bufsIndex,
	)
	return groResultTableInsert
}

// udpGRO evaluates the UDP packet at pktBufsIndex in bufs
// for coalescing with existing packets tracked in table.
// It returns a groResultNoop when no action was taken,
// groResultTableInsert when the evaluated packet was
// inserted into table, and groResultCoalesced when the
// evaluated packet was coalesced with another packet in table.
func udpGRO(
	bufs [][]byte,
	offset int,
	bufsIndex int,
	table *udpGROTable,
	isV6 bool,
) groResult {
	pkt := bufs[bufsIndex][offset:]
	// IP packet's total length (header + payload) field is 16 bits
	// which has max value of 65535
	if len(pkt) > maxUint16 {
		// A valid IPv4 or IPv6 packet will never exceed this.
		return groResultNoop
	}
	// Extract IHL from IPv4 header which is the first 4 bits in the first byte:
	// 			0
	//  0 1 2 3 4 5 6 7
	// +-+-+-+-+-+-+-+-+
	// |Version|  IHL  |
	// +-+-+-+-+-+-+-+-+
	// iphLen = IHL × 4
	iphLen := int((pkt[0] & 0x0F) * 4)
	if isV6 {
		// header is always 40 bytes in IPv6
		iphLen = 40
		ipv6PayloadLen := int(binary.BigEndian.Uint16(pkt[4:]))
		if ipv6PayloadLen != len(pkt)-iphLen {
			return groResultNoop
		}
	} else {
		totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
		if totalLen != len(pkt) {
			return groResultNoop
		}
	}
	if len(pkt) < iphLen {
		return groResultNoop
	}
	if len(pkt) < iphLen+udphLen {
		return groResultNoop
	}
	if !isV6 {
		if pkt[6]&ipv4FlagMoreFragments != 0 || pkt[6]<<3 != 0 || pkt[7] != 0 {
			// no GRO support for fragmented segments for now
			return groResultNoop
		}
	}
	gsoSize := uint16(len(pkt) - iphLen - udphLen)
	// not a candidate if payload len is 0
	if gsoSize < 1 {
		return groResultNoop
	}
	srcAddrOffset := ipv4SrcAddrOffset
	addrLen := 4
	if isV6 {
		srcAddrOffset = ipv6SrcAddrOffset
		addrLen = 16
	}
	items, existing := table.getOrInsert(
		pkt,
		srcAddrOffset,
		srcAddrOffset+addrLen,
		iphLen,
		bufsIndex,
	)
	if !existing {
		return groResultTableInsert
	}
	// With UDP we only check the last item, otherwise we could reorder packets
	// for a given flow. We must also always insert a new item, or successfully
	// coalesce with an existing item, for the same reason.
	item := items[len(items)-1]
	can := udpPacketsCanCoalesce(pkt, uint8(iphLen), gsoSize, item, bufs, offset)
	var pktChecksumKnownInvalid bool
	if can == coalesceAppend {
		result := coalesceUDPPackets(pkt, &item, bufs, offset, isV6)
		switch result {
		case coalesceSuccess:
			table.updateAt(item, len(items)-1)
			return groResultCoalesced
		case coalesceItemInvalidChecksum:
			// If the existing item has an invalid checksum we take no action.
			// A new item will be stored after it, and the existing item will
			// never be revisited as part of future coalescing candidacy checks.
		case coalescePktInvalidChecksum:
			// We must insert a new item, but we also mark it as invalid
			// checksum to prevent a repeat checksum validation.
			pktChecksumKnownInvalid = true
		}
	}
	// failed to coalesce with any other packets; store the item in the flow
	table.insert(
		pkt,
		srcAddrOffset,
		srcAddrOffset+addrLen,
		iphLen,
		bufsIndex,
		pktChecksumKnownInvalid,
	)
	return groResultTableInsert
}

// applyTCPCoalesce updates bufs to account for
// coalescing based on the metadata found in table.
func applyTCPCoalesce(
	bufs [][]byte,
	offset int,
	table *tcpGROTable,
) error {
	for _, items := range table.itemsByFlow {
		for _, item := range items {
			if item.numMerged > 0 {
				hdr := virtioNetHdr{
					// This turns into CHECKSUM_PARTIAL in the skb (Socket Buffer).
					// Indicate that the packet requires checksum processing.
					flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
					hdrLen:     uint16(item.iphLen + item.tcphLen),
					gsoSize:    item.gsoSize,
					csumStart:  uint16(item.iphLen),
					csumOffset: 16,
				}
				pkt := bufs[item.bufsIndex][offset:]
				// Recalculate the total len (IPv4) or payload len (IPv6).
				// Recalculate the (IPv4) header checksum.
				if item.key.isV6 {
					hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV6
					// set IPv6 header payload length
					binary.BigEndian.PutUint16(
						pkt[4:],
						uint16(len(pkt))-uint16(item.iphLen),
					) // set new IPv6 header payload len
				} else {
					hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV4
					// set IPv4 header checksum field to 0
					pkt[10], pkt[11] = 0, 0
					// set new total length
					binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
					// compute IPv4 header checksum
					iphChecksum := ^checksum(pkt[:item.iphLen], 0)
					// set IPv4 header checksum field
					binary.BigEndian.PutUint16(pkt[10:], iphChecksum)
				}
				if err := hdr.encode(
					bufs[item.bufsIndex][offset-virtioNetHdrLen:],
				); err != nil {
					return err
				}
				// Calculate the pseudo header checksum and place it at the TCP
				// checksum offset. Downstream checksum offloading will combine
				// this with computation of the tcp header and payload checksum.
				addrLen := 4
				addrOffset := ipv4SrcAddrOffset
				if item.key.isV6 {
					addrLen = 16
					addrOffset = ipv6SrcAddrOffset
				}
				srcAddrAt := offset + addrOffset
				srcAddr := bufs[item.bufsIndex][srcAddrAt : srcAddrAt+addrLen]
				dstAddr := bufs[item.bufsIndex][srcAddrAt+addrLen : srcAddrAt+addrLen*2]
				// TODO: Why doesn't total length include IP header?
				pseudoHeaderChecksum :=
					pseudoHeaderChecksumNoFold(
						srcAddr,
						dstAddr,
						unix.IPPROTO_TCP,
						uint16(len(pkt)-int(item.iphLen)),
					)
				// checksum([]byte{}, pseudoHeaderChecksum) folds the initial value
				binary.BigEndian.PutUint16(
					pkt[hdr.csumStart+hdr.csumOffset:],
					checksum([]byte{}, pseudoHeaderChecksum),
				)
			} else {
				hdr := virtioNetHdr{}
				if err := hdr.encode(
					bufs[item.bufsIndex][offset-virtioNetHdrLen:],
				); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// applyUDPCoalesce updates bufs to account for
// coalescing based on the metadata found in table.
func applyUDPCoalesce(
	bufs [][]byte,
	offset int,
	table *udpGROTable,
) error {
	for _, items := range table.itemsByFlow {
		for _, item := range items {
			if item.numMerged > 0 {
				hdr := virtioNetHdr{
					// This turns into CHECKSUM_PARTIAL in the skb (Socket Buffer).
					// Indicate that the packet requires checksum processing.
					flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
					hdrLen:     uint16(item.iphLen + udphLen),
					gsoSize:    item.gsoSize,
					csumStart:  uint16(item.iphLen),
					csumOffset: 6,
				}
				pkt := bufs[item.bufsIndex][offset:]
				// Recalculate the total len (IPv4) or payload len (IPv6).
				// Recalculate the (IPv4) header checksum.
				hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_UDP_L4
				if item.key.isV6 {
					// set new IPv6 header payload len
					binary.BigEndian.PutUint16(
						pkt[4:],
						uint16(len(pkt))-uint16(item.iphLen),
					)
				} else {
					// set IPv4 header checksum field to 0
					pkt[10], pkt[11] = 0, 0
					// set new total length
					binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
					// compute IPv4 header checksum
					iphChecksum := ^checksum(pkt[:item.iphLen], 0)
					// set IPv4 header checksum field
					binary.BigEndian.PutUint16(pkt[10:], iphChecksum)
				}
				// TODO: why is there space reserved for virtioNetHdr?
				if err := hdr.encode(
					bufs[item.bufsIndex][offset-virtioNetHdrLen:],
				); err != nil {
					return err
				}
				// recalculate the UDP len field value
				binary.BigEndian.PutUint16(
					pkt[item.iphLen+4:],
					uint16(len(pkt[item.iphLen:])),
				)
				// Calculate the pseudo header checksum and place it at the UDP
				// checksum offset. Downstream checksum offloading will combine
				// this with computation of the udp header and payload checksum.
				addrLen := 4
				addrOffset := ipv4SrcAddrOffset
				if item.key.isV6 {
					addrLen = 16
					addrOffset = ipv6SrcAddrOffset
				}
				srcAddrAt := offset + addrOffset
				srcAddr := bufs[item.bufsIndex][srcAddrAt : srcAddrAt+addrLen]
				dstAddr := bufs[item.bufsIndex][srcAddrAt+addrLen : srcAddrAt+addrLen*2]
				pseudoHeaderChecksum :=
					pseudoHeaderChecksumNoFold(
						srcAddr,
						dstAddr,
						unix.IPPROTO_UDP,
						uint16(len(pkt)-int(item.iphLen)),
					)
				// checksum([]byte{}, pseudoHeaderChecksum) folds the initial value
				binary.BigEndian.PutUint16(
					pkt[hdr.csumStart+hdr.csumOffset:],
					checksum([]byte{}, pseudoHeaderChecksum),
				)
			} else {
				hdr := virtioNetHdr{}
				if err := hdr.encode(
					bufs[item.bufsIndex][offset-virtioNetHdrLen:],
				); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type groCandidateType uint8

const (
	notGROCandidate groCandidateType = iota
	tcp4GROCandidate
	tcp6GROCandidate
	udp4GROCandidate
	udp6GROCandidate
)

func packetIsGROCandidate(pkt []byte, canUDPGRO bool) groCandidateType {
	// min IP header length (20) plus UDP header length (8)
	if len(pkt) < 28 {
		return notGROCandidate
	}
	// check if IPv4
	if pkt[0]>>4 == 4 {
		// Check IPv4 header length. Without options it's 5 (20 bytes).
		if pkt[0]&0x0F != 5 {
			// IPv4 packets with IP options do not coalesce
			return notGROCandidate
		}
		// check if payload is a TCP frame and that IP header
		// and TCP header are of valid length (20 bytes each)
		if pkt[9] == unix.IPPROTO_TCP && len(pkt) >= 40 {
			return tcp4GROCandidate
		}
		// check if payload is a UDP frame
		if pkt[9] == unix.IPPROTO_UDP && canUDPGRO {
			return udp4GROCandidate
		}
		// check if IPv6
	} else if pkt[0]>>4 == 6 {
		// Check if payload is a TCP frame and that IP header
		// and TCP header are of valid length.
		// IP header is 40 bytes, TCP is 20 bytes.
		if pkt[6] == unix.IPPROTO_TCP && len(pkt) >= 60 {
			return tcp6GROCandidate
		}
		// Check if payload is a UDP frame and that IP header
		// and TCP header are of valid length.
		// IP header is 40 bytes, UDP is 8 bytes.
		if pkt[6] == unix.IPPROTO_UDP && len(pkt) >= 48 && canUDPGRO {
			return udp6GROCandidate
		}
	}
	return notGROCandidate
}

// handleGRO evaluates bufs for GRO, and writes the indices
// of the resulting packets into toWrite. toWrite, tcpTable,
// and udpTable should initially be empty (but non-nil),
// and are passed in to save allocs as the caller may reset
// and recycle them across vectors of packets. canUDPGRO
// indicates if UDP GRO is supported.
func handleGRO(
	bufs [][]byte,
	offset int,
	tcpTable *tcpGROTable,
	udpTable *udpGROTable,
	canUDPGRO bool,
	toWrite *[]int,
) error {
	for i := range bufs {
		if offset < virtioNetHdrLen || offset > len(bufs[i])-1 {
			return errors.New("invalid offset")
		}
		var result groResult
		switch packetIsGROCandidate(bufs[i][offset:], canUDPGRO) {
		case tcp4GROCandidate:
			result = tcpGRO(bufs, offset, i, tcpTable, false)
		case tcp6GROCandidate:
			result = tcpGRO(bufs, offset, i, tcpTable, true)
		case udp4GROCandidate:
			result = udpGRO(bufs, offset, i, udpTable, false)
		case udp6GROCandidate:
			result = udpGRO(bufs, offset, i, udpTable, true)
		}
		switch result {
		case groResultNoop:
			// no GRO used, encode just empty virtioNetHdr
			hdr := virtioNetHdr{}
			if err := hdr.encode(
				bufs[i][offset-virtioNetHdrLen:],
			); err != nil {
				return err
			}
			fallthrough
		case groResultTableInsert:
			// TODO: check how it works with Write
			*toWrite = append(*toWrite, i)
		}
	}
	errTCP := applyTCPCoalesce(bufs, offset, tcpTable)
	errUDP := applyUDPCoalesce(bufs, offset, udpTable)
	return errors.Join(errTCP, errUDP)
}

// gsoSplit splits packets from `readBuf` into `bufs`,
// writing the size of each element into `sizes`.
// It returns the number of buffers populated,
// and/or an error. Used by handleVirtioRead.
func gsoSplit(
	readBuf []byte,
	hdr virtioNetHdr,
	bufs [][]byte,
	sizes []int,
	offset int,
	isV6 bool,
) (int, error) {
	iphLen := int(hdr.csumStart)
	srcAddrOffset := ipv6SrcAddrOffset
	addrLen := 16
	if !isV6 {
		readBuf[10], readBuf[11] = 0, 0 // clear ipv4 header checksum
		srcAddrOffset = ipv4SrcAddrOffset
		addrLen = 4
	}
	// TCP or UDP header checksum offset
	transportChecksumAt := int(hdr.csumStart + hdr.csumOffset)
	// clear TCP/UDP checksum
	readBuf[transportChecksumAt], readBuf[transportChecksumAt+1] = 0, 0
	var firstSeq uint32
	var protocol uint8
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV4 ||
		hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV6 {
		protocol = unix.IPPROTO_TCP
		// extract sequence number from TCP header
		firstSeq = binary.BigEndian.Uint32(readBuf[hdr.csumStart+4:])
	} else {
		protocol = unix.IPPROTO_UDP
	}
	nextSegmentDataStart := int(hdr.hdrLen)
	i := 0 // bufs index
	for nextSegmentDataStart < len(readBuf) {
		if i == len(bufs) {
			return i - 1, ErrTooManySegments
		}
		nextSegmentEnd := nextSegmentDataStart + int(hdr.gsoSize)
		nextSegmentEnd = min(nextSegmentEnd, len(readBuf))
		segmentDataLen := nextSegmentEnd - nextSegmentDataStart
		totalLen := int(hdr.hdrLen) + segmentDataLen
		sizes[i] = totalLen
		out := bufs[i][offset:]
		// copy IP header
		copy(out, readBuf[:iphLen])
		if !isV6 {
			// For IPv4 we are responsible for incrementing the ID field,
			// updating the total len field, and recalculating the header
			// checksum.
			// If i = 0, then no need to update identification field
			// because it does not change.
			if i > 0 {
				// out is a different slice on every iteration
				id := binary.BigEndian.Uint16(out[4:])
				id += uint16(i)
				binary.BigEndian.PutUint16(out[4:], id)
			}
			binary.BigEndian.PutUint16(out[2:], uint16(totalLen))
			ipv4CSum := ^checksum(out[:iphLen], 0)
			binary.BigEndian.PutUint16(out[10:], ipv4CSum)
		} else {
			// For IPv6 we are responsible for updating the payload length field.
			binary.BigEndian.PutUint16(out[4:], uint16(totalLen-iphLen))
		}
		// copy transport header ([iphLen:iphLen+tcp/udphLen])
		copy(out[hdr.csumStart:hdr.hdrLen], readBuf[hdr.csumStart:hdr.hdrLen])
		if protocol == unix.IPPROTO_TCP {
			// set TCP seq and adjust TCP flags
			seq := firstSeq + uint32(hdr.gsoSize*uint16(i))
			binary.BigEndian.PutUint32(out[hdr.csumStart+4:], seq)
			if nextSegmentEnd != len(readBuf) {
				// FIN and PSH should only be set on last segment
				clearFlags := tcpFlagFIN | tcpFlagPSH
				// "&^" is the "AND NOT" or "bit clear" operator.
				// It clears bits where the right operand has 1s.
				// x &^= y is equivalent to x = x & (^y)
				// Example:
				// x = 0b11111111
				// y = 0b00010001  // clear bits 4 and 0
				// x &^= y         // x = 0b11101110
				out[hdr.csumStart+tcpFlagsOffset] &^= clearFlags
			}
		} else {
			// set UDP header len
			binary.BigEndian.PutUint16(
				out[hdr.csumStart+4:],
				uint16(segmentDataLen)+(hdr.hdrLen-hdr.csumStart),
			)
		}
		// payload
		copy(out[hdr.hdrLen:], readBuf[nextSegmentDataStart:nextSegmentEnd])
		// transport checksum
		transportHeaderLen := int(hdr.hdrLen - hdr.csumStart)
		lenForPseudo := uint16(transportHeaderLen + segmentDataLen)
		transportChecksumNoFold :=
			pseudoHeaderChecksumNoFold(
				readBuf[srcAddrOffset:srcAddrOffset+addrLen],
				readBuf[srcAddrOffset+addrLen:srcAddrOffset+addrLen*2],
				protocol,
				lenForPseudo,
			)
		transportChecksum := ^checksum(
			out[hdr.csumStart:totalLen],
			transportChecksumNoFold,
		)
		binary.BigEndian.PutUint16(
			out[hdr.csumStart+hdr.csumOffset:],
			transportChecksum,
		)
		nextSegmentDataStart += int(hdr.gsoSize)
		i++
	}
	return i, nil
}

// gsoNoneChecksum only does checksum calculation
// without packet splitting. Used by handleVirtioRead.
func gsoNoneChecksum(
	readBuf []byte,
	checksumStart, // TCP/UDP header start (IP header length)
	checksumOffset uint16, // checksum field offset from checksumStart
) error {
	// calculate checksum field index
	checksumAt := checksumStart + checksumOffset
	// The initial value at the checksum offset
	// should be summed with the checksum we compute.
	// This is typically the pseudo-header checksum.
	initial := binary.BigEndian.Uint16(readBuf[checksumAt:])
	// reset checksum
	readBuf[checksumAt], readBuf[checksumAt+1] = 0, 0
	// new checksum
	binary.BigEndian.PutUint16(
		readBuf[checksumAt:],
		^checksum(readBuf[checksumStart:], uint64(initial)),
	)
	return nil
}
