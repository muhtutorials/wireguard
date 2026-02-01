package device

import (
	"container/list"
	"encoding/binary"
	"math/bits"
	"net"
)

// parent indirection
type parent struct {
	parentBit     **node
	parentBitType uint8
}

// node in the trie
type node struct {
	peer   *Peer
	child  [2]*node
	parent parent
	// classless inter-domain routing
	cidr        uint8
	bitAtByte   uint8
	bitAtShift  uint8
	bits        []byte
	perPeerElem *list.Element
}

func commonBits(ip1, ip2 []byte) uint8 {
	switch len(ip1) {
	case net.IPv4len:
		a := binary.BigEndian.Uint32(ip1)
		b := binary.BigEndian.Uint32(ip2)
		x := a ^ b
		return uint8(bits.LeadingZeros32(x))
	case net.IPv6len:
		a := binary.BigEndian.Uint64(ip1)
		b := binary.BigEndian.Uint64(ip2)
		x := a ^ b
		if x != 0 {
			return uint8(bits.LeadingZeros64(x))
		}
		a = binary.BigEndian.Uint64(ip1[8:])
		b = binary.BigEndian.Uint64(ip2[8:])
		x = a ^ b
		return 64 + uint8(bits.LeadingZeros64(x))
	default:
		panic("Wrong size bit string")
	}
}
