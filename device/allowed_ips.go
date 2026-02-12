// This trie data structures determine which peer
// should handle traffic for a given IP address.
package device

import (
	"container/list"
	"encoding/binary"
	"errors"
	"math/bits"
	"net"
	"net/netip"
	"sync"
	"unsafe"
)

// Parent indirection. Used node removal optimization.
type parent struct {
	child      **node
	childIndex uint8
}

// node in the trie
type node struct {
	parent   parent
	children [2]*node
	// Classless inter-domain routing (CIDR) stores prefix
	// length (range of 0-32 for IPv4, range of 0-128 for IPv6).
	// IP address + prefix length:
	// 	192.168.1.0/24
	// 	2001:db8::/32
	// 	10.0.0.0/8
	// IP address: the starting address of the block.
	// Prefix length: how many bits are fixed (the network part).
	// The remaining bits are variable (the host part).
	cidr uint8
	// Byte index where host part begins:
	// 	192.168.1.0/24
	// 	24 / 8 = 3
	index uint8
	// Bit shift where host part begins:
	// 	192.168.1.0/24
	// 	7 - 24 % 8 = 7
	shift uint8
	// Network portion (CIDR bits) of IP address.
	// Host bits are zeroed.
	network []byte
	peer    *Peer
	// Peer can have multiple IPs which are stored in Peer.nodes list.
	// peerNode is an element in that list.
	// Peer.nodes is used for easy peer removal where you don't
	// need to traverse the whole trie by comparing node.peer == peer
	// to remove every node which belong to the peer.
	// You can delete them directly by iterating Peer.nodes.
	peerNode *list.Element
}

// commonBits calculates how many leading bits
// in two IPs are the same
func commonBits(ip1, ip2 []byte) uint8 {
	switch len(ip1) {
	case net.IPv4len:
		// convert []byte to uint32
		a := binary.BigEndian.Uint32(ip1)
		b := binary.BigEndian.Uint32(ip2)
		// XOR two values so the same bits give a zero
		x := a ^ b
		// calculate how many leading bits are the same
		// by counting leading zeroes which we get
		// from the previous operation
		return uint8(bits.LeadingZeros32(x))
	case net.IPv6len:
		a := binary.BigEndian.Uint64(ip1)
		b := binary.BigEndian.Uint64(ip2)
		x := a ^ b
		// if the first 8 bytes differ no need to check the rest 8 bytes
		if x != 0 {
			return uint8(bits.LeadingZeros64(x))
		}
		// compare the second part of IP addresses (len(ipv6) == 16)
		a = binary.BigEndian.Uint64(ip1[8:])
		b = binary.BigEndian.Uint64(ip2[8:])
		x = a ^ b
		return 64 + uint8(bits.LeadingZeros64(x))
	default:
		panic("wrong size bit string")
	}
}

func (n *node) addToPeerNodes() {
	n.peerNode = n.peer.nodes.PushBack(n)
}

func (n *node) removeFromPeerNodes() {
	if n.peerNode != nil {
		n.peer.nodes.Remove(n.peerNode)
		n.peerNode = nil
	}
}

func (n *node) childIndex(ip []byte) byte {
	return (ip[n.index] >> n.shift) & 1
}

// network = []byte{192, 168, 1, 5}
// cidr = 24
// mask = []byte{255, 255, 255, 0}
// network[0] &= 255  // 192 & 255 = 192
// network[1] &= 255  // 168 & 255 = 168
// network[2] &= 255  // 1 & 255 = 1
// network[3] &= 0    // 5 & 0 = 0
// network = []byte{192, 168, 1, 0}
func (n *node) maskSelf() {
	mask := net.CIDRMask(int(n.cidr), len(n.network)*8)
	for i := range len(mask) {
		n.network[i] &= mask[i]
	}
}

func (n *node) zeroOutPointers() {
	// make the garbage collector's life slightly easier
	n.peer = nil
	n.parent.child = nil
	n.children[0] = nil
	n.children[1] = nil
}

func (n *node) nodePlacement(ip []byte, cidr uint8) (parent *node, exact bool) {
	// n != nil: checks if we reached the end of the trie.
	// n.cidr <= cidr: checks if current node's prefix is
	// 	equal or less specific than what we're inserting.
	//	Can't go past a more specific route.
	//	If current is `/24` and inserting `/16`, stop (would insert above).
	// commonBits(n.network, ip) >= n.cidr: checks if IP is within
	// 	the CIDR prefix (belongs to the network).
	// Example trie:
	// 10.0.0.0/8 (node A)
	// ├── 10.0.0.0/16 (node B) ← child[0] of A
	// └── 10.128.0.0/16 (node C) ← child[1] of A
	for n != nil && n.cidr <= cidr && commonBits(n.network, ip) >= n.cidr {
		parent = n
		// check if the same network
		if parent.cidr == cidr {
			exact = true
			return
		}
		index := n.childIndex(ip)
		n = n.children[index]
	}
	return
}

func (p parent) insert(ip []byte, cidr uint8, peer *Peer) {
	// p is root
	if *p.child == nil {
		newNode := &node{
			parent:  p,
			cidr:    cidr,
			index:   cidr / 8,
			shift:   7 - (cidr % 8),
			network: ip,
			peer:    peer,
		}
		newNode.maskSelf()
		newNode.addToPeerNodes()
		*p.child = newNode
		return
	}
	parentNode, exact := (*p.child).nodePlacement(ip, cidr)
	if exact {
		parentNode.removeFromPeerNodes()
		// replace peer with new peer
		parentNode.peer = peer
		parentNode.addToPeerNodes()
		return
	}
	newNode := &node{
		cidr:    cidr,
		index:   cidr / 8,
		shift:   7 - (cidr % 8),
		network: ip,
		peer:    peer,
	}
	newNode.maskSelf()
	newNode.addToPeerNodes()
	var down *node
	if parentNode == nil {
		down = *p.child
	} else {
		index := parentNode.childIndex(ip)
		down = parentNode.children[index]
		if down == nil {
			newNode.parent = parent{&parentNode.children[index], index}
			parentNode.children[index] = newNode
			return
		}
	}
	common := commonBits(down.network, ip)
	if common < cidr {
		cidr = common
	}
	next := parentNode
	if newNode.cidr == cidr {
		index := newNode.childIndex(down.network)
		down.parent = parent{&newNode.children[index], index}
		newNode.children[index] = down
		if next == nil {
			newNode.parent = p
			*p.child = newNode
		} else {
			index := next.childIndex(newNode.network)
			newNode.parent = parent{&next.children[index], index}
			next.children[index] = newNode
		}
		return
	}
	nd := &node{
		cidr:  cidr,
		index: cidr / 8,
		shift: 7 - (cidr % 8),
		// copy slice
		network: append([]byte{}, newNode.network...),
	}
	nd.maskSelf()
	index := nd.childIndex(down.network)
	down.parent = parent{&nd.children[index], index}
	nd.children[index] = down
	index = nd.childIndex(newNode.network)
	newNode.parent = parent{&nd.children[index], index}
	nd.children[index] = newNode
	if next == nil {
		nd.parent = p
		*p.child = nd
	} else {
		index := next.childIndex(nd.network)
		nd.parent = parent{&next.children[index], index}
		next.children[index] = nd
	}
}

// remove removes node (method receiver) from the trie.
func (n *node) remove() {
	n.removeFromPeerNodes()
	n.peer = nil
	// If node has two children, the trie remains intact,
	// node becomes empty (n.peer == nil).
	if n.children[0] != nil && n.children[1] != nil {
		return
	}
	// node has one or zero children
	index := 0
	if n.children[0] == nil {
		index = 1
	}
	child := n.children[index]
	// If node has one child, this child becomes node's parent's child,
	// i.e. child becomes node and node is removed from the trie.
	if child != nil {
		child.parent = n.parent
	}
	*n.parent.child = child
	if n.children[0] != nil || n.children[1] != nil || n.parent.childIndex > 1 {
		n.zeroOutPointers()
		return
	}
	// type parent struct {
	// 	child      **node
	// 	childIndex uint8
	// }
	//
	// type node struct {
	// 	parent   parent
	// 	children [2]*node
	// 	...
	// }
	//
	// func main() {
	// 	child0 := &node{}
	// 	child1 := &node{}
	// 	parentNode := node{
	// 		children: [2]*node{child0, child1},
	// 	}
	// 	child0.parent = parent{
	// 		child:      &parentNode.children[0],
	// 		childIndex: 0,
	// 	}
	// 	fmt.Printf("parentNode address %d\n", unsafe.Pointer(&parentNode))
	// 	fmt.Println("parentNode.parent offset", unsafe.Offsetof(parentNode.parent))
	// 	fmt.Println("parentNode.children offset", unsafe.Offsetof(parentNode.children))
	// 	fmt.Printf("parentNode.children[0] address %d\n", unsafe.Pointer(parentNode.children[0]))
	// 	fmt.Printf("parentNode.children[1] address %d\n", unsafe.Pointer(parentNode.children[1]))
	// 	fmt.Printf("child0 address %d\n", unsafe.Pointer(child0))
	// 	fmt.Printf("child1 address %d\n", unsafe.Pointer(child1))
	// 	fmt.Printf("child0.parent.child address %d\n", unsafe.Pointer(child0.parent.child))
	// }
	//
	// addresses are converted into decimals
	// parentNode address 824634892352
	// parentNode.parent offset 0
	// parentNode.children offset 16
	// parentNode.children[0] address 824634892288
	// parentNode.children[1] address 824634892320
	// child0 address 824634892288
	// child1 address 824634892320
	// child0.parent.child address 824634892368
	//
	// 					 		↓824634892368 mem addr of pointer to children[0]
	//                    ↓mem addr of children[0] ↓mem addr of children[1]
	// children: [2]*node{824634892288, 824634892320}
	ptrToChildPtr := uintptr(unsafe.Pointer(n.parent.child))
	childrenOffset := unsafe.Offsetof(n.children)
	childOffset := unsafe.Sizeof(n.children[0]) * uintptr(n.parent.childIndex)
	parentPtr := unsafe.Pointer(ptrToChildPtr - childrenOffset - childOffset)
	parent := (*node)(parentPtr)
	// If node has no children and parent node is not empty
	// (parent.peer != nil), node is removed from the trie.
	if parent.peer != nil {
		n.zeroOutPointers()
		return
	}
	// check another parent's child
	child = parent.children[n.parent.childIndex^1]
	// If node has no children, parent node is empty
	// (parent.peer == nil) and parent node has another child,
	// this child becomes new parent and both old parent and
	// node are removed from the trie.
	// If parent doesn't have another child, parent and
	// node are removed from the trie.
	if child != nil {
		child.parent = parent.parent
	}
	*parent.parent.child = child
	n.zeroOutPointers()
	parent.zeroOutPointers()
}

type AllowedIPs struct {
	IPv4 *node
	IPv6 *node
	mu   sync.RWMutex
}

func (ips *AllowedIPs) Insert(prefix netip.Prefix, peer *Peer) {
	ips.mu.Lock()
	defer ips.mu.Unlock()
	// `parent.childIndex = 2` signifies the root of the trie
	if prefix.Addr().Is6() {
		ip := prefix.Addr().As16()
		parent{&ips.IPv6, 2}.insert(ip[:], uint8(prefix.Bits()), peer)
	} else if prefix.Addr().Is4() {
		ip := prefix.Addr().As4()
		parent{&ips.IPv4, 2}.insert(ip[:], uint8(prefix.Bits()), peer)
	} else {
		panic(errors.New("inserting unknown address type"))
	}
}
