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
	// Bit position where host part begins (0 is LSB, 7 is MSB):
	// 	192.168.1.0/24
	// 	7 - 24 % 8 = 7
	shift uint8
	// network address masked to the CIDR length
	addr []byte
	peer *Peer
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

func (n *node) childIndex(ip []byte) byte {
	return (ip[n.index] >> n.shift) & 1
}

func (n *node) nodePlacement(ip []byte, cidr uint8) (parent *node, exact bool) {
	// n != nil: checks if we reached the end of the trie.
	// n.cidr <= cidr: checks if current node's prefix is
	// 	equal or less specific than what we're inserting.
	//	Can't go past a more specific route.
	//	If current is `/24` and inserting `/16`, stop (would insert above).
	// commonBits(n.addr, ip) >= n.cidr: checks if IP is
	// 	on the node's network.
	// Example trie:
	// 10.0.0.0/8 (node A)
	// ├── 10.0.0.0/16 (node B) ← child[0] of A
	// └── 10.128.0.0/16 (node C) ← child[1] of A
	for n != nil && n.cidr <= cidr && commonBits(n.addr, ip) >= n.cidr {
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

func (n *node) maskSelf() {
	// addr = []byte{192, 168, 1, 5}
	// cidr = 24
	// mask = []byte{255, 255, 255, 0}
	// addr[0] &= 255  // 192 & 255 = 192
	// addr[1] &= 255  // 168 & 255 = 168
	// addr[2] &= 255  // 1 & 255 = 1
	// addr[3] &= 0    // 5 & 0 = 0
	// addr = []byte{192, 168, 1, 0}
	mask := net.CIDRMask(int(n.cidr), len(n.addr)*8)
	for i := range len(mask) {
		n.addr[i] &= mask[i]
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

func (n *node) zeroOutPointers() {
	// make the garbage collector's life slightly easier
	n.peer = nil
	n.parent.child = nil
	n.children[0] = nil
	n.children[1] = nil
}

func (p parent) insert(ip []byte, cidr uint8, peer *Peer) {
	// p is the parent type with a child field which contains the root node.
	// If parent has no child, add the inserted node as its child to be
	// the first node in the trie and its root.
	if *p.child == nil {
		newNode := &node{
			parent: p,
			cidr:   cidr,
			index:  cidr / 8,
			shift:  7 - (cidr % 8),
			addr:   ip,
			peer:   peer,
		}
		newNode.maskSelf()
		newNode.addToPeerNodes()
		*p.child = newNode
		return
	}
	// Traverse the trie to find where to insert the new node.
	// parentNode is the new node's parent.
	parentNode, exact := (*p.child).nodePlacement(ip, cidr)
	// Check if the new node is on the same network as its parent,
	// if it is, just replace parent peer with new peer.
	if exact {
		parentNode.removeFromPeerNodes()
		parentNode.peer = peer
		parentNode.addToPeerNodes()
		return
	}
	newNode := &node{
		cidr:  cidr,
		index: cidr / 8,
		shift: 7 - (cidr % 8),
		addr:  ip,
		peer:  peer,
	}
	newNode.maskSelf()
	newNode.addToPeerNodes()
	// down is either the root node or a parentNode's child which takes the slot
	// where the new node fits.
	var down *node
	if parentNode == nil {
		// if new node has no parent start at the root
		down = *p.child
	} else { // new node has a parent node
		// find new node's childindex
		index := parentNode.childIndex(ip)
		down = parentNode.children[index]
		// Check if child slot is empty,
		// if it is, insert there the new node.
		if down == nil {
			newNode.parent = parent{&parentNode.children[index], index}
			parentNode.children[index] = newNode
			return
		}
	}
	common := commonBits(down.addr, ip)
	cidr = min(cidr, common)
	next := parentNode
	if newNode.cidr == cidr {
		index := newNode.childIndex(down.addr)
		down.parent = parent{&newNode.children[index], index}
		newNode.children[index] = down
		if next == nil {
			newNode.parent = p
			*p.child = newNode
		} else {
			index := next.childIndex(newNode.addr)
			newNode.parent = parent{&next.children[index], index}
			next.children[index] = newNode
		}
		return
	}
	// intermediate node?
	nd := &node{
		cidr:  cidr,
		index: cidr / 8,
		shift: 7 - (cidr % 8),
		// copy slice
		addr: append([]byte{}, newNode.addr...),
	}
	nd.maskSelf()
	index := nd.childIndex(down.addr)
	down.parent = parent{&nd.children[index], index}
	nd.children[index] = down
	index = nd.childIndex(newNode.addr)
	newNode.parent = parent{&nd.children[index], index}
	nd.children[index] = newNode
	if next == nil {
		nd.parent = p
		*p.child = nd
	} else {
		index := next.childIndex(nd.addr)
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

func (n *node) find(ip []byte) *Peer {
	var peer *Peer
	size := uint8(len(ip))
	// `commonBits(n.addr, ip) >= n.cidr` checks if IP is
	// 	on the node's network.
	for n != nil && commonBits(n.addr, ip) >= n.cidr {
		if n.peer != nil {
			peer = n.peer
		}
		// IP: 192.168.1.100 (size = 4 bytes).
		// Node with /24: index = 3 (24/8 = 3), shift = 7.
		// We still need to check bit 24-31, so we continue.
		// Node with /32: index = 4 (32/8 = 4), shit = 7.
		// Since index == size (4 == 4), we break.
		// There cannot be any child nodes because:
		// 	You can't have a more specific route than a host route.
		// 	There are no bits left to examine - we've used all 32/128 bits.
		// Without this check, the code would try to compute:
		// index := n.childIndex(ip)  // This would index beyond the IP slice!
		// n = n.children[index]
		// For a /32 IPv4 route:
		// 	n.index = 4
		// 	But valid indices for ip are only 0-3
		//	This would cause an index out of bounds panic.
		if n.index == size {
			break
		}
		index := n.childIndex(ip)
		n = n.children[index]
	}
	return peer
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
	if prefix.Addr().Is4() {
		ip := prefix.Addr().As4()
		parent{&ips.IPv4, 2}.insert(ip[:], uint8(prefix.Bits()), peer)
	} else if prefix.Addr().Is6() {
		ip := prefix.Addr().As16()
		parent{&ips.IPv6, 2}.insert(ip[:], uint8(prefix.Bits()), peer)
	} else {
		panic(errors.New("inserting unknown address type"))
	}
}

func (ips *AllowedIPs) Find(ip []byte) *Peer {
	ips.mu.RLock()
	defer ips.mu.RUnlock()
	switch len(ip) {
	case net.IPv4len:
		return ips.IPv4.find(ip)
	case net.IPv6len:
		return ips.IPv6.find(ip)
	default:
		panic(errors.New("looking up unknown address type"))
	}
}

func (ips *AllowedIPs) Remove(prefix netip.Prefix, peer *Peer) {
	ips.mu.Lock()
	defer ips.mu.Unlock()
	var n *node
	var exact bool
	if prefix.Addr().Is4() {
		ip := prefix.Addr().As4()
		n, exact = ips.IPv4.nodePlacement(ip[:], uint8(prefix.Bits()))
	} else if prefix.Addr().Is6() {
		ip := prefix.Addr().As16()
		n, exact = ips.IPv6.nodePlacement(ip[:], uint8(prefix.Bits()))
	} else {
		panic(errors.New("removing unknown address type"))
	}
	if !exact || n == nil || peer != n.peer {
		return
	}
	n.remove()
}

func (ips *AllowedIPs) RemoveByPeer(peer *Peer) {
	ips.mu.Lock()
	defer ips.mu.Unlock()
	var next *list.Element
	for elem := peer.nodes.Front(); elem != nil; elem = next {
		// Save the next element, because the current element's
		// pointers (elem.next and elem.prev) are zeroed out on removal.
		next = elem.Next()
		elem.Value.(*node).remove()
	}
}

func (ips *AllowedIPs) PeerNodes(peer *Peer, cb func(prefix netip.Prefix) bool) {
	ips.mu.RLock()
	defer ips.mu.RUnlock()
	for elem := peer.nodes.Front(); elem != nil; elem = elem.Next() {
		n := elem.Value.(*node)
		addr, _ := netip.AddrFromSlice(n.addr)
		if !cb(netip.PrefixFrom(addr, int(n.cidr))) {
			return
		}
	}
}
