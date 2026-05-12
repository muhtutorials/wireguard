// This trie data structure determines which peer
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

// Parent indirection (storing a **node + childIndex instead
// of just a *node) exists for direct, O(1) modification of
// the parent's child pointer during removal, without needing
// to know the parent node's address or compare children.
type parent struct {
	// pointer to one of the two elements of parent node's children array
	child **node
	// either 0 or 1 (left or right child)
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
	// Index of byte where host part begins:
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
	// Node is an element in that list.
	// Peer.nodes is used for easy peer removal where we don't need to
	// traverse the whole trie by making comparison `node.peer == peer`
	// to remove every node which belong to the peer.
	// We can delete them directly by iterating Peer.nodes.
	peerNode *list.Element
}

// commonBits calculates how many leading bits
// in two IPs are the same
func commonBits(ip1, ip2 []byte) uint8 {
	switch len(ip1) {
	case net.IPv4len: // 4 bytes long
		// convert []byte to uint32
		a := binary.BigEndian.Uint32(ip1)
		b := binary.BigEndian.Uint32(ip2)
		// XOR two values so the same bits give a zero
		x := a ^ b
		// calculate how many leading bits are the same
		// by counting leading zeroes which we got
		// from the previous operation
		return uint8(bits.LeadingZeros32(x))
	case net.IPv6len: // 16 bytes long
		a := binary.BigEndian.Uint64(ip1)
		b := binary.BigEndian.Uint64(ip2)
		x := a ^ b
		// if the first 8 bytes differ no need to check the rest 8 bytes
		if x != 0 {
			return uint8(bits.LeadingZeros64(x))
		}
		// compare the second part of IP addresses
		a = binary.BigEndian.Uint64(ip1[8:])
		b = binary.BigEndian.Uint64(ip2[8:])
		x = a ^ b
		return 64 + uint8(bits.LeadingZeros64(x))
	default:
		panic("wrong size bit string")
	}
}

// childIndex returns index of the child node to which passed IP belongs.
// It's either 0 or 1 (left or right child).
func (n *node) childIndex(ip []byte) byte {
	return (ip[n.index] >> n.shift) & 1
}

func (n *node) nodePlacement(ip []byte, cidr uint8) (parent *node, exact bool) {
	// n != nil: checks if we reached the end of the trie.
	// n.cidr <= cidr: checks if current node's prefix is
	// 	equal or less specific than what we're inserting.
	//	We can't go past a more specific route.
	//	If current is `/24` and inserting `/16`, stop (would insert above).
	// commonBits(n.addr, ip) >= n.cidr: checks if IP is
	// 	on the node's network.
	// /[number]: number of network bits (network part).
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
		n = n.children[n.childIndex(ip)]
	}
	return
}

// maskSelf discards (zeroes out) all bits that are not in CIDR range.
// That is, only network part of IP address remains.
func (n *node) maskSelf() {
	// addr = []byte{192, 168, 1, 5}
	// cidr = 24 (first 24 bits)
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
	n.parent.child = nil
	n.children[0] = nil
	n.children[1] = nil
	n.peer = nil
}

func (p parent) insert(ip []byte, cidr uint8, peer *Peer) {
	// `p` here is the parent type with a child field containing
	// the root node. If parent has no child, we add the new node
	// as its child to be the first and the root node in the trie.
	// CASE 1: the new node is the first node in the trie.
	if *p.child == nil {
		// the trie is empty, so we insert the first node
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
	// `parentNode` is the new node's parent.
	parentNode, exact := (*p.child).nodePlacement(ip, cidr)
	// Check if the new node has the same network address as its parent.
	// If it does, we just replace parent peer with new peer.
	// CASE 2: the new node has exact network address match.
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
	// `down` is either the root node or a parent node's child
	// which takes the slot where the new node fits
	var down *node
	// CASE 3: the new node has no parent.
	if parentNode == nil {
		// if the new node has no parent start at the root
		down = *p.child
	} else { // CASE 4: the new node has a parent.
		// Find the new node's child index.
		index := parentNode.childIndex(ip)
		down = parentNode.children[index]
		// Check if child slot is empty.
		// If it is, insert the new node there.
		// CASE 5: the new node's parent has a free child slot.
		if down == nil {
			newNode.parent = parent{&parentNode.children[index], index}
			parentNode.children[index] = newNode
			return
		}
	}
	// The new node needs to be inserted but there's
	// already an existing node (down) in the way.
	// Calculate common prefix length.
	common := commonBits(down.addr, ip)
	cidr = min(cidr, common)
	// Check if the new node can be the parent of `down` node.
	// CASE 6: the new node can be the parent of `down` node.
	if newNode.cidr == cidr {
		index := newNode.childIndex(down.addr)
		down.parent = parent{&newNode.children[index], index}
		newNode.children[index] = down
		// CASE 7: the new node has no parent but a parent itself.
		if parentNode == nil {
			newNode.parent = p
			*p.child = newNode
		} else { // CASE 8: the new node has a parent and a parent itself.
			index := parentNode.childIndex(newNode.addr)
			newNode.parent = parent{&parentNode.children[index], index}
			parentNode.children[index] = newNode
		}
		return
	}
	// common node which will contain both the new
	// node and `down` node which was in the way
	commonNode := &node{
		cidr:  cidr, // min cidr
		index: cidr / 8,
		shift: 7 - (cidr % 8),
		// Even if newNode.addr has longer prefix than minimum cidr
		// between the new node and `down` node, it will be masked later.
		// down.addr could be used here too.
		addr: append([]byte{}, newNode.addr...), // copy slice
	}
	commonNode.maskSelf()
	index := commonNode.childIndex(down.addr)
	down.parent = parent{&commonNode.children[index], index}
	commonNode.children[index] = down
	index = commonNode.childIndex(newNode.addr)
	newNode.parent = parent{&commonNode.children[index], index}
	commonNode.children[index] = newNode
	// CASE 9: common node has no parent.
	if parentNode == nil {
		commonNode.parent = p
		*p.child = commonNode
	} else { // CASE 10: common node has a parent.
		index := parentNode.childIndex(commonNode.addr)
		commonNode.parent = parent{&parentNode.children[index], index}
		parentNode.children[index] = commonNode
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
	// If node has one child, this child becomes node
	// and node is removed from the trie.
	if child != nil {
		child.parent = n.parent
	}
	*n.parent.child = child
	// Node has one child or its parent struct is the root of the trie.
	// `n.parent.childIndex > 1` checks for `2`
	// which signifies the root of the trie.
	if child != nil || n.parent.childIndex > 1 {
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
	//
	// Node has no children, so we remove it and check parent and its another child.
	// We get parent node using pointer arithmetic.
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
	// check parent's another child
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
	ipLen := uint8(len(ip))
	// `commonBits(n.addr, ip) >= n.cidr` checks if IP is
	// 	on the node's network.
	for n != nil && commonBits(n.addr, ip) >= n.cidr {
		if n.peer != nil {
			peer = n.peer
		}
		// IP: 192.168.1.100 (ipLen = 4 bytes).
		// Node with /24: index = 3 (24/8 = 3).
		// We still need to check bit 24-31, so we continue.
		// Node with /32: index = 4 (32/8 = 4).
		// Since index == ipLen (4 == 4), we break.
		// There cannot be any child nodes because:
		// 	You can't have a more specific route than a host route.
		// 	There are no bits left to examine - we've used all 32/128 bits.
		// Without this check, the code would try to compute:
		// n.childIndex(ip) - this would index beyond the IP slice!
		// For a /32 IPv4 route:
		// 	n.index = 4
		// 	But valid indices for ip are only 0-3.
		//	This would cause an index out of bounds panic.
		if n.index == ipLen {
			break
		}
		n = n.children[n.childIndex(ip)]
	}
	return peer
}

type Router struct {
	IPv4 *node
	IPv6 *node
	mu   sync.RWMutex
}

func (r *Router) Insert(prefix netip.Prefix, peer *Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// `parent.childIndex == 2` signifies the root of the trie
	if prefix.Addr().Is4() {
		ip := prefix.Addr().As4()
		parent{&r.IPv4, 2}.insert(ip[:], uint8(prefix.Bits()), peer)
	} else if prefix.Addr().Is6() {
		ip := prefix.Addr().As16()
		parent{&r.IPv6, 2}.insert(ip[:], uint8(prefix.Bits()), peer)
	} else {
		panic(errors.New("inserting unknown address type"))
	}
}

func (r *Router) Find(ip []byte) *Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	switch len(ip) {
	case net.IPv4len:
		return r.IPv4.find(ip)
	case net.IPv6len:
		return r.IPv6.find(ip)
	default:
		panic(errors.New("unknown address type"))
	}
}

func (r *Router) Remove(prefix netip.Prefix, peer *Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n *node
	var exact bool
	if prefix.Addr().Is4() {
		ip := prefix.Addr().As4()
		n, exact = r.IPv4.nodePlacement(ip[:], uint8(prefix.Bits()))
	} else if prefix.Addr().Is6() {
		ip := prefix.Addr().As16()
		n, exact = r.IPv6.nodePlacement(ip[:], uint8(prefix.Bits()))
	} else {
		panic(errors.New("removing unknown address type"))
	}
	if n == nil || !exact || peer != n.peer {
		return
	}
	n.remove()
}

// RemoveByPeer removes all peer's nodes.
func (r *Router) RemoveByPeer(peer *Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var next *list.Element
	// Initialization (elem := peer.nodes.Front()) – evaluated once before
	// the loop begins. It sets elem to the first element of the list.
	// Condition (elem != nil) – evaluated before each iteration.
	// If true, the loop body executes; if false, the loop terminates.
	// Post statement (elem = next) – evaluated after each iteration’s
	// body (i.e., after the remove() call). It advances elem to the
	// element stored in next, which was recorded earlier inside the
	// loop via next = elem.Next().
	for elem := peer.nodes.Front(); elem != nil; elem = next {
		// Save the next element, because the current element's
		// pointers (elem.next and elem.prev) are zeroed out on removal.
		next = elem.Next()
		elem.Value.(*node).remove()
	}
}

// PeerNodes provides a peer's nodes iterator.
func (r *Router) PeerNodes(
	peer *Peer,
	yield func(prefix netip.Prefix) bool,
) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for elem := peer.nodes.Front(); elem != nil; elem = elem.Next() {
		n := elem.Value.(*node)
		addr, _ := netip.AddrFromSlice(n.addr)
		prefix := netip.PrefixFrom(addr, int(n.cidr))
		if !yield(prefix) {
			return
		}
	}
}
