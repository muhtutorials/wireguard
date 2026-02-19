package device

import "sync"

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The functions in this file occur (roughly) in the order in
 * which the packets are processed.
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)
 */

type QuOutItem struct {
	buf     *[MaxMessageSize]byte // slice holding the packet data
	packet  []byte                // slice of "buffer" (always!)
	nonce   uint64                // nonce for encryption
	keypair *Keypair              // keypair for encryption
	peer    *Peer                 // related peer
}

type QuOutItemsSynced struct {
	items []*QuOutItem
	sync.Mutex
}

func (d *Device) NewQuOutItem() *QuOutItem {
	item := d.GetOutItem()
	item.buf = d.GetMsgBuf()
	item.nonce = 0
	// keypair and peer were zeroed out (if necessary) by zeroOutPointers
	return item
}

// zeroOutPointers zeroes out item fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (i *QuOutItem) zeroOutPointers() {
	i.buf = nil
	i.packet = nil
	i.keypair = nil
	i.peer = nil
}
