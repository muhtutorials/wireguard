package device

import (
	"crypto/cipher"
	"sync"
	"sync/atomic"
	"time"

	"github.com/muhtutorials/wireguard/replay"
)

/* Due to limitations in Go and /x/crypto there is currently
 * no way to ensure that key material is securely erased in memory.
 *
 * Since this may harm the forward secrecy property,
 * we plan to resolve this issue; whenever Go allows us to do so.
 */

type Keypair struct {
	sendNonce    atomic.Uint64
	send         cipher.AEAD
	receive      cipher.AEAD
	localIndex   uint32
	remoteIndex  uint32
	isInitiator  bool
	replayFilter replay.Filter
	createdAt    time.Time
}

type Keypairs struct {
	// sync.RWMutex protects the relationship between current and
	// previous (you can't have both change independently), while
	// next is an independent value that can be set atomically
	// without affecting the current/previous relationship.
	//
	// currently used keypair
	current *Keypair
	// previous keypair (allows for delayed packets)
	previous *Keypair
	// next keypair (used during handshake)
	next atomic.Pointer[Keypair]
	sync.RWMutex
}

func (k *Keypairs) Current() *Keypair {
	k.RLock()
	defer k.RUnlock()
	return k.current
}

func (d *Device) DeleteKeypair(key *Keypair) {
	if key != nil {
		d.indexTable.Delete(key.localIndex)
	}
}
