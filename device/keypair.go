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
 * we plan to resolve this issue whenever Go allows us to do so.
 */

type Keypair struct {
	// keeps track of MessageTransport.Counter field
	sendNonce atomic.Uint64
	// encrypts outgoing packets
	encrypt cipher.AEAD
	// decrypts incoming packets
	decrypt cipher.AEAD
	// Random number assigned to a received handshake.
	// Used for session retrieval.
	localIndex uint32
	// sender from handshake initiation
	remoteIndex uint32
	// indicates if device is handshake initiator
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
		d.sessions.Delete(key.localIndex)
	}
}
