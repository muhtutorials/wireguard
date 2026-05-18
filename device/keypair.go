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
	// Currently used keypair. Can both encrypt and decrypt.
	current *Keypair
	// When a new keypair is derived after a handshake, current
	// keypair becomes previous keypair, which is used for
	// delayed packets. After yet another handshake previous
	// keypair is deleted and incoming packets associated with
	// this keypair are ignored.
	previous *Keypair
	// Next keypair. Not yet active,
	// but ready (responder's new key after handshake)
	next atomic.Pointer[Keypair]
	sync.RWMutex
}

func (k *Keypairs) Current() *Keypair {
	k.RLock()
	defer k.RUnlock()
	return k.current
}

// DeleteSession deletes session associated with keypair.
func (d *Device) DeleteSession(key *Keypair) {
	if key != nil {
		d.sessions.Delete(key.localIndex)
	}
}
