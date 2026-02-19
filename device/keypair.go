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
	replayFilter replay.Filter
	isInitiator  bool
	created      time.Time
	localIndex   uint32
	remoteIndex  uint32
}

type Keypairs struct {
	sync.RWMutex
	current  *Keypair
	previous *Keypair
	next     atomic.Pointer[Keypair]
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
