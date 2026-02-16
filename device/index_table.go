package device

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
)

type Index struct {
	peer      *Peer
	handshake *Handshake
	keypair   *Keypair
}

type IndexTable struct {
	table map[uint32]Index
	mu    sync.RWMutex
}

func (t *IndexTable) Init() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.table = make(map[uint32]Index)
}

func (t *IndexTable) Get(id uint32) Index {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.table[id]
}

func (t *IndexTable) Delete(id uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.table, id)
}

func (t *IndexTable) SwapIndexForKeypair(index uint32, keypair *Keypair) {
	t.mu.Lock()
	defer t.mu.Unlock()
	val, ok := t.table[index]
	if !ok {
		return
	}
	t.table[index] = Index{
		peer:    val.peer,
		keypair: keypair,
	}
}

func (t *IndexTable) NewIndexForHandshake(peer *Peer, handshake *Handshake) (uint32, error) {
	for {
		index, err := randUint32()
		if err != nil {
			return index, err
		}
		// The two-check pattern (first with RLock, then with Lock) is
		// an optimization technique called double-checked locking.
		// First check uses RLock to avoid the expensive exclusive Lock.
		t.mu.RLock()
		_, ok := t.table[index]
		t.mu.RUnlock()
		if ok {
			continue
		}
		// Second check uses Lock because another goroutine might have
		// inserted between the first check and this lock.
		t.mu.Lock()
		_, ok = t.table[index]
		if ok {
			t.mu.Unlock()
			continue
		}
		t.table[index] = Index{
			peer:      peer,
			handshake: handshake,
		}
		t.mu.Unlock()
		return index, nil
	}
}

func randUint32() (uint32, error) {
	var buf [4]byte
	_, err := rand.Read(buf[:])
	// Arbitrary endianness; both are intrinsified by the Go compiler.
	return binary.LittleEndian.Uint32(buf[:]), err
}
