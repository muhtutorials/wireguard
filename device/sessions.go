package device

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
)

type Session struct {
	peer      *Peer
	handshake *Handshake
	keypair   *Keypair
}

type SessionMap struct {
	m map[uint32]Session
	sync.RWMutex
}

func (s *SessionMap) Init() {
	s.Lock()
	defer s.Unlock()
	s.m = make(map[uint32]Session)
}

func (s *SessionMap) Get(index uint32) Session {
	s.Lock()
	defer s.Unlock()
	return s.m[index]
}

func (s *SessionMap) Delete(index uint32) {
	s.Lock()
	defer s.Unlock()
	delete(s.m, index)
}

func (s *SessionMap) NewIndex(peer *Peer, handshake *Handshake) (uint32, error) {
	for {
		index, err := randUint32()
		if err != nil {
			return index, err
		}
		// The two-check pattern (first with RLock, then with Lock)
		// is an optimization technique, where first check uses
		// RLock to avoid the expensive exclusive Lock.
		s.RLock()
		_, ok := s.m[index]
		s.RUnlock()
		if ok {
			continue
		}
		// Second check is made because another goroutine might have
		// inserted between the first check and this lock.
		s.Lock()
		_, ok = s.m[index]
		if ok {
			s.Unlock()
			continue
		}
		s.m[index] = Session{
			peer:      peer,
			handshake: handshake,
		}
		s.Unlock()
		return index, nil
	}
}

// AddKeypair adds keypair to a session and zeroes out its handshake.
func (s *SessionMap) AddKeypair(index uint32, keypair *Keypair) {
	s.Lock()
	defer s.Unlock()
	session, ok := s.m[index]
	if !ok {
		return
	}
	s.m[index] = Session{
		peer:    session.peer,
		keypair: keypair,
	}
}

func randUint32() (uint32, error) {
	var buf [4]byte
	_, err := rand.Read(buf[:])
	// Arbitrary endianness; both are intrinsified by the Go compiler.
	return binary.LittleEndian.Uint32(buf[:]), err
}
