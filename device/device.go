package device

import "sync"

type Device struct {
	// static identity
	keys       keys
	peers      peers
	indexTable IndexTable
	pools      pools
	log        *Logger
}

type keys struct {
	privateKey NoisePrivateKey
	publicKey  NoisePublicKey
	sync.RWMutex
}

type peers struct {
	p map[NoisePublicKey]*Peer
	sync.RWMutex
}

type pools struct {
	outItemsSynced *WaitPool
	inItemsSynced  *WaitPool
	outItems       *WaitPool
	inItems        *WaitPool
	msgBufs        *WaitPool
}

func (d *Device) LookupPeer(pk NoisePublicKey) *Peer {
	d.peers.RLock()
	defer d.peers.RUnlock()
	return d.peers.p[pk]
}
