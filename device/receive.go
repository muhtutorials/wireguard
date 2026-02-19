package device

import (
	"sync"

	"github.com/muhtutorials/wireguard/conn"
)

type QuHandshake struct {
	buf      *[MaxMessageSize]byte
	packet   []byte
	msgType  uint32
	endpoint conn.Endpoint
}

type QuInItem struct {
	buf      *[MaxMessageSize]byte
	packet   []byte
	counter  uint64
	keypair  *Keypair
	endpoint conn.Endpoint
}

type QuInItemsSynced struct {
	items []*QuInItem
	sync.Mutex
}

// zeroOutPointers zeroes out item fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (i *QuInItem) zeroOutPointers() {
	i.buf = nil
	i.packet = nil
	i.keypair = nil
	i.endpoint = nil
}
