package device

import (
	"runtime"
	"sync"

	"github.com/muhtutorials/wireguard/conn"
)

const (
	QuSize          = conn.BatchSize
	QuOutSize       = 1024
	QuInSize        = 1024
	QuHandshakeSize = 1024
	// largest possible UDP datagram
	MaxSegmentSize = (1 << 16) - 1
	// disable and allow for infinite memory growth
	PreallocatedBufsPerPool = 0
)

// quOut is a channel of QuOutItems awaiting encryption.
// quOut is ref-counted using its wg field.
// quOut created with newQuOut has one reference.
// Every additional writer must call wg.Add(1).
// Every completed writer must call wg.Done().
// When no further writers will be added,
// call wg.Done() to remove the initial reference.
// When the ref-count hits 0, the queue's channel is closed.
type quOut struct {
	c  chan *QuOutItemsSynced
	wg sync.WaitGroup
}

func newQuOut() *quOut {
	q := &quOut{
		c: make(chan *QuOutItemsSynced, QuOutSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

// QuIn is similar to quOut. See above.
type quIn struct {
	c  chan *QuInItemsSynced
	wg sync.WaitGroup
}

func newQuIn() *quIn {
	q := &quIn{
		c: make(chan *QuInItemsSynced, QuInSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

// quHandshake is similar to quOut. See above.
type quHandshake struct {
	c  chan QuHandshake
	wg sync.WaitGroup
}

func newQuHandshake() *quHandshake {
	q := &quHandshake{
		c: make(chan QuHandshake, QuHandshakeSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

type quOutFlush struct {
	c chan *QuOutItemsSynced
}

// newQuOutFlush returns a channel that will be flushed when it gets GC'd.
// It is useful in cases in which is it hard to manage the lifetime of the channel.
// The returned channel must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil values.
// All sends to the channel must be best-effort, because there may be no receivers.
func newQuOutFlush(d *Device) *quOutFlush {
	q := &quOutFlush{
		c: make(chan *QuOutItemsSynced, QuOutSize),
	}
	// SetFinalizer is analagous to drop method in Rust
	runtime.SetFinalizer(q, d.flushQuOut)
	return q
}

func (d *Device) flushQuOut(q *quOutFlush) {
	for {
		select {
		case quOutItems := <-q.c:
			quOutItems.Lock()
			for _, item := range quOutItems.items {
				d.PutMsgBuf(item.buf)
				d.PutOutItem(item)
			}
			d.putQuOutItems(quOutItems)
		default:
			return
		}
	}
}

type quInFlush struct {
	c chan *QuInItemsSynced
}

// newQuInFlush returns a channel that will be flushed when it gets GC'd.
// It is useful in cases in which is it hard to manage the lifetime of the channel.
// The returned channel must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil values.
func newQuInFlush(device *Device) *quInFlush {
	q := &quInFlush{
		c: make(chan *QuInItemsSynced, QuInSize),
	}
	runtime.SetFinalizer(q, device.flushQuIn)
	return q
}

func (d *Device) flushQuIn(q *quInFlush) {
	for {
		select {
		case quInItems := <-q.c:
			quInItems.Lock()
			for _, item := range quInItems.items {
				d.PutMsgBuf(item.buf)
				d.PutInItem(item)
			}
			d.PutQuInItems(quInItems)
		default:
			return
		}
	}
}
