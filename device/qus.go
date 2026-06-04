package device

import (
	"runtime"
	"sync"

	"github.com/muhtutorials/wireguard/conn"
)

const (
	QuStagedSize    = conn.BatchSize
	QuHandshakeSize = 1024
	QuOutSize       = 1024
	QuInSize        = 1024
)

// qu is a channel of items awaiting encryption or decryption.
// qu is ref-counted using its `wg` field.
// qu created with newQu has one reference.
// Every additional writer must call wg.Add(1).
// Every completed writer must call wg.Done().
// When no further writers will be added,
// call wg.Done() to remove the initial reference.
// When the ref-count hits 0, the queue's channel is closed.
type qu[T any] struct {
	c  chan T
	wg sync.WaitGroup
}

func newQu[T any](size int) *qu[T] {
	q := &qu[T]{
		c: make(chan T, size),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

type quOutFlush struct {
	c chan *QuOutItemsWithLock
}

// newQuOutFlush returns a channel that will be flushed when
// it gets GC'd. It is useful in cases in which is it hard
// to manage the lifetime of the channel. The returned channel
// must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil value.
func newQuOutFlush(d *Device) *quOutFlush {
	q := &quOutFlush{
		c: make(chan *QuOutItemsWithLock, QuOutSize),
	}
	// NOTE: SetFinalizer is analogous to drop method in Rust
	runtime.SetFinalizer(q, d.flushQuOut)
	return q
}

func (d *Device) flushQuOut(q *quOutFlush) {
	for {
		select {
		case items := <-q.c:
			items.Lock()
			d.PutQuOutItems(items)
		default:
			return
		}
	}
}

type quInFlush struct {
	c chan *QuInItemsWithLock
}

// newQuInFlush returns a channel that will be flushed when
// it gets GC'd. It is useful in cases in which is it hard
// to manage the lifetime of the channel. The returned channel
// must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil value.
func newQuInFlush(device *Device) *quInFlush {
	q := &quInFlush{
		c: make(chan *QuInItemsWithLock, QuInSize),
	}
	runtime.SetFinalizer(q, device.flushQuIn)
	return q
}

func (d *Device) flushQuIn(q *quInFlush) {
	for {
		select {
		case items := <-q.c:
			items.Lock()
			d.PutQuInItems(items)
		default:
			return
		}
	}
}
