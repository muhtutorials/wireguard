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

// quOut is a channel of QuOutElems awaiting encryption.
// quOut is ref-counted using its wg field.
// quOut created with newQuOut has one reference.
// Every additional writer must call wg.Add(1).
// Every completed writer must call wg.Done().
// When no further writers will be added,
// call wg.Done to remove the initial reference.
// When the refcount hits 0, the queue's channel is closed.
type quOut struct {
	c  chan *QuOutElems
	wg sync.WaitGroup
}

func newQuOut() *quOut {
	q := &quOut{
		c: make(chan *QuOutElems, QuOutSize),
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
	c  chan *QuInElems
	wg sync.WaitGroup
}

func newQuIn() *quIn {
	q := &quIn{
		c: make(chan *QuInElems, QuInSize),
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
	c  chan QuHandshakeElem
	wg sync.WaitGroup
}

func newQuHandshake() *quHandshake {
	q := &quHandshake{
		c: make(chan QuHandshakeElem, QuHandshakeSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

type quOutFlush struct {
	c chan *QuOutElems
}

// newQuOutFlush returns a channel that will be flushed when it gets GC'd.
// It is useful in cases in which is it hard to manage the lifetime of the channel.
// The returned channel must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil values.
// All sends to the channel must be best-effort, because there may be no receivers.
func newQuOutFlush(d *Device) *quOutFlush {
	q := &quOutFlush{
		c: make(chan *QuOutElems, QuOutSize),
	}
	// SetFinalizer is analagous to drop method in Rust
	runtime.SetFinalizer(q, d.flushQuOut)
	return q
}

func (d *Device) flushQuOut(q *quOutFlush) {
	for {
		select {
		case quOutElems := <-q.c:
			quOutElems.Lock()
			for _, elem := range quOutElems.elems {
				d.PutMsgBuf(elem.buf)
				d.PutOutElem(elem)
			}
			d.putQuOutElems(quOutElems)
		default:
			return
		}
	}
}

type quInFlush struct {
	c chan *QuInElems
}

// newQuInFlush returns a channel that will be flushed when it gets GC'd.
// It is useful in cases in which is it hard to manage the lifetime of the channel.
// The returned channel must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil values.
func newQuInFlush(device *Device) *quInFlush {
	q := &quInFlush{
		c: make(chan *QuInElems, QuInSize),
	}
	runtime.SetFinalizer(q, device.flushQuIn)
	return q
}

func (d *Device) flushInboundQueue(q *quInFlush) {
	for {
		select {
		case quInElems := <-q.c:
			quInElems.Lock()
			for _, elem := range quInElems.elems {
				d.PutMsgBuf(elem.buf)
				d.PutInElem(elem)
			}
			d.PutQuInElems(quInElems)
		default:
			return
		}
	}
}
