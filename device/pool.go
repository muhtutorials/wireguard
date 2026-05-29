package device

import "sync"

// `0` allows for infinite memory growth
const MaxPoolItems = 0

type WaitPool struct {
	pool sync.Pool
	cond sync.Cond
	mu   sync.Mutex
	// how many items are taken from the pool
	count uint32
	// max number of items allowed to be taken from the pool
	max uint32
}

func NewWaitPool(max uint32, new func() any) *WaitPool {
	p := &WaitPool{pool: sync.Pool{New: new}, max: max}
	p.cond = sync.Cond{L: &p.mu}
	return p
}

func (p *WaitPool) Get() any {
	if p.max != 0 {
		p.mu.Lock()
		for p.count >= p.max {
			p.cond.Wait()
		}
		p.count++
		p.mu.Unlock()
	}
	return p.pool.Get()
}

func (p *WaitPool) Put(val any) {
	p.pool.Put(val)
	if p.max == 0 {
		return
	}
	p.mu.Lock()
	p.count--
	p.cond.Signal()
	p.mu.Unlock()
}

func (d *Device) InitPools() {
	d.pools.quOutItemsWithLock = NewWaitPool(MaxPoolItems, func() any {
		return &QuOutItemsWithLock{
			items: make([]*QuOutItem, 0, d.BatchSize()),
		}
	})
	d.pools.quInItemsWithLock = NewWaitPool(MaxPoolItems, func() any {
		return &QuInItemsWithLock{
			items: make([]*QuInItem, 0, d.BatchSize()),
		}
	})
	d.pools.quOutItems = NewWaitPool(MaxPoolItems, func() any {
		return new(QuOutItem)
	})
	d.pools.quInItems = NewWaitPool(MaxPoolItems, func() any {
		return new(QuInItem)
	})
	d.pools.messageBufs = NewWaitPool(MaxPoolItems, func() any {
		return new([MaxMessageSize]byte)
	})
}

func (d *Device) GetQuOutItemsWithLock() *QuOutItemsWithLock {
	items := d.pools.quOutItemsWithLock.Get().(*QuOutItemsWithLock)
	// lock is not released in RoutineSendToPeer, so we just
	// reinitialize the mutex when we get the items again
	items.Mutex = sync.Mutex{}
	return items
}

func (d *Device) PutQuOutItemsWithLock(q *QuOutItemsWithLock) {
	for i := range q.items {
		q.items[i] = nil
	}
	q.items = q.items[:0]
	d.pools.quOutItemsWithLock.Put(q)
}

func (d *Device) GetQuInItemsWithLock() *QuInItemsWithLock {
	items := d.pools.quInItemsWithLock.Get().(*QuInItemsWithLock)
	items.Mutex = sync.Mutex{}
	return items
}

func (d *Device) PutQuInItemsWithLock(q *QuInItemsWithLock) {
	for i := range q.items {
		q.items[i] = nil
	}
	q.items = q.items[:0]
	d.pools.quInItemsWithLock.Put(q)
}

func (d *Device) GetQuOutItem() *QuOutItem {
	return d.pools.quOutItems.Get().(*QuOutItem)
}

func (d *Device) PutQuOutItem(item *QuOutItem) {
	item.zeroOutPointers()
	d.pools.quOutItems.Put(item)
}

func (d *Device) GetQuInItem() *QuInItem {
	return d.pools.quInItems.Get().(*QuInItem)
}

func (d *Device) PutQuInItem(item *QuInItem) {
	item.zeroOutPointers()
	d.pools.quInItems.Put(item)
}

func (d *Device) GetMessageBuf() *[MaxMessageSize]byte {
	return d.pools.messageBufs.Get().(*[MaxMessageSize]byte)
}

func (d *Device) PutMessageBuf(msg *[MaxMessageSize]byte) {
	d.pools.messageBufs.Put(msg)
}

func (d *Device) PutQuOutItems(q *QuOutItemsWithLock) {
	for _, item := range q.items {
		d.PutMessageBuf(item.buf)
		d.PutQuOutItem(item)
	}
	d.PutQuOutItemsWithLock(q)
}

func (d *Device) PutQuInItems(q *QuInItemsWithLock) {
	for _, item := range q.items {
		d.PutMessageBuf(item.buf)
		d.PutQuInItem(item)
	}
	d.PutQuInItemsWithLock(q)
}
