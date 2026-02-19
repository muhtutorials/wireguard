package device

import "sync"

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

func (d *Device) PopulatePools() {
	d.pools.outItemsSynced = NewWaitPool(PreallocatedBufsPerPool, func() any {
		items := make([]*QuOutItem, 0, d.BatchSize())
		return &QuOutItemsSynced{items: items}
	})
	d.pools.inItemsSynced = NewWaitPool(PreallocatedBufsPerPool, func() any {
		items := make([]*QuInItem, 0, d.BatchSize())
		return &QuInItemsSynced{items: items}
	})
	d.pools.outItems = NewWaitPool(PreallocatedBufsPerPool, func() any {
		return new(QuOutItem)
	})
	d.pools.inItems = NewWaitPool(PreallocatedBufsPerPool, func() any {
		return new(QuInItem)
	})
	d.pools.msgBufs = NewWaitPool(PreallocatedBufsPerPool, func() any {
		return new([MaxMessageSize]byte)
	})
}

func (d *Device) GetOutItemsSynced() *QuOutItemsSynced {
	items := d.pools.outItemsSynced.Get().(*QuOutItemsSynced)
	items.Mutex = sync.Mutex{}
	return items
}

func (d *Device) PutOutItemsSynced(q *QuOutItemsSynced) {
	for i := range q.items {
		q.items[i] = nil
	}
	q.items = q.items[:0]
	d.pools.outItemsSynced.Put(q)
}

func (d *Device) GetInItemsSynced() *QuInItemsSynced {
	items := d.pools.inItemsSynced.Get().(*QuInItemsSynced)
	items.Mutex = sync.Mutex{}
	return items
}

func (d *Device) PutInItemsSynced(q *QuInItemsSynced) {
	for i := range q.items {
		q.items[i] = nil
	}
	q.items = q.items[:0]
	d.pools.inItemsSynced.Put(q)
}

func (d *Device) GetOutItem() *QuOutItem {
	return d.pools.outItems.Get().(*QuOutItem)
}

func (d *Device) PutOutItem(item *QuOutItem) {
	item.zeroOutPointers()
	d.pools.outItems.Put(item)
}

func (d *Device) GetInItem() *QuInItem {
	return d.pools.inItems.Get().(*QuInItem)
}

func (d *Device) PutInboundElement(item *QuInItem) {
	item.zeroOutPointers()
	d.pools.inItems.Put(item)
}

func (d *Device) GetMsgBuf() *[MaxMessageSize]byte {
	return d.pools.msgBufs.Get().(*[MaxMessageSize]byte)
}

func (d *Device) PutMsgBuf(msg *[MaxMessageSize]byte) {
	d.pools.msgBufs.Put(msg)
}
