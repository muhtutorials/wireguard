package ratelimiter

import (
	"net/netip"
	"sync"
	"time"
)

const (
	// maximum sustained rate: 20 packets/second
	packetsPerSecond = 20
	// time cost per packet in nanoseconds: 50_000_000ns (50ms)
	// 1s = 1000_000_000ns
	packetCost = 1000_000_000 / packetsPerSecond
	// burst capacity: 5 extra packets allowed
	packetsBurst = 5
	// maximum token bucket capacity in nanoseconds: 250_000_000ns (250ms)
	maxTokens = packetCost * packetsBurst
	// cleanup interval for old tokens
	cleanupInterval = time.Second
)

type Ratelimiter struct {
	table       map[netip.Addr]*Entry
	now         func() time.Time // returns the current local time
	stopOrReset chan struct{}    // send to reset, close to stop
	mu          sync.RWMutex
}

type Entry struct {
	tokens   int64
	lastTime time.Time
	mu       sync.Mutex
}

func (r *Ratelimiter) Init() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.table = make(map[netip.Addr]*Entry)
	if r.now == nil {
		r.now = time.Now
	}
	// stop any ongoing cleanup routine
	if r.stopOrReset != nil {
		close(r.stopOrReset)
	}
	r.stopOrReset = make(chan struct{})
	stopOrReset := r.stopOrReset // store in case Init is called again
	// start cleanup routine
	go func() {
		ticker := time.NewTicker(time.Second)
		ticker.Stop()
		for {
			select {
			case _, ok := <-stopOrReset:
				ticker.Stop()
				if !ok {
					return
				}
				ticker = time.NewTicker(time.Second)
			case <-ticker.C:
				if r.cleanup() {
					ticker.Stop()
				}
			}
		}
	}()
}

func (r *Ratelimiter) cleanup() (empty bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range r.table {
		v.mu.Lock()
		if r.now().Sub(v.lastTime) > cleanupInterval {
			delete(r.table, k)
		}
		v.mu.Unlock()
	}
	return len(r.table) == 0
}

func (r *Ratelimiter) Allow(ip netip.Addr) bool {
	// lookup entry
	// TODO: race condition
	r.mu.RLock()
	entry, ok := r.table[ip]
	r.mu.RUnlock()
	// make new entry if not found
	if !ok {
		entry = new(Entry)
		entry.tokens = maxTokens - packetCost
		entry.lastTime = r.now()
		r.mu.Lock()
		r.table[ip] = entry
		if len(r.table) == 1 {
			// start the ticker
			r.stopOrReset <- struct{}{}
		}
		r.mu.Unlock()
		return true
	}
	// add tokens to entry
	entry.mu.Lock()
	now := r.now()
	entry.tokens += now.Sub(entry.lastTime).Nanoseconds()
	entry.lastTime = now
	if entry.tokens > maxTokens {
		entry.tokens = maxTokens
	}
	// subtract cost of packet
	if entry.tokens > packetCost {
		entry.tokens -= packetCost
		entry.mu.Unlock()
		return true
	}
	entry.mu.Unlock()
	return false
}

func (r *Ratelimiter) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopOrReset != nil {
		close(r.stopOrReset)
	}
}
