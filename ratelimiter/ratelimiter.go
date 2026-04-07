package ratelimiter

import (
	"net/netip"
	"sync"
	"time"
)

const (
	// maximum sustained rate: 20 packets/second
	packetsPerSecond = 20
	// time cost per packet in nanoseconds:
	// 1000_000_000ns (1s) / 20 = 50_000_000ns (50ms)
	packetCost = 1000_000_000 / packetsPerSecond
	// burst capacity: 5 extra packets allowed
	packetsBurst = 5
	// maximum token bucket capacity in nanoseconds:
	// 50_000_000ns * 5 = 250_000_000ns (250ms)
	maxTokens = packetCost * packetsBurst
	// cleanup interval for old tokens
	cleanupInterval = time.Second
)

type RateLimiter struct {
	table map[netip.Addr]*Entry
	// returns the current local time
	now func() time.Time
	// Send on the channel to reset the ticker.
	// Close the channel to close ratelimiter.
	stopOrReset chan struct{}
	mu          sync.RWMutex
}

type Entry struct {
	tokens   int64
	lastTime time.Time
	mu       sync.Mutex
}

func (r *RateLimiter) Init() {
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
	// store in case Init is called again
	stopOrReset := r.stopOrReset
	// start cleanup routine
	go func() {
		ticker := time.NewTicker(time.Second)
		ticker.Stop()
		for {
			select {
			case _, ok := <-stopOrReset:
				if !ok {
					// channel is closed, stop rate limiter
					return
				}
				// received on channel, restart ticker
				ticker.Reset(time.Second)
			case <-ticker.C:
				if r.cleanup() {
					// table is empty, stop the ticker
					ticker.Stop()
				}
			}
		}
	}()
}

func (r *RateLimiter) cleanup() (empty bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range r.table {
		v.mu.Lock()
		if r.now().Sub(v.lastTime) > cleanupInterval {
			delete(r.table, k)
		}
		v.mu.Unlock()
	}
	// if table is empty return true
	return len(r.table) == 0
}

func (r *RateLimiter) Allow(ip netip.Addr) bool {
	// TODO: race condition
	// get or create entry
	r.mu.RLock()
	entry, ok := r.table[ip]
	r.mu.RUnlock()
	if !ok {
		// entry wasn't found so we make a new one
		entry = new(Entry)
		entry.tokens = maxTokens - packetCost
		entry.lastTime = r.now()
		r.mu.Lock()
		defer r.mu.Unlock()
		r.table[ip] = entry
		if len(r.table) == 1 {
			// start the ticker
			r.stopOrReset <- struct{}{}
		}
		return true
	}
	// entry was found so add accumulated tokens to it
	entry.mu.Lock()
	defer entry.mu.Unlock()
	now := r.now()
	// tokens = tokens + (now - lastTime)
	entry.tokens += now.Sub(entry.lastTime).Nanoseconds()
	entry.lastTime = now
	// cap tokens at maxTokens
	entry.tokens = min(entry.tokens, maxTokens)
	// subtract cost of packet
	if entry.tokens >= packetCost {
		entry.tokens -= packetCost
		return true
	}
	// not enough tokens
	return false
}

func (r *RateLimiter) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopOrReset != nil {
		close(r.stopOrReset)
	}
}
