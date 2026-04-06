// Package replay implements an efficient anti-replay algorithm as specified in RFC 6479.
package replay

const (
	// used for division by 64 to get block index
	blockBitShift = 6
	// Number of bits in a block. Must be a power of 2.
	nBits = 1 << blockBitShift // 1 << 6 = 64
	// Number of blocks in the ring buffer. Must be a power of 2.
	nBlocks    = 1 << 7                // 1 << 7 = 128
	bitMask    = nBits - 1             // 64 - 1 = 63 = 0b0011_1111
	blockMask  = nBlocks - 1           // 128 - 1 = 127 = 0b0111_1111
	windowSize = (nBlocks - 1) * nBits // (128 - 1) * 64 = 8128
)

type block uint64

// Filter rejects replayed messages by checking if message counter value is
// within the sliding window of previously received messages.
// The zero value for Filter is an empty Filter ready for use.
// Filters are unsafe for concurrent use.
type Filter struct {
	// highest value seen so far
	last uint64
	// Bit field ring buffer.
	// Each bit represents a counter value.
	ring [nBlocks]block // 128 x 64 = 8192
}

// Validate checks if the counter value should be accepted.
// Out of limit values (>= limit) are always rejected.
func (f *Filter) Validate(value, limit uint64) bool {
	// limit defines the maximum acceptable counter value.
	// Prevents value overflow attacks.
	if value >= limit {
		return false
	}
	// Divide by 64 to get the absolute block index
	// (not inside ring buffer) to calculate how many
	// blocks the window has moved.
	blockIndex := value >> blockBitShift
	if value > f.last {
		// move window forward
		currentIndex := f.last >> blockBitShift
		diff := blockIndex - currentIndex
		// cap diff at nBlocks, because if the window moves
		// forward by more than nBlocks, everything in the
		// ring buffer becomes stale and should be cleared.
		diff = min(diff, nBlocks)
		// clear the ring between `currentIndex` and `currentIndex+diff`
		for i := currentIndex + 1; i <= currentIndex+diff; i++ {
			// `i&blockMask` is modulo division of 127 by `i`
			// (masks out numbers exeeding 127)
			f.ring[i&blockMask] = 0
		}
		f.last = value
	} else if f.last-value > windowSize { // behind current window
		return false
	}
	// Mask out higher bits to prevent "index out of range" error,
	// because we have only 128 blocks.
	blockIndex &= blockMask
	// get bit index by masking out values higher than 6th bit,
	// because we have 64 bits in a block
	bitIndex := value & bitMask
	old := f.ring[blockIndex]
	new := old | 1<<bitIndex
	f.ring[blockIndex] = new
	return old != new
}

// Reset resets the filter to empty state.
func (f *Filter) Reset() {
	f.last = 0
	f.ring = [nBlocks]block{}
}
