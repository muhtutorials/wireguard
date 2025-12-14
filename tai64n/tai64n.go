package tai64n

import (
	"bytes"
	"encoding/binary"
	"time"
)

const (
	TimestampSize = 12
	// By adding this large base value, WireGuard guarantees
	// that all TAI64N timestamps are positive 64-bit integers,
	// avoiding issues with signed/unsigned integer handling
	// across different systems.
	base         = uint64(0x400000000000000a)
	whitenerMask = uint32(0xffffff)
)

// First 8 bytes are seconds, last 4 bytes nanoseconds.
// Values encoded in big-endian order.
type Timestamp [TimestampSize]byte

func new(t time.Time) Timestamp {
	secs := base + uint64(t.Unix())
	// "&^" bit clear (AND NOT).
	// If the second operand has 1 in that position, sets result to 0.
	// If the second operand has 0 in that position, keeps the first operand's bit.
	//
	// 0xffffff = 16,777,215
	// Before whitening: 1ns precision (1,000,000,000 values/second).
	// After whitening: ~16.7ms precision (16,777,216 values/second).
	// Prevents timing attacks: high-precision timestamps can leak information about system state and help attackers correlate events.
	// Reduces fingerprinting: unique microsecond/nanosecond patterns can identify specific devices or handshakes.
	// Hides system characteristics: different systems have different clock behaviors at high precision.
	// Still sufficient for protocol: handshakes happen every few seconds, so millisecond precision is plenty.
	//
	// Clears lower 24 bits (3 bytes).
	nano := uint32(t.Nanosecond()) &^ whitenerMask
	var timestamp Timestamp
	binary.BigEndian.PutUint64(timestamp[:], secs)
	binary.BigEndian.PutUint32(timestamp[8:], nano)
	return timestamp
}

func Now() Timestamp {
	return new(time.Now())
}

// After calculates if t is later than other.
func (t Timestamp) After(other Timestamp) bool {
	return bytes.Compare(t[:], other[:]) > 0
}

func (t Timestamp) String() string {
	secs := int64(binary.BigEndian.Uint64(t[:8]) - base)
	nano := int64(binary.BigEndian.Uint32(t[8:12]))
	return time.Unix(secs, nano).String()
}
