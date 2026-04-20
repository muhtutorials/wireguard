package tun

import (
	"encoding/binary"
	"math/bits"
)

func checksumNoFold(b []byte, initial uint64) uint64 {
	// Big-Endian (network order):
	// Number: 0x12345678
	// Memory: [0x12] [0x34] [0x56] [0x78]
	//          ^^^^^  ^^^^   ^^^^   ^^^^
	//          most    ...    ...   least
	//       significant          significant
	//
	// Little-Endian (x86, ARM, most PCs):
	// Number: 0x12345678
	// Memory: [0x78] [0x56] [0x34] [0x12]
	//          ^^^^   ^^^^   ^^^^   ^^^^^
	//          least   ...    ...   most
	//       significant          significant
	//
	// `initial` is the starting checksum value.
	// The reason for converting `initial` (a uint64) into
	// []byte and then back into uint64 is to swap endianness
	// from native endianness to big endian.
	// The function checksumNoFold processes data using native
	// endian (for performance on the host CPU), but the
	// checksum algorithm itself requires values to be treated
	// in big-endian order (network byte order).
	// `initial` may have been computed in native endian
	// order from previous calls.
	// We convert to bytes using native endian:
	// 	binary.NativeEndian.PutUint64(tmp, initial)
	// Read back as big endian: binary.BigEndian.Uint64(tmp).
	// This effectively performs an endianness conversion:
	// 	If native = little endian (x86, ARM), the byte order gets reversed.
	// 	If native = big endian, it's a no-op.
	tmp := make([]byte, 8)
	binary.NativeEndian.PutUint64(tmp, initial)
	ac := binary.BigEndian.Uint64(tmp)
	// `0` or `1`
	var carry uint64
	for len(b) >= 128 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[8:16]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[16:24]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[24:32]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[32:40]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[40:48]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[48:56]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[56:64]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[64:72]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[72:80]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[80:88]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[88:96]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[96:104]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[104:112]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[112:120]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[120:128]), carry)
		ac += carry
		b = b[128:]
	}
	if len(b) >= 64 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[8:16]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[16:24]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[24:32]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[32:40]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[40:48]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[48:56]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[56:64]), carry)
		ac += carry
		b = b[64:]
	}
	if len(b) >= 32 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[8:16]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[16:24]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[24:32]), carry)
		ac += carry
		b = b[32:]
	}
	if len(b) >= 16 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[8:16]), carry)
		ac += carry
		b = b[16:]
	}
	if len(b) >= 8 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac += carry
		b = b[8:]
	}
	if len(b) >= 4 {
		ac, carry = bits.Add64(ac, uint64(binary.NativeEndian.Uint32(b[:4])), 0)
		ac += carry
		b = b[4:]
	}
	if len(b) >= 2 {
		ac, carry = bits.Add64(ac, uint64(binary.NativeEndian.Uint16(b[:2])), 0)
		ac += carry
		b = b[2:]
	}
	if len(b) == 1 {
		// Convert a single remaining byte into a 16-bit value for
		// checksum calculation by zero-padding the high byte.
		// The checksum algorithm operates on 16-bit words (2 bytes at a time).
		// When an odd number of bytes remains (exactly 1 byte left),
		// it must be padded to 16 bits.
		tmp := binary.NativeEndian.Uint16([]byte{b[0], 0})
		ac, carry = bits.Add64(ac, uint64(tmp), 0)
		ac += carry
	}
	binary.NativeEndian.PutUint64(tmp, ac)
	return binary.BigEndian.Uint64(tmp)
}

// pseudoHeaderChecksumNoFold calculates IP header checksum.
// It's called "pseudo" because not all header fields are
// included in the calculation, only 4: source address,
// destination address, protocol (TCP/UDP) and total length
// (TCP/UDP packet length).
func pseudoHeaderChecksumNoFold(
	srcAddr,
	dstAddr []byte,
	protocol uint8,
	totalLen uint16,
) uint64 {
	sum := checksumNoFold(srcAddr, 0)
	sum = checksumNoFold(dstAddr, sum)
	// In IP pseudo-headers for TCP/UDP checksum calculation
	// (per RFC 768 for UDP and RFC 793 for TCP), the protocol
	// field is one byte (e.g., 6 for TCP, 17 for UDP).
	// However, the checksum algorithm operates on 16-bit
	// words (two bytes at a time). When the protocol is promoted
	// to a 16-bit value for checksum calculation:
	//  - High byte (bits 15–8): 0
	//  - Low byte (bits 7–0): protocol number
	// TODO: The order differs from the one in `checksumNoFold`:
	// 	binary.NativeEndian.Uint16([]byte{b[0], 0}).
	// Not sure why.
	sum = checksumNoFold([]byte{0, protocol}, sum)
	tmp := make([]byte, 2)
	// convert uint16 to []byte
	binary.BigEndian.PutUint16(tmp, totalLen)
	return checksumNoFold(tmp, sum)
}

func checksum(b []byte, initial uint64) uint16 {
	ac := checksumNoFold(b, initial)
	// Reduce a 64-bit accumulated sum down to a 16-bit final
	// checksum as required by IP, TCP, and UDP protocols.
	// The folding process repeatedly:
	// 1. Shift right by 16 bits (ac >> 16) — take the "carry" bits above 16 bits.
	// 2. Mask to lower 16 bits (ac & 0xffff) — keep the low 16 bits.
	// 3. Add them together.
	// Four iterations guarantee all high bits are folded in,
	// even for the maximum possible sum.
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	return uint16(ac)
}
