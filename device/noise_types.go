package device

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

const (
	NoisePublicKeySize    = 32
	NoisePrivateKeySize   = 32
	NoisePresharedKeySize = 32
)

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
	NoisePresharedKey [NoisePresharedKeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes
)

func hexToBytes(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	if len(slice) != len(dst) {
		return errors.New("hex string does not fit the slice")
	}
	copy(dst, slice)
	return nil
}

// Curve25519 has specific mathematical requirements for private keys:
//
//	Security Requirements:
//		Clear lower 3 bits - Prevents small-subgroup attacks
//	 	(ensures the key is a multiple of the cofactor 8).
//		Clear highest bit - Ensures the key fits within the curve's prime field.
//		Set second-highest bit - Prevents timing attacks and ensures sufficient entropy.
//	The resulting key must be:
//		Between 2^251 and 2^252-1 (in a specific range).
//		A multiple of 8 (cofactor clearing).
//		Not all zeros or weak keys.
func (key *NoisePrivateKey) clamp() {
	// clears lower 3 bits (248 in binary: 11111000)
	key[0] &= 248
	// `& 127` clears the highest bit (127 in binary: 01111111)
	// `| 64` sets the second-highest bit to 1 (64 in binary: 01000000)
	key[31] = (key[31] & 127) | 64
}

func (key NoisePrivateKey) Equals(key2 NoisePrivateKey) bool {
	return subtle.ConstantTimeCompare(key[:], key2[:]) == 1
}

func (key NoisePrivateKey) IsZero() bool {
	var zero NoisePrivateKey
	return key.Equals(zero)
}

func (key *NoisePrivateKey) FromHex(src string) error {
	err := hexToBytes(key[:], src)
	key.clamp()
	return err
}

func (key *NoisePrivateKey) FromMaybeZeroHex(src string) error {
	err := hexToBytes(key[:], src)
	if key.IsZero() {
		return err
	}
	key.clamp()
	return err
}

func (key NoisePublicKey) Equals(key2 NoisePublicKey) bool {
	return subtle.ConstantTimeCompare(key[:], key2[:]) == 1
}

func (key NoisePublicKey) IsZero() bool {
	var zero NoisePublicKey
	return key.Equals(zero)
}

func (key *NoisePublicKey) FromHex(src string) error {
	return hexToBytes(key[:], src)
}

func (key *NoisePresharedKey) FromHex(src string) error {
	return hexToBytes(key[:], src)
}
