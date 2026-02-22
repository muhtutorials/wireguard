package device

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

// KDF related functions.
// HMAC-based Key Derivation Function (HKDF)
// https://tools.ietf.org/html/rfc5869

func HMAC1(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func HMAC2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func KDF1(t0 *[blake2s.Size]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func KDF3(t0, t1, t2 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	HMAC2(t2, prk[:], t1[:], []byte{0x3})
	setZero(prk[:])
}

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

// This function is not used as pervasively as it should
// because this is mostly impossible in Go at the moment
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

func newPrivateKey() (NoisePrivateKey, error) {
	var key NoisePrivateKey
	_, err := rand.Read(key[:])
	key.clamp()
	return key, err
}

func (priv *NoisePrivateKey) publicKey() NoisePublicKey {
	var pub NoisePublicKey
	privBytes := (*[NoisePrivateKeySize]byte)(priv)
	pubBytes := (*[NoisePublicKeySize]byte)(&pub)
	curve25519.ScalarBaseMult(pubBytes, privBytes)
	return pub
}

var errInvalidPublicKey = errors.New("invalid public key")

func (priv *NoisePrivateKey) sharedSecret(pub NoisePublicKey) ([NoisePublicKeySize]byte, error) {
	privBytes := (*[NoisePrivateKeySize]byte)(priv)[:]
	pubBytes := (*[NoisePublicKeySize]byte)(&pub)[:]
	shared, err := curve25519.X25519(privBytes, pubBytes)
	if err != nil {
		return [NoisePublicKeySize]byte(shared), err
	}
	return [NoisePublicKeySize]byte(shared), nil
}
