package device

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/muhtutorials/wireguard/tai64n"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	InitialChainKey = blake2s.Sum256([]byte(NoiseConstruction))
	mixHash(&InitialHash, &InitialChainKey, []byte(WGIdentifier))
}

type handshakeState int

const (
	handshakeZeroed handshakeState = iota
	handshakeInitiationCreated
	handshakeInitiationConsumed
	handshakeResponseCreated
	handshakeResponseConsumed
)

func (hs handshakeState) String() string {
	switch hs {
	case handshakeZeroed:
		return "handshakeZeroed"
	case handshakeInitiationCreated:
		return "handshakeInitiationCreated"
	case handshakeInitiationConsumed:
		return "handshakeInitiationConsumed"
	case handshakeResponseCreated:
		return "handshakeResponseCreated"
	case handshakeResponseConsumed:
		return "handshakeResponseConsumed"
	default:
		return fmt.Sprintf("Unknown handshake state: %d", int(hs))
	}
}

const (
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	WGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	WGLabelMAC1       = "mac1----"
	WGLabelCookie     = "cookie--"
)

const (
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4
)

const (
	// size of handshake initiation message
	MessageInitiationSize = 148
	// size of response message
	MessageResponseSize = 92
	// size of cookie reply message
	MessageCookieReplySize = 64
	// size of data preceding content in transport message
	MessageTransportHeaderSize = 16
	// size of empty transport
	MessageTransportSize = MessageTransportHeaderSize + chacha20poly1305.Overhead
	// size of keepalive
	MessageKeepaliveSize = MessageTransportSize
	// size of largest handshake related message
	MessageHandshakeSize = MessageInitiationSize
)

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

var errMessageLenMismatch = errors.New("message length mismatch")

var (
	InitialChainKey [blake2s.Size]byte
	InitialHash     [blake2s.Size]byte
	ZeroNonce       [chacha20poly1305.NonceSize]byte
)

// Type is an 8-bit field, followed by 3 nul bytes,
// by marshalling the messages in little-endian byteorder
// we can treat these as a 32-bit unsigned int (for now)

type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral NoisePublicKey
	Static    [NoisePublicKeySize + chacha20poly1305.Overhead]byte
	Timestamp [tai64n.TimestampSize + chacha20poly1305.Overhead]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

func (m *MessageInitiation) marshal(b []byte) error {
	if len(b) != MessageInitiationSize {
		return errMessageLenMismatch
	}
	binary.LittleEndian.PutUint32(b, m.Type)
	binary.LittleEndian.PutUint32(b[4:], m.Sender)
	copy(b[8:], m.Ephemeral[:])
	copy(b[8+len(m.Ephemeral):], m.Static[:])
	copy(b[8+len(m.Ephemeral)+len(m.Static):], m.Timestamp[:])
	copy(b[8+len(m.Ephemeral)+len(m.Static)+len(m.Timestamp):], m.MAC1[:])
	copy(b[8+len(m.Ephemeral)+len(m.Static)+len(m.Timestamp)+len(m.MAC1):], m.MAC2[:])
	return nil
}

func (m *MessageInitiation) unmarshal(b []byte) error {
	if len(b) != MessageInitiationSize {
		return errMessageLenMismatch
	}
	m.Type = binary.LittleEndian.Uint32(b)
	m.Sender = binary.LittleEndian.Uint32(b[4:])
	copy(m.Ephemeral[:], b[8:])
	copy(m.Static[:], b[8+len(m.Ephemeral):])
	copy(m.Timestamp[:], b[8+len(m.Ephemeral)+len(m.Static):])
	copy(m.MAC1[:], b[8+len(m.Ephemeral)+len(m.Static)+len(m.Timestamp):])
	copy(m.MAC2[:], b[8+len(m.Ephemeral)+len(m.Static)+len(m.Timestamp)+len(m.MAC1):])
	return nil
}

type MessageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral NoisePublicKey
	Empty     [chacha20poly1305.Overhead]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

func (m *MessageResponse) marshal(b []byte) error {
	if len(b) != MessageResponseSize {
		return errMessageLenMismatch
	}
	binary.LittleEndian.PutUint32(b, m.Type)
	binary.LittleEndian.PutUint32(b[4:], m.Sender)
	binary.LittleEndian.PutUint32(b[8:], m.Receiver)
	copy(b[12:], m.Ephemeral[:])
	copy(b[12+len(m.Ephemeral):], m.Empty[:])
	copy(b[12+len(m.Ephemeral)+len(m.Empty):], m.MAC1[:])
	copy(b[12+len(m.Ephemeral)+len(m.Empty)+len(m.MAC1):], m.MAC2[:])
	return nil
}

func (m *MessageResponse) unmarshal(b []byte) error {
	if len(b) != MessageResponseSize {
		return errMessageLenMismatch
	}
	m.Type = binary.LittleEndian.Uint32(b)
	m.Sender = binary.LittleEndian.Uint32(b[4:])
	m.Receiver = binary.LittleEndian.Uint32(b[8:])
	copy(m.Ephemeral[:], b[12:])
	copy(m.Empty[:], b[12+len(m.Ephemeral):])
	copy(m.MAC1[:], b[12+len(m.Ephemeral)+len(m.Empty):])
	copy(m.MAC2[:], b[12+len(m.Ephemeral)+len(m.Empty)+len(m.MAC1):])
	return nil
}

type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

type MessageCookieReply struct {
	Type     uint32
	Receiver uint32
	Nonce    [chacha20poly1305.NonceSizeX]byte
	Cookie   [blake2s.Size128 + chacha20poly1305.Overhead]byte
}

func (m *MessageCookieReply) marshal(b []byte) error {
	if len(b) != MessageCookieReplySize {
		return errMessageLenMismatch
	}
	binary.LittleEndian.PutUint32(b, m.Type)
	binary.LittleEndian.PutUint32(b[4:], m.Receiver)
	copy(b[8:], m.Nonce[:])
	copy(b[8+len(m.Nonce):], m.Cookie[:])
	return nil
}

func (m *MessageCookieReply) unmarshal(b []byte) error {
	if len(b) != MessageCookieReplySize {
		return errMessageLenMismatch
	}
	m.Type = binary.LittleEndian.Uint32(b)
	m.Receiver = binary.LittleEndian.Uint32(b[4:])
	copy(m.Nonce[:], b[8:])
	copy(m.Cookie[:], b[8+len(m.Nonce):])
	return nil
}

type Handshake struct {
	state                     handshakeState
	hash                      [blake2s.Size]byte       // hash value
	chainKey                  [blake2s.Size]byte       // chain key
	presharedKey              NoisePresharedKey        // psk
	localEphemeral            NoisePrivateKey          // ephemeral secret key
	localIndex                uint32                   // used to clear hash-table
	remoteIndex               uint32                   // index for sending
	remoteStatic              NoisePublicKey           // long term key
	remoteEphemeral           NoisePublicKey           // ephemeral public key
	precomputedSharedSecret   [NoisePublicKeySize]byte // precomputed shared secret
	lastTimestamp             tai64n.Timestamp
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time
	sync.RWMutex
}

func (h *Handshake) Clear() {
	setZero(h.hash[:])
	setZero(h.chainKey[:])
	setZero(h.localEphemeral[:])
	setZero(h.remoteEphemeral[:])
	h.state = handshakeZeroed
	h.localIndex = 0
}

func (h *Handshake) mixHash(data []byte) {
	mixHash(&h.hash, &h.hash, data)
}

func (h *Handshake) mixKey(data []byte) {
	mixKey(&h.chainKey, &h.chainKey, data)
}

func mixKey(dst, c *[blake2s.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}

func mixHash(dst, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func (d *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	d.keys.RLock()
	defer d.keys.RUnlock()
	hs := &peer.handshake
	hs.Lock()
	defer hs.Unlock()
	// create ephemeral key
	var err error
	hs.hash = InitialHash
	hs.chainKey = InitialChainKey
	hs.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	hs.mixHash(hs.remoteStatic[:])
	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: hs.localEphemeral.publicKey(),
	}
	hs.mixKey(msg.Ephemeral[:])
	hs.mixHash(msg.Ephemeral[:])
	// encrypt static key
	shared, err := hs.localEphemeral.sharedSecret(hs.remoteStatic)
	if err != nil {
		return nil, err
	}
	var key [chacha20poly1305.KeySize]byte
	KDF2(
		&hs.chainKey,
		&key,
		hs.chainKey[:],
		shared[:],
	)
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Static[:0], ZeroNonce[:], d.keys.publicKey[:], hs.hash[:])
	hs.mixHash(msg.Static[:])
	// encrypt timestamp
	if isZero(hs.precomputedSharedSecret[:]) {
		return nil, errInvalidPublicKey
	}
	KDF2(
		&hs.chainKey,
		&key,
		hs.chainKey[:],
		hs.precomputedSharedSecret[:],
	)
	timestamp := tai64n.Now()
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], hs.hash[:])
	// assign index
	d.indexTable.Delete(hs.localIndex)
	msg.Sender, err = d.indexTable.NewIndexForHandshake(peer, hs)
	if err != nil {
		return nil, err
	}
	hs.localIndex = msg.Sender
	hs.mixHash(msg.Timestamp[:])
	hs.state = handshakeInitiationCreated
	return &msg, nil
}

func (d *Device) ConsumeMessageInitiation(msg *MessageInitiation) *Peer {
	if msg.Type != MessageInitiationType {
		return nil
	}
	d.keys.RLock()
	defer d.keys.RUnlock()
	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)
	mixHash(&hash, &InitialHash, d.keys.publicKey[:])
	mixHash(&hash, &hash, msg.Ephemeral[:])
	mixKey(&chainKey, &InitialChainKey, msg.Ephemeral[:])
	// decrypt static key
	var peerPublicKey NoisePublicKey
	var key [chacha20poly1305.KeySize]byte
	shared, err := d.keys.privateKey.sharedSecret(msg.Ephemeral)
	if err != nil {
		return nil
	}
	KDF2(&chainKey, &key, chainKey[:], shared[:])
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(peerPublicKey[:0], ZeroNonce[:], msg.Static[:], hash[:])
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.Static[:])
	// lookup peer
	peer := d.LookupPeer(peerPublicKey)
	if peer == nil || !peer.isRunning.Load() {
		return nil
	}
	hs := &peer.handshake
	// verify identity
	var timestamp tai64n.Timestamp
	hs.RLock()
	if isZero(hs.precomputedSharedSecret[:]) {
		hs.RUnlock()
		return nil
	}
	KDF2(
		&chainKey,
		&key,
		chainKey[:],
		hs.precomputedSharedSecret[:],
	)
	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		hs.RUnlock()
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])
	// protect against replay and flood
	replay := !timestamp.After(hs.lastTimestamp)
	flood := time.Since(hs.lastInitiationConsumption) <= HandshakeInitationRate
	hs.RUnlock()
	if replay {
		d.log.Verbosef("%v - ConsumeMessageInitiation: handshake replay @ %v", peer, timestamp)
		return nil
	}
	if flood {
		d.log.Verbosef("%v - ConsumeMessageInitiation: handshake flood", peer)
		return nil
	}
	// update handshake state
	hs.Lock()
	hs.hash = hash
	hs.chainKey = chainKey
	hs.remoteIndex = msg.Sender
	hs.remoteEphemeral = msg.Ephemeral
	if timestamp.After(hs.lastTimestamp) {
		hs.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(hs.lastInitiationConsumption) {
		hs.lastInitiationConsumption = now
	}
	hs.state = handshakeInitiationConsumed
	hs.Unlock()
	setZero(hash[:])
	setZero(chainKey[:])
	return peer
}

func (d *Device) CreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	hs := &peer.handshake
	hs.Lock()
	defer hs.Unlock()
	if hs.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}
	// assign index
	var err error
	d.indexTable.Delete(hs.localIndex)
	hs.localIndex, err = d.indexTable.NewIndexForHandshake(peer, hs)
	if err != nil {
		return nil, err
	}
	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = hs.localIndex
	msg.Receiver = hs.remoteIndex
	// create ephemeral key
	hs.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = hs.localEphemeral.publicKey()
	hs.mixHash(msg.Ephemeral[:])
	hs.mixKey(msg.Ephemeral[:])
	shared, err := hs.localEphemeral.sharedSecret(hs.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	hs.mixKey(shared[:])
	shared, err = hs.localEphemeral.sharedSecret(hs.remoteStatic)
	if err != nil {
		return nil, err
	}
	hs.mixKey(shared[:])
	// add preshared key
	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte
	KDF3(
		&hs.chainKey,
		&tau,
		&key,
		hs.chainKey[:],
		hs.presharedKey[:],
	)
	hs.mixHash(tau[:])
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, hs.hash[:])
	hs.mixHash(msg.Empty[:])
	hs.state = handshakeResponseCreated
	return &msg, nil
}

func (d *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		return nil
	}
	// get handshake by receiver
	index := d.indexTable.Get(msg.Receiver)
	hs := index.handshake
	if hs == nil {
		return nil
	}
	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)
	ok := func() bool {
		// lock handshake state
		hs.RLock()
		defer hs.RUnlock()
		if hs.state != handshakeInitiationCreated {
			return false
		}
		// lock private key for reading
		d.keys.RLock()
		defer d.keys.RUnlock()
		// finish 3-way DH
		mixHash(&hash, &hs.hash, msg.Ephemeral[:])
		mixKey(&chainKey, &hs.chainKey, msg.Ephemeral[:])
		shared, err := hs.localEphemeral.sharedSecret(msg.Ephemeral)
		if err != nil {
			return false
		}
		mixKey(&chainKey, &chainKey, shared[:])
		setZero(shared[:])
		shared, err = d.keys.privateKey.sharedSecret(msg.Ephemeral)
		if err != nil {
			return false
		}
		mixKey(&chainKey, &chainKey, shared[:])
		setZero(shared[:])
		// add preshared key (psk)
		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		KDF3(
			&chainKey,
			&tau,
			&key,
			chainKey[:],
			hs.presharedKey[:],
		)
		mixHash(&hash, &hash, tau[:])
		// authenticate transcript
		aead, _ := chacha20poly1305.New(key[:])
		_, err = aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
		if err != nil {
			return false
		}
		mixHash(&hash, &hash, msg.Empty[:])
		return true
	}()
	if !ok {
		return nil
	}
	// update handshake state
	hs.Lock()
	hs.hash = hash
	hs.chainKey = chainKey
	hs.remoteIndex = msg.Sender
	hs.state = handshakeResponseConsumed
	hs.Unlock()
	setZero(hash[:])
	setZero(chainKey[:])
	return index.peer
}

// Derives a new keypair from the current handshake state.
func (peer *Peer) BeginSymmetricSession() error {
	d := peer.device
	hs := &peer.handshake
	hs.Lock()
	defer hs.Unlock()
	// derive keys
	var (
		isInitiator bool
		sendKey     [chacha20poly1305.KeySize]byte
		recvKey     [chacha20poly1305.KeySize]byte
	)
	if hs.state == handshakeResponseConsumed {
		KDF2(
			&sendKey,
			&recvKey,
			hs.chainKey[:],
			nil,
		)
		isInitiator = true
	} else if hs.state == handshakeResponseCreated {
		KDF2(
			&recvKey,
			&sendKey,
			hs.chainKey[:],
			nil,
		)
		isInitiator = false
	} else {
		return fmt.Errorf("invalid state for keypair derivation: %v", hs.state)
	}
	// zero handshake
	setZero(hs.chainKey[:])
	// Doesn't necessarily need to be zeroed.
	// Could be used for something interesting down the line.
	setZero(hs.hash[:])
	setZero(hs.localEphemeral[:])
	peer.handshake.state = handshakeZeroed
	// create AEAD instances
	var keypair *Keypair
	keypair.send, _ = chacha20poly1305.New(sendKey[:])
	keypair.receive, _ = chacha20poly1305.New(recvKey[:])
	setZero(sendKey[:])
	setZero(recvKey[:])
	keypair.created = time.Now()
	keypair.replayFilter.Reset()
	keypair.isInitiator = isInitiator
	keypair.localIndex = peer.handshake.localIndex
	keypair.remoteIndex = peer.handshake.remoteIndex
	// remap index
	d.indexTable.SwapIndexForKeypair(hs.localIndex, keypair)
	hs.localIndex = 0
	// rotate key pairs
	keypairs := &peer.keypairs
	keypairs.Lock()
	defer keypairs.Unlock()
	previous := keypairs.previous
	next := keypairs.next.Load()
	current := keypairs.current
	if isInitiator {
		if next != nil {
			keypairs.next.Store(nil)
			keypairs.previous = next
			d.DeleteKeypair(current)
		} else {
			keypairs.previous = current
		}
		d.DeleteKeypair(previous)
		keypairs.current = keypair
	} else {
		keypairs.next.Store(keypair)
		d.DeleteKeypair(next)
		keypairs.previous = nil
		d.DeleteKeypair(previous)
	}
	return nil
}

func (peer *Peer) ReceivedWithKeypair(receivedKeypair *Keypair) bool {
	kp := &peer.keypairs
	if kp.next.Load() != receivedKeypair {
		return false
	}
	kp.Lock()
	defer kp.Unlock()
	if kp.next.Load() != receivedKeypair {
		return false
	}
	old := kp.previous
	kp.previous = kp.current
	peer.device.DeleteKeypair(old)
	kp.current = kp.next.Load()
	kp.next.Store(nil)
	return true
}
