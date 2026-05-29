package device

import (
	"net"
	"time"
)

// specification constants
const (
	// rekey is a new handshake initiation to derive fresh encryption keys
	RekeyAfterMessages  = (1 << 60)
	RejectAfterMessages = (1 << 64) - (1 << 13) - 1
	RekeyAfterTime      = time.Second * 120
	RekeyAttemptTime    = time.Second * 90
	// how long to wait for a handshake response before retrying
	RekeyTimeout         = time.Second * 5
	MaxHandshakeAttempts = uint32(RekeyAttemptTime / RekeyTimeout)
	// If many peers experience timeout simultaneously
	// (e.g., network glitch), without jitter they'd all
	// retry at the exact same moment, causing a traffic spike.
	// Adding random jitter spreads out the retransmissions.
	RekeyTimeoutJitterMaxMs = 334
	// maximum lifetime of a keypair from creation to deletion
	RejectAfterTime = time.Second * 180
	// KeepaliveTimeout controls how often "keepalive"
	// packets are sent to maintain a connection when
	// there's no regular data traffic.
	KeepaliveTimeout = time.Second * 10
	// how long cookie is valid
	CookieRefreshTime      = time.Second * 120
	HandshakeInitationRate = time.Second / 50
	// 16 bytes (128 bits) is a fundamental alignment size in modern cryptography:
	// - Most symmetric encryption algorithms work with 16-byte blocks.
	// - It's a power of 2 (2^4), which makes bitwise operations efficient.
	// - Hardware acceleration (AES-NI, etc.) often operates on 16-byte chunks.
	// - 16-byte alignment matches CPU cache line boundaries on many architectures.
	// - All packets (except handshakes) are padded to multiples of 16 bytes,
	//   which makes packet sizes less distinctive and makes harder to identify
	//   packet types by length.
	PaddingMultiple = 16
)

const (
	// minimum size of transport message (keepalive,
	// which is equal MessageTransportSize)
	MinMessageSize = MessageKeepaliveSize
	// maximum size of transport message (largest possible UDP datagram)
	MaxMessageSize = (1 << 16) - 1
	// maximum size of transport message content
	MaxContentSize = MaxMessageSize - MessageTransportSize
)

// implementation constants
const (
	// how long the device remains under load after detected
	UnderLoadAfterTime = time.Second
	// maximum number of configured peers
	MaxPeers = 1 << 16
)

// offsets of IPv4 packet fields
const (
	IPv4offsetTotalLen = 2
	IPv4offsetSrcAddr  = 12
	IPv4offsetDstAddr  = IPv4offsetSrcAddr + net.IPv4len
)

// offsets of IPv6 packet fields
const (
	IPv6offsetPayloadLen = 4
	IPv6offsetSrcAddr    = 8
	IPv6offsetDstAddr    = IPv6offsetSrcAddr + net.IPv6len
)
