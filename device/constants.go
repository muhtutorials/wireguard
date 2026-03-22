package device

import (
	"net"
	"time"
)

/* Specification constants */
const (
	RekeyAfterMessages      = (1 << 60)
	RejectAfterMessages     = (1 << 64) - (1 << 13) - 1
	RekeyAfterTime          = time.Second * 120
	RekeyAttemptTime        = time.Second * 90
	RekeyTimeout            = time.Second * 5
	MaxTimerHandshakes      = 90 / 5 /* RekeyAttemptTime / RekeyTimeout */
	RekeyTimeoutJitterMaxMs = 334
	RejectAfterTime         = time.Second * 180
	KeepaliveTimeout        = time.Second * 10
	CookieRefreshTime       = time.Second * 120
	HandshakeInitationRate  = time.Second / 50
	// 16 bytes (128 bits) is a fundamental alignment size in modern cryptography:
	// - Most symmetric encryption algorithms work with 16-byte blocks.
	// - It's a power of 2 (2^4), which makes bitwise operations efficient.
	// - Hardware acceleration (AES-NI, etc.) often operates on 16-byte chunks.
	// - 16-byte alignment matches CPU cache line boundaries on many architectures.
	// - All packets (except handshakes) are padded to multiples of 16 bytes,
	//   which makes packet sizes less distinctive and harder to identify
	//   packet types by length.
	PaddingMultiple = 16
)

const (
	// minimum size of transport message (keepalive,
	// which is equal MessageTransportSize)
	MinMessageSize = MessageKeepaliveSize
	// maximum size of transport message (largest possible UDP datagram)
	MaxMessageSize = MaxSegmentSize
	// maximum size of transport message content
	MaxContentSize = MaxSegmentSize - MessageTransportSize
)

/* Implementation constants */
const (
	// how long the device remains under load after detected
	UnderLoadAfterTime = time.Second
	// maximum number of configured peers
	MaxPeers = 1 << 16
)

// offsets of fields inside IPv4 packet
const (
	IPv4offsetTotalLen = 2
	IPv4offsetSrc      = 12
	IPv4offsetDst      = IPv4offsetSrc + net.IPv4len
)

// offsets of fields inside IPv6 packet
const (
	IPv6offsetPayloadLen = 4
	IPv6offsetSrc        = 8
	IPv6offsetDst        = IPv6offsetSrc + net.IPv6len
)
