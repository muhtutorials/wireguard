package device

import (
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
	PaddingMultiple         = 16
)

const (
	// minimum size of transport message (keepalive)
	MinMessageSize = MessageKeepaliveSize
	// maximum size of transport message
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
