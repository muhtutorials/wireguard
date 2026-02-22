package device

import "sync/atomic"

type Peer struct {
	device                      *Device
	handshake                   Handshake
	keypairs                    Keypairs
	timers                      timers
	isRunning                   atomic.Bool
	lastHandshake               atomic.Int64 // nano seconds since epoch
	persistentKeepaliveInterval atomic.Uint32
}

type timers struct {
	newHandshake            *Timer
	retransmitHandshake     *Timer
	sendKeepalive           *Timer
	persistentKeepalive     *Timer
	zeroKeyMaterial         *Timer
	handshakeAttempts       atomic.Uint32
	sentLastMinuteHandshake atomic.Bool
	needAnotherKeepalive    atomic.Bool
}
