package device

import (
	"math/rand/v2"
	"sync"
	"time"
)

// Timer manages time-based aspects of the WireGuard protocol.
// Timer roughly copies the interface of the Linux kernel's struct timer_list.
type Timer struct {
	*time.Timer
	// tells if callback is scheduled to run
	isPending bool
	// prevents callback from running after timer is deleted
	runningMu sync.Mutex
	// protects timer API (Mod, Del, IsPending).
	modifyingMu sync.RWMutex // read Mutex is used by `IsPending` method
}

// NewTimer creates a timer that will execute expiration function (expFunc)
// after 1 hour, but immediately stops it. This creates a "stopped timer"
// that can be later reset and used.
func (peer *Peer) NewTimer(expFunc func(*Peer)) *Timer {
	t := new(Timer)
	t.Timer = time.AfterFunc(time.Hour, func() {
		t.runningMu.Lock()
		defer t.runningMu.Unlock()
		t.modifyingMu.Lock()
		if !t.isPending {
			t.modifyingMu.Unlock()
			return
		}
		t.isPending = false
		t.modifyingMu.Unlock()
		expFunc(peer)
	})
	t.Stop()
	return t
}

func (t *Timer) Mod(d time.Duration) {
	t.modifyingMu.Lock()
	defer t.modifyingMu.Unlock()
	t.isPending = true
	t.Reset(d)
}

func (t *Timer) Del() {
	t.modifyingMu.Lock()
	defer t.modifyingMu.Unlock()
	t.isPending = false
	t.Stop()
}

// DelSync ensures:
// No new callbacks will execute (isPending = false).
// Any currently running callback completes (runningMu.Lock()).
// Double-check after lock (in case callback modified state).
func (t *Timer) DelSync() {
	t.Del()            // mark not pending + Stop
	t.runningMu.Lock() // wait for any in-progress callback
	t.Del()            // mark not pending again (defensive)
	t.runningMu.Unlock()
}

func (t *Timer) IsPending() bool {
	t.modifyingMu.RLock()
	defer t.modifyingMu.RUnlock()
	return t.isPending
}

func expiredNewHandshake(peer *Peer) {
	peer.device.log.Verbosef(
		"%s - Retrying handshake because we stopped hearing back after %d seconds",
		peer,
		int((KeepaliveTimeout + RekeyTimeout).Seconds()),
	)
	// We clear endpoint's `src`, in case this is the cause of trouble.
	peer.markEndpointSrcForClearing()
	peer.SendHandshakeInitiation(false)
}

func expiredResendHandshake(peer *Peer) {
	if peer.timers.handshakeAttempts.Load() > MaxHandshakeAttempts {
		peer.device.log.Verbosef(
			"%s - Handshake didn't complete after %d attempts, giving up",
			peer,
			MaxHandshakeAttempts+1,
		)
		if peer.timersActive() {
			peer.timers.sendKeepalive.Del()
		}
		// We drop all packets without a keypair and don't try again,
		// if we try unsuccessfully for too long to make a handshake.
		peer.FlushStagedPackets()
		// We set a timer for destroying any residue that might be left
		// of a partial exchange.
		if peer.timersActive() && !peer.timers.zeroOutKeys.IsPending() {
			peer.timers.zeroOutKeys.Mod(RejectAfterTime * 3)
		}
	} else {
		peer.timers.handshakeAttempts.Add(1)
		peer.device.log.Verbosef(
			"%s - Handshake didn't complete after %d seconds, retrying (try %d)",
			peer,
			int(RekeyTimeout.Seconds()),
			peer.timers.handshakeAttempts.Load()+1,
		)
		// We clear the endpoint address src address,
		// in case this is the cause of trouble.
		peer.markEndpointSrcForClearing()
		peer.SendHandshakeInitiation(true)
	}
}

// expiredSendKeepalive is silence detection keepalive.
// This is an internal protocol mechanism to detect dead peers.
func expiredSendKeepalive(peer *Peer) {
	peer.SendKeepalive()
	if peer.timers.needAnotherKeepalive.Load() {
		peer.timers.needAnotherKeepalive.Store(false)
		if peer.timersActive() {
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		}
	}
}

// expiredKeepalive is persistent keepalive.
// This is a user-configured feature to maintain NAT mappings.
func expiredKeepalive(peer *Peer) {
	if peer.keepaliveInterval.Load() > 0 {
		peer.SendKeepalive()
	}
}

func expiredZeroOutKeys(peer *Peer) {
	peer.device.log.Verbosef(
		"%s - Removing all keys, since we haven't received a new one in %d seconds",
		peer,
		int((RejectAfterTime * 3).Seconds()),
	)
	peer.ZeroAndFlushAll()
}

func (peer *Peer) timersInit() {
	peer.timers.newHandshake = peer.NewTimer(expiredNewHandshake)
	peer.timers.resendHandshake = peer.NewTimer(expiredResendHandshake)
	peer.timers.sendKeepalive = peer.NewTimer(expiredSendKeepalive)
	peer.timers.keepalive = peer.NewTimer(expiredKeepalive)
	peer.timers.zeroOutKeys = peer.NewTimer(expiredZeroOutKeys)
}

func (peer *Peer) timersStart() {
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.timers.needAnotherKeepalive.Store(false)
}

func (peer *Peer) timersStop() {
	peer.timers.newHandshake.DelSync()
	peer.timers.resendHandshake.DelSync()
	peer.timers.sendKeepalive.DelSync()
	peer.timers.keepalive.DelSync()
	peer.timers.zeroOutKeys.DelSync()
}

func (peer *Peer) timersActive() bool {
	return peer.isRunning.Load() && peer.device != nil && peer.device.isUp()
}

// The Asymmetric Relationship
// If we send data but hear nothing back:
// - Problem might be in either direction.
// - Need handshake to repair both ways.
// If we receive data:
// - Peer can reach us (their outgoing path works).
// - They might doubt WE can reach THEM (our outgoing path).
// - Simple keepalive confirms our return path works.

// Should be called after an authenticated data packet is sent.
// Example:
// Send data → schedule a handshake in 15 seconds (as a "liveness probe").
// Receive ANY response (data, keepalive, or handshake) before 15 seconds
// → cancel the handshake.
// Receive NO response for 15 seconds → handshake timer fires
// → send new handshake initiation.
func (peer *Peer) timersDataSent() {
	if peer.timersActive() && !peer.timers.newHandshake.IsPending() {
		// 1. KeepaliveTimeout (10 seconds)
		//    This is the "silence detection" window.
		//    If we haven't sent data for 10 seconds, we might
		//    need to check if the peer is still alive.
		// 2. RekeyTimeout (5 seconds)
		//    This is the handshake response window.
		//    After initiating a handshake, we expect a response within 5 seconds.
		// 3. Why add them together?
		//    The total (15 seconds) represents: "We haven't sent any data for 10
		//    seconds, and if we initiate a handshake now, we should wait 5
		//    seconds for a response before retrying".
		d := KeepaliveTimeout +
			RekeyTimeout +
			time.Millisecond*time.Duration(rand.Int64N(RekeyTimeoutJitterMaxMs))
		// Why we use handshake instead of keepalive here:
		// 1. Repairs broken sessions
		//    If the peer has restarted or lost its key state, a keepalive will
		//    fail (it requires an existing valid session). A handshake initiation
		//    will establish a fresh session.
		// 2. Verifies bidirectional communication
		//    A handshake proves the peer can both receive AND send (since they
		//    must respond). A keepalive might just be one-way if the peer's
		//    return path is broken.
		// 3. Resets timer chains
		//    The WireGuard protocol has specific rules about when to rekey.
		//    After KeepaliveTimeout (10 seconds) of silence, sending a
		//    handshake is the appropriate next step according to the
		//    protocol specification.
		peer.timers.newHandshake.Mod(d)
	}
}

// Should be called after an authenticated data packet is received.
func (peer *Peer) timersDataReceived() {
	if peer.timersActive() {
		if !peer.timers.sendKeepalive.IsPending() {
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		} else {
			// prevents expensive timer resets on every packet
			peer.timers.needAnotherKeepalive.Store(true)
		}
	}
}

// Should be called after any type of authenticated
// packet is sent (keepalive, data, or handshake).
func (peer *Peer) timersAuthenticatedPacketSent() {
	if peer.timersActive() {
		peer.timers.sendKeepalive.Del()
	}
}

// Should be called after any type of authenticated
// packet is received (keepalive, data, or handshake).
func (peer *Peer) timersAuthenticatedPacketReceived() {
	if peer.timersActive() {
		peer.timers.newHandshake.Del()
	}
}

// Should be called before a packet with authentication
// (keepalive, data, or handshake) is sent, or after one is received.
func (peer *Peer) timersAuthenticatedPacketTraversal() {
	keepalive := peer.keepaliveInterval.Load()
	if keepalive > 0 && peer.timersActive() {
		peer.timers.keepalive.Mod(time.Duration(keepalive) * time.Second)
	}
}

// Should be called after a handshake initiation message is sent.
func (peer *Peer) timersHandshakeInitiated() {
	if peer.timersActive() {
		d := RekeyTimeout +
			time.Millisecond*time.Duration(rand.Int64N(RekeyTimeoutJitterMaxMs))
		peer.timers.resendHandshake.Mod(d)
	}
}

// Should be called after a handshake response message is received and processed
// or when getting key confirmation via the first data message.
func (peer *Peer) timersHandshakeComplete() {
	if peer.timersActive() {
		peer.timers.resendHandshake.Del()
	}
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.lastHandshake.Store(time.Now().UnixNano())
}

// Should be called after an ephemeral key is created, which is before
// sending a handshake response or after receiving a handshake response.
func (peer *Peer) timersSessionDerived() {
	if peer.timersActive() {
		peer.timers.zeroOutKeys.Mod(RejectAfterTime * 3)
	}
}
