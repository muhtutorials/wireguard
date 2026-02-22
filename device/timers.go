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
	runningMu   sync.Mutex
	modifyingMu sync.RWMutex
	isPending   bool
}

// NewTimer creates a timer that will execute expiration function (expFunc)
// after 1 hour, but immediately stops it. This creates a "stopped timer"
// that can be later reset or used.
func (peer *Peer) NewTimer(expFunc func(*Peer)) *Timer {
	t := &Timer{}
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
	t.isPending = true
	t.Reset(d)
	t.modifyingMu.Unlock()
}

func (t *Timer) Del() {
	t.modifyingMu.Lock()
	t.isPending = false
	t.Stop()
	t.modifyingMu.Unlock()
}

// TODO: Why is it needed?
func (t *Timer) DelSync() {
	t.Del()
	t.runningMu.Lock()
	t.Del()
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
	// We clear the endpoint address src address, in case this is the cause of trouble.
	peer.markEndpointSrcForClearing()
	peer.SendHandshakeInitiation(false)
}

func expiredRetransmitHandshake(peer *Peer) {
	if peer.timers.handshakeAttempts.Load() > MaxTimerHandshakes {
		peer.device.log.Verbosef(
			"%s - Handshake did not complete after %d attempts, giving up",
			peer,
			MaxTimerHandshakes+2,
		)
		if peer.timersActive() {
			peer.timers.sendKeepalive.Del()
		}
		// We drop all packets without a keypair and don't try again,
		// if we try unsuccessfully for too long to make a handshake.
		peer.FlushStagedPackets()
		// We set a timer for destroying any residue that might be left
		// of a partial exchange.
		if peer.timersActive() && !peer.timers.zeroKeyMaterial.IsPending() {
			peer.timers.zeroKeyMaterial.Mod(RejectAfterTime * 3)
		}
	} else {
		peer.timers.handshakeAttempts.Add(1)
		peer.device.log.Verbosef(
			"%s - Handshake did not complete after %d seconds, retrying (try %d)",
			peer,
			int(RekeyTimeout.Seconds()), peer.timers.handshakeAttempts.Load()+1,
		)
		// We clear the endpoint address src address, in case this is the cause of trouble.
		peer.markEndpointSrcForClearing()
		peer.SendHandshakeInitiation(true)
	}
}

func expiredSendKeepalive(peer *Peer) {
	peer.SendKeepalive()
	if peer.timers.needAnotherKeepalive.Load() {
		peer.timers.needAnotherKeepalive.Store(false)
		if peer.timersActive() {
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		}
	}
}

func expiredPersistentKeepalive(peer *Peer) {
	if peer.persistentKeepaliveInterval.Load() > 0 {
		peer.SendKeepalive()
	}
}

func expiredZeroKeyMaterial(peer *Peer) {
	peer.device.log.Verbosef(
		"%s - Removing all keys, since we haven't received a new one in %d seconds",
		peer,
		int((RejectAfterTime * 3).Seconds()),
	)
	peer.ZeroAndFlushAll()
}

func (peer *Peer) timersInit() {
	peer.timers.newHandshake = peer.NewTimer(expiredNewHandshake)
	peer.timers.retransmitHandshake = peer.NewTimer(expiredRetransmitHandshake)
	peer.timers.sendKeepalive = peer.NewTimer(expiredSendKeepalive)
	peer.timers.persistentKeepalive = peer.NewTimer(expiredPersistentKeepalive)
	peer.timers.zeroKeyMaterial = peer.NewTimer(expiredZeroKeyMaterial)
}

func (peer *Peer) timersStart() {
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.timers.needAnotherKeepalive.Store(false)
}

func (peer *Peer) timersStop() {
	peer.timers.newHandshake.DelSync()
	peer.timers.retransmitHandshake.DelSync()
	peer.timers.sendKeepalive.DelSync()
	peer.timers.persistentKeepalive.DelSync()
	peer.timers.zeroKeyMaterial.DelSync()
}

func (peer *Peer) timersActive() bool {
	return peer.isRunning.Load() && peer.device != nil && peer.device.isUp()
}

// Should be called after an authenticated data packet is sent.
func (peer *Peer) timersDataSent() {
	if peer.timersActive() && !peer.timers.newHandshake.IsPending() {
		d := KeepaliveTimeout + RekeyTimeout + time.Millisecond*time.Duration(rand.Int64N(RekeyTimeoutJitterMaxMs))
		peer.timers.newHandshake.Mod(d)
	}
}

// Should be called after an authenticated data packet is received.
func (peer *Peer) timersDataReceived() {
	if peer.timersActive() {
		if !peer.timers.sendKeepalive.IsPending() {
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		} else {
			peer.timers.needAnotherKeepalive.Store(true)
		}
	}
}

// Should be called after any type of authenticated
// packet is sent (keepalive, data, or handshake).
func (peer *Peer) timersAnyAuthenticatedPacketSent() {
	if peer.timersActive() {
		peer.timers.sendKeepalive.Del()
	}
}

// Should be called after any type of authenticated
// packet is received (keepalive, data, or handshake).
func (peer *Peer) timersAnyAuthenticatedPacketReceived() {
	if peer.timersActive() {
		peer.timers.newHandshake.Del()
	}
}

// Should be called after a handshake initiation message is sent.
func (peer *Peer) timersHandshakeInitiated() {
	if peer.timersActive() {
		d := RekeyTimeout + time.Millisecond*time.Duration(rand.Int64N(RekeyTimeoutJitterMaxMs))
		peer.timers.retransmitHandshake.Mod(d)
	}
}

// Should be called after a handshake response message is received and processed
// or when getting key confirmation via the first data message.
func (peer *Peer) timersHandshakeComplete() {
	if peer.timersActive() {
		peer.timers.retransmitHandshake.Del()
	}
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.lastHandshake.Store(time.Now().UnixNano())
}

// Should be called after an ephemeral key is created, which is before
// sending a handshake response or after receiving a handshake response.
func (peer *Peer) timersSessionDerived() {
	if peer.timersActive() {
		peer.timers.zeroKeyMaterial.Mod(RejectAfterTime * 3)
	}
}

// Should be called before a packet with authentication
// (keepalive, data, or handshake) is sent, or after one is received.
func (peer *Peer) timersAnyAuthenticatedPacketTraversal() {
	keepalive := peer.persistentKeepaliveInterval.Load()
	if keepalive > 0 && peer.timersActive() {
		peer.timers.persistentKeepalive.Mod(time.Duration(keepalive) * time.Second)
	}
}
