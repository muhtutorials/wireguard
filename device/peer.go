package device

import (
	"container/list"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/muhtutorials/wireguard/conn"
)

type Peer struct {
	device            *Device
	handshake         Handshake
	keypairs          Keypairs
	endpoint          endpoint
	qus               peerQus
	timers            timers
	nodes             list.List
	cookieGenerator   CookieGenerator
	isRunning         atomic.Bool
	lastHandshake     atomic.Int64 // nanoseconds since epoch
	keepaliveInterval atomic.Uint32
	// bytes sent to peer
	txBytes atomic.Uint64
	// bytes received from peer
	rxBytes atomic.Uint64
	// waits for RoutineSendToPeer and RoutineSendToInternet to finish
	stopping sync.WaitGroup
	// protects against concurrent start/stop
	sync.Mutex
}

type endpoint struct {
	val conn.Endpoint
	// When set to true, val.ClearSrc() should be
	// called before next packet transmission.
	clearSrcOnTx bool
	sync.Mutex
}

type peerQus struct {
	// peer's received packets before handshake was
	// established or during reestablishing handshake
	staged chan *QuOutItemsWithLock
	// sequential ordering of UDP transmission (writing)
	out *quOutFlush
	// sequential ordering of TUN writing
	in *quInFlush
}

type timers struct {
	newHandshake    *Timer
	resendHandshake *Timer
	sendKeepalive   *Timer
	keepalive       *Timer
	// zeroes out peer's keys
	zeroOutKeys       *Timer
	handshakeAttempts atomic.Uint32
	// Tells if peer has already sent a last-minute handshake.
	// (explanation at Peer.keepKeyFreshReceiving)
	sentLastMinuteHandshake atomic.Bool
	// prevents expensive timer resets on every packet
	needAnotherKeepalive atomic.Bool
}

// NewPeer is used by handlePublicKeyLine method to create
// a new peer by providing a public key via IPC.
func (d *Device) NewPeer(pub NoisePublicKey) (*Peer, error) {
	if d.isClosed() {
		return nil, errors.New("device closed")
	}
	// lock resources
	d.keys.RLock()
	defer d.keys.RUnlock()
	d.peers.Lock()
	defer d.peers.Unlock()
	// check if over limit
	if len(d.peers.val) >= MaxPeers {
		return nil, errors.New("too many peers")
	}
	// map public key
	_, ok := d.peers.val[pub]
	if ok {
		return nil, errors.New("adding existing peer")
	}
	// create peer
	peer := new(Peer)
	peer.device = d
	// pre-compute DH
	handshake := &peer.handshake
	handshake.Lock()
	handshake.precomputedSharedSecret, _ = d.keys.privateKey.sharedSecret(pub)
	handshake.remoteStatic = pub
	handshake.Unlock()
	peer.qus.staged = make(chan *QuOutItemsWithLock, QuStagedSize)
	peer.qus.out = newQuOutFlush(d)
	peer.qus.in = newQuInFlush(d)
	// init timers
	peer.timersInit()
	peer.cookieGenerator.Init(pub)
	// add peer
	d.peers.val[pub] = peer
	return peer, nil
}

func (peer *Peer) String() string {
	// The awful goo that follows is identical to:
	//
	//   base64Key := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	//   abbreviatedKey := base64Key[0:4] + "…" + base64Key[39:43]
	//   return fmt.Sprintf("peer(%s)", abbreviatedKey)
	//
	// except that it is considerably more efficient.
	src := peer.handshake.remoteStatic
	b64 := func(input byte) byte {
		return input +
			'A' +
			byte(((25-int(input))>>8)&6) -
			byte(((51-int(input))>>8)&75) -
			byte(((61-int(input))>>8)&15) +
			byte(((62-int(input))>>8)&3)
	}
	b := []byte("peer(____…____)")
	const first = len("peer(")
	const second = len("peer(____…")
	b[first+0] = b64((src[0] >> 2) & 63)
	b[first+1] = b64(((src[0] << 4) | (src[1] >> 4)) & 63)
	b[first+2] = b64(((src[1] << 2) | (src[2] >> 6)) & 63)
	b[first+3] = b64(src[2] & 63)
	b[second+0] = b64(src[29] & 63)
	b[second+1] = b64((src[30] >> 2) & 63)
	b[second+2] = b64(((src[30] << 4) | (src[31] >> 4)) & 63)
	b[second+3] = b64((src[31] << 2) & 63)
	return string(b)
}

func (peer *Peer) Start() {
	// should never start a peer on a closed device
	if peer.device.isClosed() {
		return
	}
	// prevent simultaneous start/stop operations
	peer.Lock()
	defer peer.Unlock()
	if peer.isRunning.Load() {
		return
	}
	device := peer.device
	device.log.Verbosef("%v - Starting", peer)
	// Reset routine state.
	// Wait() blocks until any routines from a previous
	// start have completely finished.
	// Only after they're done, we add 2 for the new routines we're about
	// to launch (RoutineSendToPeer and RoutineSendToInternet).
	// This prevents resource leaks and ensures we don't have
	// multiple instances of the same routines running concurrently
	// if Start() is called twice in quick succession.
	peer.stopping.Wait()
	peer.stopping.Add(2)
	peer.handshake.Lock()
	// Set the lastSentHandshake timestamp to a time
	// in the past to force an immediate handshake.
	// RekeyTimeout (=5s) is the interval after which a new
	// handshake is initiated if no data has been sent/received.
	// Adding +1 second ensures it's definitely expired.
	// By subtracting (RekeyTimeout + 1s), we guarantee that
	// lastSentHandshake is older than RekeyTimeout relative to now.
	peer.handshake.lastSentHandshake =
		time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.Unlock()
	// keep encryption queue open for our writes
	peer.device.qus.encryption.wg.Add(1)
	device.flushQuOut(peer.qus.out)
	device.flushQuIn(peer.qus.in)
	peer.timersStart()
	// Use the device batch size, not the bind batch size,
	// as the device size is the size of the batch pools.
	batchSize := peer.device.BatchSize()
	go peer.RoutineSendToPeer(batchSize)
	go peer.RoutineSendToInternet(batchSize)
	peer.isRunning.Store(true)
}

func (peer *Peer) Send(bufs [][]byte) error {
	peer.device.net.RLock()
	defer peer.device.net.RUnlock()
	if peer.device.isClosed() {
		return nil
	}
	peer.endpoint.Lock()
	if peer.endpoint.val == nil {
		peer.endpoint.Unlock()
		return errors.New("no known endpoint for peer")
	}
	if peer.endpoint.clearSrcOnTx {
		peer.endpoint.val.ClearSrc()
		peer.endpoint.clearSrcOnTx = false
	}
	peer.endpoint.Unlock()
	err := peer.device.net.bind.Send(bufs, peer.endpoint.val)
	if err == nil {
		var totalLen uint64
		for _, buf := range bufs {
			totalLen += uint64(len(buf))
		}
		peer.txBytes.Add(totalLen)
	}
	return err
}

func (peer *Peer) Stop() {
	peer.Lock()
	defer peer.Unlock()
	if !peer.isRunning.Swap(false) {
		return
	}
	peer.device.log.Verbosef("%v - Stopping", peer)
	peer.timersStop()
	// Signal that RoutineSendToPeer and
	// RoutineSendToInternet should exit.
	peer.qus.out.c <- nil
	peer.qus.in.c <- nil
	peer.stopping.Wait()
	// no more writes to encryption queue from us
	peer.device.qus.encryption.wg.Done()
	peer.ZeroAndFlushAll()
}

func (peer *Peer) ZeroAndFlushAll() {
	device := peer.device
	// clear key pairs
	keypairs := &peer.keypairs
	keypairs.Lock()
	device.DeleteSession(keypairs.current)
	device.DeleteSession(keypairs.previous)
	device.DeleteSession(keypairs.next.Load())
	keypairs.current = nil
	keypairs.previous = nil
	keypairs.next.Store(nil)
	keypairs.Unlock()
	// clear handshake state
	handshake := &peer.handshake
	handshake.Lock()
	device.sessions.Delete(handshake.localIndex)
	handshake.Clear()
	handshake.Unlock()
	peer.FlushStagedPackets()
}

func (peer *Peer) ExpireCurrentKeypairs() {
	handshake := &peer.handshake
	handshake.Lock()
	peer.device.sessions.Delete(handshake.localIndex)
	handshake.Clear()
	// see Start method for explanation
	handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	handshake.Unlock()
	keypairs := &peer.keypairs
	keypairs.Lock()
	defer keypairs.Unlock()
	if keypairs.current != nil {
		keypairs.current.sendNonce.Store(RejectAfterMessages)
	}
	if next := keypairs.next.Load(); next != nil {
		next.sendNonce.Store(RejectAfterMessages)
	}
}

func (peer *Peer) SetEndpointFromPacket(endpoint conn.Endpoint) {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	peer.endpoint.val = endpoint
	peer.endpoint.clearSrcOnTx = false
}

// markEndpointSrcForClearing sets clearSrcOnTx to true, so
// next time when `Peer.Send` is called, it calls `ClearSrc`.
func (peer *Peer) markEndpointSrcForClearing() {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	if peer.endpoint.val == nil {
		return
	}
	peer.endpoint.clearSrcOnTx = true
}
