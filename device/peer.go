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
	device                      *Device
	handshake                   Handshake
	keypairs                    Keypairs
	endpoint                    endpoint
	qus                         peerQus
	timers                      timers
	nodes                       list.List
	cookieGenerator             CookieGenerator
	txBytes                     atomic.Uint64 // bytes send to peer (endpoint)
	rxBytes                     atomic.Uint64 // bytes received from peer
	isRunning                   atomic.Bool
	lastHandshake               atomic.Int64 // nano seconds since epoch
	persistentKeepaliveInterval atomic.Uint32
	stopping                    sync.WaitGroup // routines pending stop
	sync.Mutex                                 // protects against concurrent Start/Stop
}

type endpoint struct {
	val conn.Endpoint
	// Signal to val.ClearSrc() prior to next packet transmission.
	// clearSrcOnTx indicates that the source address
	// should NOT be cleared when transmitting.
	clearSrcOnTx bool
	// disableRoaming prevents the peer from changing IP addresses
	disableRoaming bool
	sync.Mutex
}

type peerQus struct {
	// staged packets before a handshake is available
	staged chan *QuOutItemsSynced
	// sequential ordering of UDP transmission
	out *quOutFlush
	// sequential ordering of tun writing
	in *quInFlush
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

func (d *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {
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
	// create peer
	var peer *Peer
	peer.device = d
	peer.qus.staged = make(chan *QuOutItemsSynced, QuStagedSize)
	peer.qus.out = newQuOutFlush(d)
	peer.qus.in = newQuInFlush(d)
	peer.cookieGenerator.Init(pk)
	// map public key
	_, ok := d.peers.val[pk]
	if ok {
		return nil, errors.New("adding existing peer")
	}
	// pre-compute DH
	handshake := &peer.handshake
	handshake.Lock()
	handshake.precomputedSharedSecret, _ = d.keys.privateKey.sharedSecret(pk)
	handshake.remoteStatic = pk
	handshake.Unlock()
	// reset endpoint
	peer.endpoint.Lock()
	peer.endpoint.val = nil
	peer.endpoint.disableRoaming = false
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.Unlock()
	// init timers
	peer.timersInit()
	// add peer
	d.peers.val[pk] = peer
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
		return input + 'A' + byte(((25-int(input))>>8)&6) - byte(((51-int(input))>>8)&75) - byte(((61-int(input))>>8)&15) + byte(((62-int(input))>>8)&3)
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
	// reset routine state
	// Wait() blocks until any previous goroutines from a previous
	// start have completely finished.
	// Only after they're done, we add 2 for the new goroutines we're about
	// to launch (RoutineSequentialSender and RoutineSequentialReceiver).
	// This prevents resource leaks and ensures we don't have
	// multiple instances of the same routines running concurrently
	// if Start() is called twice in quick succession.
	peer.stopping.Wait()
	peer.stopping.Add(2)
	peer.handshake.Lock()
	// Set the lastSentHandshake timestamp to a time
	// in the past to force an immediate handshake.
	// RekeyTimeout (=5s) is the interval after which a new handshake
	// is initiated if no data has been sent/received.
	// Adding +1 second ensures it's definitely expired
	// By subtracting (RekeyTimeout + 1s), we guarantee that
	// lastSentHandshake is older than RekeyTimeout relative to now().
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.Unlock()
	peer.device.qus.encryption.wg.Add(1) // keep encryption queue open for our writes
	peer.timersStart()
	device.flushQuOut(peer.qus.out)
	device.flushQuIn(peer.qus.in)
	// Use the device batch size, not the bind batch size, as the device size is
	// the size of the batch pools.
	batchSize := peer.device.BatchSize()
	go peer.RoutineSequentialSender(batchSize)
	go peer.RoutineSequentialReceiver(batchSize)
	peer.isRunning.Store(true)
}

func (peer *Peer) SendBufs(bufs [][]byte) error {
	peer.device.net.RLock()
	defer peer.device.net.RUnlock()
	if peer.device.isClosed() {
		return nil
	}
	peer.endpoint.Lock()
	endpoint := peer.endpoint.val
	if endpoint == nil {
		peer.endpoint.Unlock()
		return errors.New("no known endpoint for peer")
	}
	if peer.endpoint.clearSrcOnTx {
		endpoint.ClearSrc()
		peer.endpoint.clearSrcOnTx = false
	}
	peer.endpoint.Unlock()
	err := peer.device.net.bind.Send(bufs, endpoint)
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
	// Signal that RoutineSequentialSender and RoutineSequentialReceiver should exit.
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
	device.DeleteKeypair(keypairs.previous)
	device.DeleteKeypair(keypairs.current)
	device.DeleteKeypair(keypairs.next.Load())
	keypairs.previous = nil
	keypairs.current = nil
	keypairs.next.Store(nil)
	keypairs.Unlock()
	// clear handshake state
	handshake := &peer.handshake
	handshake.Lock()
	device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	handshake.Unlock()
	peer.FlushStagedPackets()
}

func (peer *Peer) ExpireCurrentKeypairs() {
	handshake := &peer.handshake
	handshake.Lock()
	peer.device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	// see Start method for explanation
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	handshake.Unlock()
	keypairs := &peer.keypairs
	keypairs.Lock()
	if keypairs.current != nil {
		keypairs.current.sendNonce.Store(RejectAfterMessages)
	}
	if next := keypairs.next.Load(); next != nil {
		next.sendNonce.Store(RejectAfterMessages)
	}
	keypairs.Unlock()
}

func (peer *Peer) SetEndpointFromPacket(endpoint conn.Endpoint) {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	if peer.endpoint.disableRoaming {
		return
	}
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.val = endpoint
}

func (peer *Peer) markEndpointSrcForClearing() {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	if peer.endpoint.val == nil {
		return
	}
	peer.endpoint.clearSrcOnTx = true
}
