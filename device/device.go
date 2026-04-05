package device

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/muhtutorials/wireguard/conn"
	"github.com/muhtutorials/wireguard/ratelimiter"
	"github.com/muhtutorials/wireguard/rwcancel"
	"github.com/muhtutorials/wireguard/tun"
)

// server gets an encrypted message from the bind, decrypts it,
// sends it via TUN to the website, then reads the response from TUN,
// encrypts it, and sends it back to the peer via bind
type Device struct {
	state state
	// handles the encrypted WireGuard traffic to and from peers
	net deviceNet
	// handles the plain-text internet requests and responses
	tun         deviceTun
	keys        keys // static identity
	peers       peers
	rateLimiter rateLimiter
	// allowed IPs
	router Router
	// connects receiver to peer, handshake and keypair
	indexTable    IndexTable
	pools         pools
	qus           deviceQus
	cookieChecker CookieChecker
	ipcMu         sync.RWMutex
	closed        chan struct{}
	log           *Logger
}

type state struct {
	// state holds the device's state. It is accessed atomically.
	// Use the device.deviceState method to read it.
	// device.deviceState does not acquire the mutex, so it captures only a snapshot.
	// During state transitions, the state variable is updated before the device itself.
	// The state is thus either the current state of the device or
	// the intended future state of the device.
	// For example, while executing a call to Up, state will be deviceStateUp.
	// There is no guarantee that that intended future state of the device
	// will become the actual state; Up can fail.
	// The device can also change state multiple times between time of check and time of use.
	// Unsynchronized uses of state must therefore be advisory/best-effort only.
	val atomic.Uint32 // actually a deviceState, but typed uint32 for convenience
	// stopping blocks until all inputs to Device have been closed.
	stopping sync.WaitGroup
	// protects state changes.
	sync.Mutex
}

type deviceNet struct {
	bind          conn.Bind // bind interface
	netlinkCancel *rwcancel.RWCancel
	port          uint16 // listening port
	fwmark        uint32 // mark value (0 = disabled)
	stopping      sync.WaitGroup
	sync.RWMutex
}

type deviceTun struct {
	device tun.Device
	mtu    atomic.Int32
}

type keys struct {
	privateKey NoisePrivateKey
	publicKey  NoisePublicKey
	sync.RWMutex
}

type peers struct {
	val map[NoisePublicKey]*Peer
	sync.RWMutex
}

type rateLimiter struct {
	val            ratelimiter.RateLimiter
	underLoadUntil atomic.Int64
}

type pools struct {
	quOutItemsWithLock *WaitPool
	quInItemsWithLock  *WaitPool
	quOutItems         *WaitPool
	quInItems          *WaitPool
	// TODO: why is it not part of items?
	messageBufs *WaitPool
}

type deviceQus struct {
	handshake  *quHandshake
	encryption *quOut
	decryption *quIn
}

func NewDevice(tunDevice tun.Device, bind conn.Bind, logger *Logger) *Device {
	d := new(Device)
	d.state.val.Store(uint32(deviceStateDown))
	d.net.bind = bind
	d.tun.device = tunDevice
	mtu, err := d.tun.device.MTU()
	if err != nil {
		d.log.Errorf("Trouble determining MTU, assuming default: %v", err)
		mtu = DefaultMTU
	}
	d.tun.mtu.Store(int32(mtu))
	d.peers.val = make(map[NoisePublicKey]*Peer)
	d.rateLimiter.val.Init()
	d.indexTable.Init()
	d.InitPools()
	// create queues
	d.qus.handshake = newQuHandshake()
	d.qus.encryption = newQuOut()
	d.qus.decryption = newQuIn()
	d.closed = make(chan struct{})
	d.log = logger
	// start workers
	cpus := runtime.NumCPU()
	d.state.stopping.Wait()
	d.qus.encryption.wg.Add(cpus) // one for each RoutineHandshake
	for i := range cpus {
		go d.RoutineHandshake(i + 1)
		go d.RoutineEncryption(i + 1)
		go d.RoutineDecryption(i + 1)
	}
	d.state.stopping.Add(1)    // RoutineReadFromTUN
	d.qus.encryption.wg.Add(1) // RoutineReadFromTUN
	go d.RoutineTUNEventReader()
	go d.RoutineReadFromTUN()
	return d
}

func (d *Device) SetPrivateKey(priv NoisePrivateKey) error {
	d.keys.Lock()
	defer d.keys.Unlock()
	if priv.Equals(d.keys.privateKey) {
		return nil
	}
	d.peers.Lock()
	defer d.peers.Unlock()
	// peers with their handshakes locked
	lockedPeers := make([]*Peer, 0, len(d.peers.val))
	for _, peer := range d.peers.val {
		peer.handshake.RLock()
		lockedPeers = append(lockedPeers, peer)
	}
	// remove peers with matching public keys
	publicKey := priv.publicKey()
	for key, peer := range d.peers.val {
		// Device's public key shoudn't be equal to peer's public key.
		// Checked because:
		// 	Defensive programming (handling impossible cases gracefully).
		// 	Configuration error protection.
		// 	Testing scenarios.
		// 	Logical completeness (the system shouldn't peer with
		//  itself even if it somehow becomes possible).
		if peer.handshake.remoteStatic.Equals(publicKey) {
			// We need to release the lock here because:
			// 	removePeerLocked -> peer.Stop() -> peer.ZeroAndFlushAll() ->
			// 	-> peer.ZeroAndFlushAll() -> handshake.Lock()
			peer.handshake.RUnlock()
			removePeerLocked(d, peer, key)
			peer.handshake.RLock()
		}
	}
	// update key material
	d.keys.privateKey = priv
	d.keys.publicKey = publicKey
	d.cookieChecker.Init(publicKey)
	expiredPeers := make([]*Peer, 0, len(d.peers.val))
	for _, peer := range d.peers.val {
		hs := &peer.handshake
		hs.precomputedSharedSecret, _ = d.keys.privateKey.sharedSecret(hs.remoteStatic)
		expiredPeers = append(expiredPeers, peer)
	}
	for _, peer := range lockedPeers {
		peer.handshake.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}
	return nil
}

// deviceState represents the state of a Device.
// There are three states: down, up, closed.
// Transitions:
//
//	down -----+
//	  ↑↓      ↓
//	  up -> closed
type deviceState uint32

const (
	deviceStateDown deviceState = iota
	deviceStateUp
	deviceStateClosed
)

// getState returns device.state.val as a deviceState
// See those docs for how to interpret this value.
func (d *Device) getState() deviceState {
	return deviceState(d.state.val.Load())
}

// isUp reports whether the device is up (or is attempting to come up).
// See device.state.val comments for how to interpret this value.
func (d *Device) isUp() bool {
	return d.getState() == deviceStateUp
}

// isClosed reports whether the device is closed (or is closing).
// See device.state.val comments for how to interpret this value.
func (d *Device) isClosed() bool {
	return d.getState() == deviceStateClosed
}

// changeState attempts to change the device state to match new.
func (d *Device) changeState(new deviceState) (err error) {
	d.state.Lock()
	defer d.state.Unlock()
	old := d.getState()
	if old == deviceStateClosed {
		// once closed, always closed
		d.log.Verbosef("Interface closed, ignored requested state %s", new)
		return nil
	}
	switch new {
	case old:
		return nil
	case deviceStateUp:
		d.state.val.Store(uint32(deviceStateUp))
		err = d.upLocked()
		if err == nil {
			break
		}
		fallthrough // up failed; bring the device all the way back down
	case deviceStateDown:
		d.state.val.Store(uint32(deviceStateDown))
		errDown := d.downLocked()
		if err == nil {
			err = errDown
		}
	}
	d.log.Verbosef("Interface state was %s, requested %s, now %s", old, new, d.getState())
	return
}

// upLocked attempts to bring the device up and reports whether it succeeded.
// The caller must hold d.state mutex and is responsible for updating d.state.val.
func (d *Device) upLocked() error {
	if err := d.BindUpdate(); err != nil {
		d.log.Errorf("Unable to update bind: %v", err)
		return err
	}
	// The IPC set operation waits for peers to be created before calling Start() on them,
	// so if there's a concurrent IPC set request happening, we should wait for it to complete.
	d.ipcMu.Lock()
	defer d.ipcMu.Unlock()
	d.peers.RLock()
	for _, peer := range d.peers.val {
		peer.Start()
		if peer.KeepaliveInterval.Load() > 0 {
			peer.SendKeepalive()
		}
	}
	d.peers.RUnlock()
	return nil
}

// downLocked attempts to bring the device down and reports whether it succeeded.
// The caller must hold d.state mutex and is responsible for updating d.state.val.
func (d *Device) downLocked() error {
	err := d.BindClose()
	if err != nil {
		d.log.Errorf("Bind close failed: %v", err)
	}
	d.peers.RLock()
	for _, peer := range d.peers.val {
		peer.Stop()
	}
	d.peers.RUnlock()
	return err
}

func (d *Device) Up() error {
	return d.changeState(deviceStateUp)
}

func (d *Device) Down() error {
	return d.changeState(deviceStateDown)
}

// IsUnderLoad checks if device is currently under load.
func (d *Device) IsUnderLoad() bool {
	now := time.Now()
	// Check the length of the handshake queue.
	// If it's at least 1/8 of QuHandshakeSize, the device is considered under load.
	// This indicates too many pending handshakes.
	underLoad := len(d.qus.handshake.c) >= QuHandshakeSize/8
	if underLoad {
		// Set a timestamp underLoadUntil to the current time + UnderLoadAfterTime.
		// This creates a "cooldown" period.
		// Returns true (device is under load).
		d.rateLimiter.underLoadUntil.Store(now.Add(UnderLoadAfterTime).UnixNano())
		return true
	}
	// Check if we're still in the "cooldown" period from a previous load event.
	// Return true if the "cooldown" hasn't expired yet.
	return d.rateLimiter.underLoadUntil.Load() > now.UnixNano()
}

func (d *Device) GetPeer(pk NoisePublicKey) *Peer {
	d.peers.RLock()
	defer d.peers.RUnlock()
	return d.peers.val[pk]
}

func (d *Device) RemovePeer(key NoisePublicKey) {
	d.peers.Lock()
	defer d.peers.Unlock()
	// stop peer and remove from routing
	peer, ok := d.peers.val[key]
	if ok {
		removePeerLocked(d, peer, key)
	}
}

func (d *Device) RemoveAllPeers() {
	d.peers.Lock()
	defer d.peers.Unlock()
	for key, peer := range d.peers.val {
		removePeerLocked(d, peer, key)
	}
	// The old map might have been large with many entries.
	// Creating a fresh empty map ensures that the old map
	// and its underlying array can be garbage collected.
	d.peers.val = make(map[NoisePublicKey]*Peer)
}

// must hold device.peers.Lock()
func removePeerLocked(device *Device, peer *Peer, key NoisePublicKey) {
	// stop routing and processing of packets
	device.router.RemoveByPeer(peer)
	peer.Stop()
	// remove from peer map
	delete(device.peers.val, key)
}

// SendKeepalives sends keepalives to peers with current keypair
func (d *Device) SendKeepalives() {
	if !d.isUp() {
		return
	}
	d.peers.RLock()
	defer d.peers.RUnlock()
	for _, peer := range d.peers.val {
		peer.keypairs.RLock()
		sendKeepalive := peer.keypairs.current != nil &&
			!peer.keypairs.current.createdAt.Add(RejectAfterTime).Before(time.Now())
		peer.keypairs.RUnlock()
		// current is not nil and RejectAfterTime hasn't passed yet
		if sendKeepalive {
			peer.SendKeepalive()
		}
	}
}

func (d *Device) Close() {
	d.state.Lock()
	defer d.state.Unlock()
	d.ipcMu.Lock()
	defer d.ipcMu.Unlock()
	if d.isClosed() {
		return
	}
	d.state.val.Store(uint32(deviceStateClosed))
	d.log.Verbosef("Device closing")
	d.tun.device.Close()
	d.downLocked()
	// Remove peers before closing queues,
	// because peers assume that queues are active.
	d.RemoveAllPeers()
	// We kept a reference to the encryption and decryption queues,
	// in case we started any new peers that might write to them.
	// No new peers are coming; we are done with these queues.
	d.qus.handshake.wg.Done()
	d.qus.encryption.wg.Done()
	d.qus.decryption.wg.Done()
	d.state.stopping.Wait()
	d.rateLimiter.val.Close()
	d.log.Verbosef("Device closed")
	close(d.closed)
}

// closeBindLocked closes the device's net.bind.
// The caller must hold the net mutex.
func closeBindLocked(d *Device) error {
	var err error
	nt := &d.net
	if nt.netlinkCancel != nil {
		nt.netlinkCancel.Cancel()
	}
	if nt.bind != nil {
		err = nt.bind.Close()
	}
	nt.stopping.Wait()
	return err
}

func (d *Device) Bind() conn.Bind {
	d.net.Lock()
	defer d.net.Unlock()
	return d.net.bind
}

// BindSetMark sets a firewall mark (or fwmark) that can be attached
// to network packets in the Linux kernel. It's used for:
// - Policy routing - Direct packets through specific routing tables based on their mark.
// - Packet filtering - Apply different firewall rules to marked packets.
// - Traffic control - Shape or prioritize marked traffic differently.
// Set via CLI.
func (d *Device) BindSetMark(mark uint32) error {
	d.net.Lock()
	defer d.net.Unlock()
	// check if modified
	if d.net.fwmark == mark {
		return nil
	}
	// update fwmark on existing bind
	d.net.fwmark = mark
	if d.isUp() && d.net.bind != nil {
		if err := d.net.bind.SetMark(mark); err != nil {
			return err
		}
	}
	// clear cached source addresses
	d.peers.RLock()
	for _, peer := range d.peers.val {
		peer.markEndpointSrcForClearing()
	}
	d.peers.RUnlock()
	return nil
}

// BindUpdate updates bind's port when changed via CLI.
func (d *Device) BindUpdate() error {
	d.net.Lock()
	defer d.net.Unlock()
	// close existing sockets
	if err := closeBindLocked(d); err != nil {
		return err
	}
	// open new sockets
	if !d.isUp() {
		return nil
	}
	// bind to new port
	var (
		err     error
		recvFns []conn.ReceiveFunc
	)
	nt := &d.net
	recvFns, nt.port, err = nt.bind.Open(nt.port)
	if err != nil {
		nt.port = 0
		return err
	}
	nt.netlinkCancel, err = d.startRouteListener(nt.bind)
	if err != nil {
		nt.bind.Close()
		nt.port = 0
		return err
	}
	// set fwmark
	if nt.fwmark != 0 {
		if err = nt.bind.SetMark(nt.fwmark); err != nil {
			return err
		}
	}
	// clear cached source addresses
	d.peers.RLock()
	for _, peer := range d.peers.val {
		peer.markEndpointSrcForClearing()
	}
	d.peers.RUnlock()
	// start receiving routines
	d.net.stopping.Add(len(recvFns))
	// each RoutineReceiveIncoming goroutine writes to device.qus.handshake
	d.qus.handshake.wg.Add(len(recvFns))
	// each RoutineReceiveIncoming goroutine writes to device.qus.decryption
	d.qus.decryption.wg.Add(len(recvFns))
	batchSize := nt.bind.BatchSize()
	for _, fn := range recvFns {
		go d.RoutineReceiveIncoming(batchSize, fn)
	}
	d.log.Verbosef("UDP bind has been updated")
	return nil
}

func (d *Device) BindClose() error {
	d.net.Lock()
	defer d.net.Unlock()
	return closeBindLocked(d)
}

func (d *Device) Wait() chan struct{} {
	return d.closed
}

// BatchSize returns the BatchSize for the device as a whole which is the max of
// the bind batch size and the tun batch size. The batch size reported by device
// is the size used to construct memory pools, and is the allowed batch size for
// the lifetime of the device.
func (d *Device) BatchSize() int {
	size := d.net.bind.BatchSize()
	dSize := d.tun.device.BatchSize()
	return max(size, dSize)
}
