package device

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/muhtutorials/wireguard/conn"
	"github.com/muhtutorials/wireguard/tun"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The functions in this file occur (roughly) in
 * the order in which the packets are processed.
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work
 * (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceded by enough "junk" to contain
 * the transport header (to allow the construction
 * of transport messages in-place)
 */

type QuOutItem struct {
	// contains whole message
	buf *[MaxMessageSize]byte
	// slice of buf containing IP packet
	packet []byte
	// nonce for encryption
	nonce uint64
	// keypair for encryption
	keypair *Keypair
	// related peer
	peer *Peer
}

type QuOutItemsWithLock struct {
	items []*QuOutItem
	sync.Mutex
}

func (d *Device) NewQuOutItem() *QuOutItem {
	item := d.GetQuOutItem()
	item.buf = d.GetMessageBuf()
	item.nonce = 0
	// keypair and peer were zeroed out (if necessary)
	// by zeroOutPointers
	return item
}

// zeroOutPointers zeroes out item fields that contain
// pointers. This makes the garbage collector's
// life easier and avoids accidentally keeping other
// objects around unnecessarily. It also reduces the
// possible collateral damage from use-after-free bugs.
func (item *QuOutItem) zeroOutPointers() {
	item.buf = nil
	item.packet = nil
	item.keypair = nil
	item.peer = nil
}

// SendKeepalive queues a keepalive if no packets are queued for peer.
func (peer *Peer) SendKeepalive() {
	if len(peer.qus.staged) == 0 && peer.isRunning.Load() {
		item := peer.device.NewQuOutItem()
		items := peer.device.GetQuOutItemsWithLock()
		items.items = append(items.items, item)
		select {
		case peer.qus.staged <- items:
			peer.device.log.Verbosef(
				"%v - Sending keepalive packet",
				peer,
			)
		default:
			peer.device.PutMessageBuf(item.buf)
			peer.device.PutQuOutItem(item)
			peer.device.PutQuOutItemsWithLock(items)
		}
	}
	peer.SendStagedPackets()
}

func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	if !isRetry {
		peer.timers.handshakeAttempts.Store(0)
	}
	peer.handshake.RLock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.RUnlock()
		return nil
	}
	peer.handshake.RUnlock()
	peer.handshake.Lock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.Unlock()
		return nil
	}
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.Unlock()
	peer.device.log.Verbosef(
		"%v - Sending handshake initiation",
		peer,
	)
	handshakeInit, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		peer.device.log.Errorf(
			"%v - Failed to create initiation message: %v",
			peer,
			err,
		)
		return err
	}
	buf := make([]byte, MessageInitiationSize)
	_ = handshakeInit.marshal(buf)
	peer.cookieGenerator.AddMacs(buf)
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()
	if err = peer.SendBufs([][]byte{buf}); err != nil {
		peer.device.log.Errorf(
			"%v - Failed to send handshake initiation: %v",
			peer,
			err,
		)
	}
	peer.timersHandshakeInitiated()
	return err
}

func (peer *Peer) SendHandshakeResponse() error {
	peer.handshake.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.Unlock()
	peer.device.log.Verbosef(
		"%v - Sending handshake response",
		peer,
	)
	handshakeResp, err := peer.device.CreateMessageResponse(peer)
	if err != nil {
		peer.device.log.Errorf(
			"%v - Failed to create response message: %v",
			peer,
			err,
		)
		return err
	}
	buf := make([]byte, MessageResponseSize)
	_ = handshakeResp.marshal(buf)
	peer.cookieGenerator.AddMacs(buf)
	if err = peer.BeginSymmetricSession(); err != nil {
		peer.device.log.Errorf(
			"%v - Failed to derive keypair: %v",
			peer,
			err,
		)
		return err
	}
	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()
	// TODO: allocation could be avoided
	if err = peer.SendBufs([][]byte{buf}); err != nil {
		peer.device.log.Errorf(
			"%v - Failed to send handshake response: %v",
			peer,
			err,
		)
	}
	return err
}

func (d *Device) SendHandshakeCookie(hs *QuHandshake) error {
	d.log.Verbosef(
		"Sending cookie response for denied handshake message for %v",
		hs.endpoint.DstToString(),
	)
	sender := binary.LittleEndian.Uint32(hs.packet[4:8])
	msg, err := d.cookieChecker.CreateReply(
		hs.packet,
		sender,
		hs.endpoint.DstToBytes(),
	)
	if err != nil {
		d.log.Errorf("Failed to create cookie reply: %v", err)
		return err
	}
	buf := make([]byte, MessageCookieReplySize)
	_ = msg.marshal(buf)
	// TODO: allocation could be avoided
	d.net.bind.Send([][]byte{buf}, hs.endpoint)
	return nil
}

func (peer *Peer) keepKeyFreshSending() {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return
	}
	nonce := keypair.sendNonce.Load()
	if nonce > RekeyAfterMessages ||
		(keypair.isInitiator && time.Since(keypair.createdAt) > RekeyAfterTime) {
		peer.SendHandshakeInitiation(false)
	}
}

func (d *Device) RoutineReadFromTUN() {
	defer func() {
		d.log.Verbosef("Routine: TUN reader - stopped")
		d.state.stopping.Done()
		d.qus.encryption.wg.Done()
	}()
	d.log.Verbosef("Routine: TUN reader - started")
	var (
		batchSize = d.BatchSize()
		items     = make([]*QuOutItem, batchSize)
		// bufs[i] = items[i].buf[:]
		bufs = make([][]byte, batchSize)
		// map with peer as a key and a slice of items addressed to it as value
		itemsByPeer = make(map[*Peer]*QuOutItemsWithLock, batchSize)
		sizes       = make([]int, batchSize)
		offset      = MessageTransportHeaderSize
		nPackets    = 0
		err         error
	)
	for i := range items {
		items[i] = d.NewQuOutItem()
		bufs[i] = items[i].buf[:]
	}
	defer func() {
		for _, item := range items {
			if item != nil {
				d.PutMessageBuf(item.buf)
				d.PutQuOutItem(item)
			}
		}
	}()
	for {
		// read packets
		nPackets, err = d.tun.device.Read(bufs, sizes, offset)
		for i := range nPackets {
			if sizes[i] < 1 {
				continue
			}
			item := items[i]
			item.packet = bufs[i][offset : offset+sizes[i]]
			// find peer
			var peer *Peer
			// `item.packet[0] >> 4` extracts IP version from packet
			switch item.packet[0] >> 4 {
			case 4:
				if len(item.packet) < ipv4.HeaderLen {
					continue
				}
				dst := item.packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]
				peer = d.router.Find(dst)
			case 6:
				if len(item.packet) < ipv6.HeaderLen {
					continue
				}
				dst := item.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
				peer = d.router.Find(dst)
			default:
				d.log.Verbosef("Received packet with unknown IP version")
			}
			if peer == nil {
				continue
			}
			itemsForPeer, ok := itemsByPeer[peer]
			if !ok {
				itemsForPeer = d.GetQuOutItemsWithLock()
				itemsByPeer[peer] = itemsForPeer
			}
			itemsForPeer.items = append(itemsForPeer.items, item)
			// replace items[i] and bufs[i] with new values
			items[i] = d.NewQuOutItem()
			bufs[i] = items[i].buf[:]
		}
		for peer, itemsForPeer := range itemsByPeer {
			if peer.isRunning.Load() {
				peer.StagePackets(itemsForPeer)
				peer.SendStagedPackets()
			} else {
				d.PutQuOutItems(itemsForPeer)
			}
			delete(itemsByPeer, peer)
		}
		if err != nil {
			if errors.Is(err, tun.ErrTooManySegments) {
				// TODO: record stat for this
				// This will happen if MSS is surprisingly small (< 576)
				// coincident with reasonably high throughput.
				d.log.Verbosef("Dropped some packets from multi-segment read: %v", err)
				continue
			}
			if !d.isClosed() {
				if !errors.Is(err, os.ErrClosed) {
					d.log.Errorf("Failed to read packet from TUN device: %v", err)
				}
				go d.Close()
			}
			return
		}
	}
}

func (peer *Peer) StagePackets(items *QuOutItemsWithLock) {
	// This is a non-blocking send with cleanup of stale data pattern.
	// It's a way to handle backpressure in a concurrent system.
	// The function attempts to stage packets (send items to a channel),
	// but if the channel is full, it doesn't just wait or drop the new
	// data - instead, it removes and cleans up old staged data first,
	// then tries again.
	for {
		select {
		case peer.qus.staged <- items:
			return
		default:
		}
		select {
		case tooOld := <-peer.qus.staged:
			peer.device.PutQuOutItems(tooOld)
		default:
		}
	}
}

func (peer *Peer) FlushStagedPackets() {
	for {
		select {
		case items := <-peer.qus.staged:
			peer.device.PutQuOutItems(items)
		default:
			return
		}
	}
}

func (peer *Peer) SendStagedPackets() {
top:
	if len(peer.qus.staged) == 0 || !peer.device.isUp() {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair == nil ||
		keypair.sendNonce.Load() >= RejectAfterMessages ||
		time.Since(keypair.createdAt) >= RejectAfterTime {
		peer.SendHandshakeInitiation(false)
		return
	}
	for {
		var itemsOutOfOrder *QuOutItemsWithLock
		select {
		case items := <-peer.qus.staged:
			i := 0
			for _, item := range items.items {
				item.peer = peer
				// TODO: why do we subtract 1?
				item.nonce = keypair.sendNonce.Add(1) - 1
				if item.nonce >= RejectAfterMessages {
					keypair.sendNonce.Store(RejectAfterMessages)
					if itemsOutOfOrder == nil {
						itemsOutOfOrder = peer.device.GetQuOutItemsWithLock()
					}
					itemsOutOfOrder.items = append(itemsOutOfOrder.items, item)
					continue
				} else {
					items.items[i] = item
					i++
				}
				item.keypair = keypair
			}
			// unlocked inside RoutineEncryption!
			items.Lock()
			items.items = items.items[:i]
			if itemsOutOfOrder != nil {
				// Out of order, but we can't front-load go channels
				peer.StagePackets(itemsOutOfOrder)
			}
			if len(items.items) == 0 {
				peer.device.PutQuOutItemsWithLock(items)
				goto top
			}
			// add to parallel and sequential queue
			if peer.isRunning.Load() {
				peer.device.qus.encryption.c <- items
				peer.qus.out.c <- items
			} else {
				peer.device.PutQuOutItems(items)
			}
			if itemsOutOfOrder != nil {
				goto top
			}
		default:
			return
		}
	}
}

// padding calculates amount of bytes which should be added
// to packet so it's divisible by PaddingMultiple.
func padding(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		// ((1300 + 16 - 1) & ^(16 - 1)) - 1300
		// (1315 & ^15) - 1300
		// (0b0101_0010_0011 & ^0b1111) - 1300
		// (0b0101_0010_0011 & 0b..._1111_0000) - 1300
		// 0b0101_0010_0000 - 1300
		// 1312 - 1300 = 12 (padding)
		// (1300 + 12) / 16 = 82
		return ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1)) - lastUnit
	}
	// 1600 > 1500
	if lastUnit > mtu {
		// 1600 % 1500 = 100
		lastUnit %= mtu
	}
	// ((100 + 16 - 1) & ^(16 - 1))
	// 115 & ^15
	// 0b0111_0011 & ^0b1111
	// 0b0111_0011 & 0b..._1111_0000
	// 0b0111_0000 = 112
	paddedSize := ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1))
	// If lastUnit > mtu, the packet is broken up into
	// 2 parts (1500 and 100 in this example).
	// So we add padding to 100.
	// min(112, 1500) = 112
	paddedSize = min(paddedSize, mtu)
	// 112 - 100 = 12 (padding)
	// 112 / 16 = 7
	return paddedSize - lastUnit
}

// Encrypts the elements in the queue and marks them
// for sequential consumption (by releasing the mutex).
// There should be one instance per core.
func (d *Device) RoutineEncryption(id int) {
	var paddingZeros [PaddingMultiple]byte
	var nonce [chacha20poly1305.NonceSize]byte
	defer d.log.Verbosef("Routine: encryption worker %d - stopped", id)
	d.log.Verbosef("Routine: encryption worker %d - started", id)
	for items := range d.qus.encryption.c {
		for _, item := range items.items {
			// populate header fields
			header := item.buf[:MessageTransportHeaderSize]
			msgType := header[0:4]
			msgReceiver := header[4:8]
			msgCounter := header[8:16]
			binary.LittleEndian.PutUint32(msgType, MessageTransportType)
			binary.LittleEndian.PutUint32(msgReceiver, item.keypair.remoteIndex)
			binary.LittleEndian.PutUint64(msgCounter, item.nonce)
			// pad content to multiple of 16
			paddingSize := padding(len(item.packet), int(d.tun.mtu.Load()))
			item.packet = append(item.packet, paddingZeros[:paddingSize]...)
			// encrypt content and release to consumer
			// TODO: why are firt 4 bytes not written to?
			binary.LittleEndian.PutUint64(nonce[4:], item.nonce)
			// Seal appends the encrypted message to the header.
			// `item.buf` is reused here, encrypted message is saved to the rest of the buf.
			// (item.buf[:MessageTransportHeaderSize] + encrypted message).
			// And then saves the encrypted message to `item.packet`.
			// Whole operation has zero allocations.
			item.packet = item.keypair.send.Seal(
				header,
				nonce[:],
				item.packet,
				nil,
			)
		}
		// locked inside SendStagedPackets!
		items.Unlock()
	}
}

func (peer *Peer) RoutineSequentialSender(maxBatchSize int) {
	// NOTE: lock is not released here because items are put back into pool
	// after use and then when they are taken again from the pool mutex is
	// initialized again.
	device := peer.device
	defer func() {
		// without defer, if Done() panicked, the log message wouldn't be printed
		defer device.log.Verbosef("%v - Routine: sequential sender - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential sender - started", peer)
	bufs := make([][]byte, 0, maxBatchSize)
	for items := range peer.qus.out.c {
		bufs = bufs[:0]
		if items == nil {
			return
		}
		if !peer.isRunning.Load() {
			// peer has been stopped; return re-usable elems to the shared pool.
			// This is an optimization only. It is possible for the peer to be stopped
			// immediately after this check, in which case, elem will get processed.
			// The timers and SendBuffers code are resilient to a few stragglers.
			// TODO: rework peer shutdown order to ensure
			// that we never accidentally keep timers alive longer than necessary.
			items.Lock()
			device.PutQuOutItems(items)
			continue
		}
		dataSent := false
		items.Lock()
		for _, item := range items.items {
			if len(item.packet) != MessageKeepaliveSize {
				dataSent = true
			}
			bufs = append(bufs, item.packet)
		}
		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()
		err := peer.SendBufs(bufs)
		if dataSent {
			peer.timersDataSent()
		}
		device.PutQuOutItems(items)
		if err != nil {
			var errGSO conn.ErrUDPGSODisabled
			if errors.As(err, &errGSO) {
				device.log.Verbosef(err.Error())
				err = errGSO.RetryErr
			}
		}
		if err != nil {
			device.log.Errorf("%v - Failed to send data packets: %v", peer, err)
			continue
		}
		peer.keepKeyFreshSending()
	}
}
