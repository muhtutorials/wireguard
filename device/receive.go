package device

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/muhtutorials/wireguard/conn"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type QuHandshake struct {
	msgType  uint32
	buf      *[MaxMessageSize]byte
	packet   []byte
	endpoint conn.Endpoint
}

type QuInItem struct {
	buf      *[MaxMessageSize]byte
	packet   []byte
	counter  uint64
	keypair  *Keypair
	endpoint conn.Endpoint
}

type QuInItemsWithLock struct {
	items []*QuInItem
	sync.Mutex
}

// zeroOutPointers zeroes out item fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (i *QuInItem) zeroOutPointers() {
	i.buf = nil
	i.packet = nil
	i.keypair = nil
	i.endpoint = nil
}

// keepKeyFreshReceiving is called when a new authenticated message has been received.
// NOTE: Not thread safe, but called by sequential receiver!
func (peer *Peer) keepKeyFreshReceiving() {
	if peer.timers.sentLastMinuteHandshake.Load() {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair != nil &&
		keypair.isInitiator &&
		time.Since(keypair.createdAt) > (RejectAfterTime-KeepaliveTimeout-RekeyTimeout) {
		peer.timers.sentLastMinuteHandshake.Store(true)
		peer.SendHandshakeInitiation(false)
	}
}

// RoutineReceiveIncoming receives incoming datagrams for the device.
// Every time the bind is updated a new routine is started for
// IPv4 and IPv6 (separately).
func (d *Device) RoutineReceiveIncoming(maxBatchSize int, recv conn.ReceiveFunc) {
	recvName := recv.PrettyName()
	defer func() {
		d.log.Verbosef("Routine: receive incoming %s - stopped", recvName)
		d.qus.handshake.wg.Done()
		d.qus.decryption.wg.Done()
		d.net.stopping.Done()
	}()
	d.log.Verbosef("Routine: receive incoming %s - started", recvName)
	// receive datagrams until conn is closed
	var (
		arrBufs = make([]*[MaxMessageSize]byte, maxBatchSize)
		// slices of arrBufs
		bufs        = make([][]byte, maxBatchSize)
		sizes       = make([]int, maxBatchSize)
		endpoints   = make([]conn.Endpoint, maxBatchSize)
		nPackets    int
		err         error
		retries     int
		itemsByPeer = make(map[*Peer]*QuInItemsWithLock, maxBatchSize)
	)
	for i := range arrBufs {
		arrBufs[i] = d.GetMessageBuf()
		bufs[i] = arrBufs[i][:]
	}
	defer func() {
		for i := range maxBatchSize {
			if arrBufs[i] != nil {
				d.PutMessageBuf(arrBufs[i])
			}
		}
	}()
	for {
		nPackets, err = recv(bufs, sizes, endpoints)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			d.log.Verbosef("Failed to receive %s packet: %v", recvName, err)
			if _, ok := err.(net.Error); ok {
				return
			}
			if retries < 10 {
				retries++
				time.Sleep(time.Second / 3)
				continue
			}
			return
		}
		retries = 0
		// handle each packet in the batch
		for i, size := range sizes[:nPackets] {
			if size < MinMessageSize {
				continue
			}
			// check size of packet
			packet := arrBufs[i][:size]
			msgType := binary.LittleEndian.Uint32(packet[:4])
			switch msgType {
			// check if transport
			case MessageTransportType:
				// check size
				if len(packet) < MessageTransportSize {
					continue
				}
				// get key pair
				receiver := binary.LittleEndian.Uint32(
					packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
				)
				index := d.indexTable.Get(receiver)
				keypair := index.keypair
				if keypair == nil {
					continue
				}
				// check keypair expiry
				if keypair.createdAt.Add(RejectAfterTime).Before(time.Now()) {
					continue
				}
				// create work element
				peer := index.peer
				item := d.GetQuInItem()
				item.buf = arrBufs[i]
				item.packet = packet
				// set later by RoutineDecryption method
				item.counter = 0
				item.keypair = keypair
				item.endpoint = endpoints[i]
				itemsForPeer, ok := itemsByPeer[peer]
				if !ok {
					itemsForPeer = d.GetQuInItemsWithLock()
					// unlocked inside RoutineDecryption
					itemsForPeer.Lock()
					itemsByPeer[peer] = itemsForPeer
				}
				itemsForPeer.items = append(itemsForPeer.items, item)
				// get new buffers
				arrBufs[i] = d.GetMessageBuf()
				bufs[i] = arrBufs[i][:]
				continue
			// otherwise it is a fixed size & handshake related packet
			case MessageInitiationType:
				if len(packet) != MessageInitiationSize {
					continue
				}
			case MessageResponseType:
				if len(packet) != MessageResponseSize {
					continue
				}
			case MessageCookieReplyType:
				if len(packet) != MessageCookieReplySize {
					continue
				}
			default:
				d.log.Verbosef("Received message with unknown type")
				continue
			}
			select {
			case d.qus.handshake.c <- QuHandshake{
				msgType:  msgType,
				buf:      arrBufs[i],
				packet:   packet,
				endpoint: endpoints[i],
			}:
				arrBufs[i] = d.GetMessageBuf()
				bufs[i] = arrBufs[i][:]
			default:
			}
		}
		for peer, items := range itemsByPeer {
			if peer.isRunning.Load() {
				d.qus.decryption.c <- items
				peer.qus.in.c <- items
			} else {
				d.PutQuInItems(items)
			}
			delete(itemsByPeer, peer)
		}
	}
}

func (d *Device) RoutineDecryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte
	defer d.log.Verbosef("Routine: decryption worker %d - stopped", id)
	d.log.Verbosef("Routine: decryption worker %d - started", id)
	for items := range d.qus.decryption.c {
		for _, item := range items.items {
			// split message into fields
			counter := item.packet[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := item.packet[MessageTransportOffsetContent:]
			// decrypt and release to consumer
			var err error
			item.counter = binary.LittleEndian.Uint64(counter)
			// copy counter to nonce
			binary.LittleEndian.PutUint64(nonce[4:12], item.counter)
			// TODO: why does packet become only decrypted payload here?
			item.packet, err = item.keypair.receive.Open(
				content[:0],
				nonce[:],
				content,
				nil,
			)
			if err != nil {
				item.packet = nil
			}
		}
		// locked inside RoutineReceiveIncoming
		items.Unlock()
	}
}

// RoutineHandshake handles incoming packets related to handshake.
func (d *Device) RoutineHandshake(id int) {
	defer func() {
		d.log.Verbosef("Routine: handshake worker %d - stopped", id)
		// TODO: why encryption here?
		d.qus.encryption.wg.Done()
	}()
	d.log.Verbosef("Routine: handshake worker %d - started", id)
	for item := range d.qus.handshake.c {
		// handle cookie fields and ratelimiting
		switch item.msgType {
		// processed by client
		case MessageCookieReplyType:
			// unmarshal packet
			var reply MessageCookieReply
			if err := reply.unmarshal(item.packet); err != nil {
				d.log.Verbosef("Failed to decode cookie reply")
				goto skip
			}
			// get peer from index
			index := d.indexTable.Get(reply.Receiver)
			if index.peer == nil {
				goto skip
			}
			// consume reply
			if peer := index.peer; peer.isRunning.Load() {
				d.log.Verbosef(
					"Receiving cookie response from %s",
					item.endpoint.DstToString(),
				)
				// consumed by client
				if !peer.cookieGenerator.ConsumeReply(&reply) {
					d.log.Verbosef("Could not decrypt invalid cookie response")
				}
			}
			goto skip
		case MessageInitiationType, MessageResponseType:
			// check mac fields and maybe ratelimit
			if !d.cookieChecker.CheckMAC1(item.packet) {
				d.log.Verbosef("Received packet with invalid mac1")
				goto skip
			}
			// endpoints destination address is the source of the datagram
			if d.IsUnderLoad() {
				// verify MAC2 field
				if !d.cookieChecker.CheckMAC2(item.packet, item.endpoint.DstToBytes()) {
					d.SendHandshakeCookie(&item)
					goto skip
				}
				// TODO: is this the only place where ratelimiter used?
				// check ratelimiter
				if !d.rateLimiter.val.Allow(item.endpoint.DstIP()) {
					goto skip
				}
			}
		default:
			d.log.Errorf("Invalid packet ended up in the handshake queue")
			goto skip
		}
		// handle handshake initiation/response content
		switch item.msgType {
		case MessageInitiationType:
			// unmarshal
			var msg MessageInitiation
			if err := msg.unmarshal(item.packet); err != nil {
				d.log.Errorf("Failed to decode initiation message")
				goto skip
			}
			// consume initiation
			peer := d.ConsumeMessageInitiation(&msg)
			if peer == nil {
				d.log.Verbosef(
					"Received invalid initiation message from %s",
					item.endpoint.DstToString(),
				)
				goto skip
			}
			// update timers
			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()
			// update endpoint
			peer.SetEndpointFromPacket(item.endpoint)
			d.log.Verbosef("%v - Received handshake initiation", peer)
			peer.rxBytes.Add(uint64(len(item.packet)))
			peer.SendHandshakeResponse()
		case MessageResponseType:
			// unmarshal
			var msg MessageResponse
			if err := msg.unmarshal(item.packet); err != nil {
				d.log.Errorf("Failed to decode response message")
				goto skip
			}
			// consume response
			peer := d.ConsumeMessageResponse(&msg)
			if peer == nil {
				d.log.Verbosef(
					"Received invalid response message from %s",
					item.endpoint.DstToString(),
				)
				goto skip
			}
			// update endpoint
			peer.SetEndpointFromPacket(item.endpoint)
			d.log.Verbosef("%v - Received handshake response", peer)
			peer.rxBytes.Add(uint64(len(item.packet)))
			// update timers
			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()
			// derive keypair
			if err := peer.BeginSymmetricSession(); err != nil {
				d.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
				goto skip
			}
			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			peer.SendKeepalive()
		}
	skip:
		// this buf was taken from pool in RoutineReceiveIncoming
		d.PutMessageBuf(item.buf)
	}
}

func (peer *Peer) RoutineSequentialReceiver(maxBatchSize int) {
	device := peer.device
	defer func() {
		device.log.Verbosef("%v - Routine: sequential receiver - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential receiver - started", peer)
	bufs := make([][]byte, 0, maxBatchSize)
	for items := range peer.qus.in.c {
		if items == nil {
			return
		}
		items.Lock()
		// index of the most recent valid packet
		validTailPacket := -1
		dataPacketReceived := false
		rxBytesLen := uint64(0)
		for i, item := range items.items {
			if item.packet == nil {
				// decryption failed
				continue
			}
			if !item.keypair.replayFilter.Validate(item.counter, RejectAfterMessages) {
				continue
			}
			validTailPacket = i
			if peer.ReceivedWithKeypair(item.keypair) {
				peer.SetEndpointFromPacket(item.endpoint)
				peer.timersHandshakeComplete()
				peer.SendStagedPackets()
			}
			// MinMessageSize = MessageTransportHeaderSize + chacha20poly1305.Overhead
			rxBytesLen += uint64(len(item.packet) + MinMessageSize)
			if len(item.packet) == 0 {
				device.log.Verbosef("%v - Receiving keepalive packet", peer)
				continue
			}
			dataPacketReceived = true
			// `item.packet[0] >> 4` extracts IP version from packet
			switch item.packet[0] >> 4 {
			case 4:
				if len(item.packet) < ipv4.HeaderLen {
					continue
				}
				// extract total length field from IPv4 packet
				lengthBytes := item.packet[IPv4offsetTotalLen : IPv4offsetTotalLen+2]
				length := binary.BigEndian.Uint16(lengthBytes)
				if int(length) > len(item.packet) || int(length) < ipv4.HeaderLen {
					continue
				}
				item.packet = item.packet[:length]
				// extract source address field from IPv4 packet
				src := item.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]
				if device.router.Find(src) != peer {
					device.log.Verbosef("IPv4 packet with disallowed source address from %v", peer)
					continue
				}
			case 6:
				if len(item.packet) < ipv6.HeaderLen {
					continue
				}
				// extract payload length field from IPv6 packet
				lengthBytes := item.packet[IPv6offsetPayloadLen : IPv6offsetPayloadLen+2]
				length := binary.BigEndian.Uint16(lengthBytes)
				length += ipv6.HeaderLen
				if int(length) > len(item.packet) {
					continue
				}
				item.packet = item.packet[:length]
				src := item.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]
				if device.router.Find(src) != peer {
					device.log.Verbosef("IPv6 packet with disallowed source address from %v", peer)
					continue
				}
			default:
				device.log.Verbosef("Packet with invalid IP version from %v", peer)
				continue
			}
			bufs = append(bufs, item.buf[:MessageTransportOffsetContent+len(item.packet)])
		}
		peer.rxBytes.Add(rxBytesLen)
		if validTailPacket >= 0 {
			peer.SetEndpointFromPacket(items.items[validTailPacket].endpoint)
			peer.keepKeyFreshReceiving()
			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()
		}
		if dataPacketReceived {
			peer.timersDataReceived()
		}
		if len(bufs) > 0 {
			_, err := device.tun.device.Write(bufs, MessageTransportOffsetContent)
			if err != nil && !device.isClosed() {
				device.log.Errorf("Failed to write packets to TUN device: %v", err)
			}
		}
		device.PutQuInItems(items)
		bufs = bufs[:0]
	}
}
