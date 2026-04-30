package conn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	// Exceeding these values results in EMSGSIZE. They account for
	// layer 3 and layer 4 headers. IPv6 does not need to account
	// for itself as the payload length field is self excluding.
	// IPv4 total length field includes header and payload.
	// 20 is IPv4 header size, 8 is UDP header size.
	maxIPv4PayloadLen = 1<<16 - 1 - 20 - 8
	// IPv6 payload length field includes only payload.
	// 8 is UDP header size.
	maxIPv6PayloadLen = 1<<16 - 1 - 8
	// This is the maximum number of UDP packets that can be
	// coalesced for GSO (Generic Segmentation Offload).
	// Why 64?
	// 	- Linux kernel hard limit for UDP GSO.
	// 	- Defined in include/linux/skbuff.h: UDP_MAX_SEGMENTS.
	// 	- Limits memory and processing per batch.
	// 	- Balances efficiency with latency.
	maxUDPSegments = 64
)

var (
	// Verifies at compile time that *NetBind implements the
	// Bind interface. Only pointer receiver is allowed.
	_ Bind = (*NetBind)(nil)
	// Verifies at compile time that &NetEndpoint implements the
	// Bind interface. Pointer and value receivers are allowed.
	_ Endpoint = &NetEndpoint{}
	// If compilation fails here these are no longer the same
	// underlying type.
	_ ipv6.Message = ipv4.Message{}
)

type NetBind struct {
	ipv4Conn *net.UDPConn
	ipv6Conn *net.UDPConn
	// ipv(4/6).PacketConn is a wrapper around net.UDPConn.
	// Used only for batch reading and writing.
	ipv4PacketConn *ipv4.PacketConn
	ipv6PacketConn *ipv6.PacketConn
	// GSO (Generic Segmentation Offload)
	// Application combines several packets into one,
	// sends to kernel, kernel sends to NIC,
	// NIC splits one large packet into several standard packets,
	// and sends them over the network.
	ipv4TxOffload bool
	// GRO (Generic Receive Offload)
	// NIC combines multiple incoming packets into one large packet,
	// kernel delivers them as a single packet to application, and
	// application splits it into several standard packets.
	ipv4RxOffload bool
	// same as ipv4TxOffload but for IPv6
	ipv6TxOffload bool
	// same as ipv4RxOffload but for IPv6
	ipv6RxOffload bool
	// these two fields are not guarded by mu
	udpAddrPool sync.Pool
	msgsPool    sync.Pool
	// protects all fields except as specified
	mu sync.Mutex
}

func New() Bind {
	return &NetBind{
		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},
		msgsPool: sync.Pool{
			New: func() any {
				// ipv6.Message and ipv4.Message are interchangeable as they are
				// both aliases for x/net/internal/socket.Message.
				msgs := make([]ipv6.Message, BatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
				}
				return &msgs
			},
		},
	}
}

type NetEndpoint struct {
	// endpoint destination
	netip.AddrPort
	// src is the current sticky source address and interface
	// index, if supported. Typically this is a PKTINFO structure
	// from/for control messages, see unix.PKTINFO for an example.
	// When a server has multiple IP addresses or multiple network
	// interfaces, it needs to know:
	// 	Which local IP received an incoming packet.
	// 	Which interface received it.
	// 	Which source IP to use when replying.
	// src is msg.OOB or "hdr + data" from this function:
	// hdr, data, remaining, err = unix.ParseOneSocketControlMessage(msg.OOB[:msg.NN])
	src []byte
}

func (e *NetEndpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

func (e *NetEndpoint) DstToString() string {
	return e.AddrPort.String()
}

func (e *NetEndpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

func (e *NetEndpoint) ClearSrc() {
	if e.src != nil {
		// Truncate src, no need to reallocate.
		e.src = e.src[:0]
	}
}

func listenNet(network string, port int) (*net.UDPConn, int, error) {
	// net.ListenConfig.Listen is for TCP.
	// net.ListenConfig.ListenPacket is for UDP.
	conn, err := listenConfig().ListenPacket(
		context.Background(),
		network,
		":"+strconv.Itoa(port),
	)
	if err != nil {
		return nil, 0, err
	}
	// retrieve port
	localAddr := conn.LocalAddr()
	udpAddr, err := net.ResolveUDPAddr(
		localAddr.Network(),
		localAddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	// convert net.PacketConn interface to *net.UDPConn type
	return conn.(*net.UDPConn), udpAddr.Port, nil
}

func (b *NetBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ipv4Conn != nil || b.ipv6Conn != nil {
		return nil, 0, ErrBindAlreadyOpen
	}
	var (
		err     error
		retries int
	)
	// Attempt to open IPv4 and IPv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
	for {
		port := int(uport)
		var ipv4Conn, ipv6Conn *net.UDPConn
		ipv4Conn, port, err = listenNet("udp4", port)
		// EAFNOSUPPORT: address family not supported by protocol
		if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
			return nil, 0, err
		}
		// Listen on the same port as we're using for IPv4.
		ipv6Conn, port, err = listenNet("udp6", port)
		// EADDRINUSE: address already in use
		if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && retries < 100 {
			ipv4Conn.Close()
			retries++
			continue
		}
		if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
			ipv4Conn.Close()
			return nil, 0, err
		}
		var fns []ReceiveFunc
		if ipv4Conn != nil {
			b.ipv4Conn = ipv4Conn
			b.ipv4PacketConn = ipv4.NewPacketConn(ipv4Conn)
			b.ipv4TxOffload, b.ipv4RxOffload = supportsUDPOffload(ipv4Conn)
			fns = append(fns, b.makeReceiveIPv4(b.ipv4PacketConn, b.ipv4RxOffload))
		}
		if ipv6Conn != nil {
			b.ipv6Conn = ipv6Conn
			b.ipv6PacketConn = ipv6.NewPacketConn(ipv6Conn)
			b.ipv6TxOffload, b.ipv6RxOffload = supportsUDPOffload(ipv6Conn)
			fns = append(fns, b.makeReceiveIPv6(b.ipv6PacketConn, b.ipv6RxOffload))
		}
		if len(fns) == 0 {
			return nil, 0, syscall.EAFNOSUPPORT
		}
		return fns, uint16(port), nil
	}
}

func (b *NetBind) makeReceiveIPv4(pc *ipv4.PacketConn, rxOffload bool) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		return b.receive(pc, rxOffload, bufs, sizes, eps)
	}
}

func (b *NetBind) makeReceiveIPv6(pc *ipv6.PacketConn, rxOffload bool) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		return b.receive(pc, rxOffload, bufs, sizes, eps)
	}
}

type batchReader interface {
	ReadBatch(msgs []ipv6.Message, flags int) (int, error)
}

type batchWriter interface {
	WriteBatch(msgs []ipv6.Message, flags int) (int, error)
}

func (b *NetBind) getMessages() *[]ipv6.Message {
	return b.msgsPool.Get().(*[]ipv6.Message)
}

func (b *NetBind) putMessages(msgs *[]ipv6.Message) {
	for i := range *msgs {
		// new ipv6.Message struct zeroes out fields, slices are reused
		(*msgs)[i] = ipv6.Message{
			// (*msgs)[i].Buffers doesn't need to be zeroed out, because
			// buf is assigned to (*msgs)[i].Buffers[0] after msgs popped
			// from the msgsPool. (*msgs)[i].Buffers contains only one slice
			// (new func: msgs[i].Buffers = make(net.Buffers, 1)).
			Buffers: (*msgs)[i].Buffers,
			OOB:     (*msgs)[i].OOB[:0],
		}
	}
	b.msgsPool.Put(msgs)
}

func (b *NetBind) receive(
	// batchReader interface makes this method generic,
	// so we can use it for IPv4 and IPv6
	br batchReader,
	rxOffload bool,
	bufs [][]byte,
	sizes []int, // lengths of data read into bufs
	eps []Endpoint,
) (n int, err error) {
	msgs := b.getMessages()
	defer b.putMessages(msgs)
	// bufs: buffers taken from device's messageBufs pool.
	// msgs: system call structs.
	// We "connect" them: msgs[i].Buffers[0] = bufs[i].
	// When ReadBatch() reads data, it goes directly into bufs[i].
	for i := range bufs {
		// The design "Buffers [][]byte" supports scatter/gather operations
		// (vectored I/O), even though the current code doesn't use it.
		// Potential future use:
		// Receive packet into multiple buffers
		// msg.Buffers[0] = headerBuffer[:20]    // IP/UDP headers
		// msg.Buffers[1] = payloadBuffer[:1400] // Actual data
		// One recvmsg() fills both buffers.
		(*msgs)[i].Buffers[0] = bufs[i]
		// set len = cap, so ReadBatch can read into it
		(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
	}
	var nMsgs int
	// rxOffload: NIC coalesces, app splits
	if rxOffload {
		// len(*msgs): total number of message buffers available (128).
		// BatchSize: maximum number of packets handled per read and write (128).
		// udpSegmentMaxDatagrams: maximum number of UDP packets that can be coalesced (64).
		// "BatchSize / udpSegmentMaxDatagrams": minimum number of merged packets needed.
		// readAt := 128 - (128 / 64) = 126
		// We read starting at index 126, using only 2 message buffers for reading.
		// Result: up to 2 packets containing merged data.
		// Then we split them into up to 128 individual packets.
		readAt := len(*msgs) - (BatchSize / maxUDPSegments)
		nMsgs, err = br.ReadBatch((*msgs)[readAt:], 0)
		if err != nil {
			return 0, err
		}
		nMsgs, err = splitMessages(*msgs, readAt)
		if err != nil {
			return 0, err
		}
	} else {
		nMsgs, err = br.ReadBatch(*msgs, 0)
		if err != nil {
			return 0, err
		}
	}
	for i := 0; i < nMsgs; i++ {
		msg := &(*msgs)[i]
		sizes[i] = msg.N
		if sizes[i] == 0 {
			continue
		}
		addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
		ep := &NetEndpoint{AddrPort: addrPort} // TODO: remove allocation
		getSrcFromControl(msg.OOB[:msg.NN], ep)
		eps[i] = ep
	}
	return nMsgs, nil
}

func (b *NetBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var err1, err2 error
	if b.ipv4Conn != nil {
		err1 = b.ipv4Conn.Close()
		b.ipv4Conn = nil
		b.ipv4PacketConn = nil
	}
	if b.ipv6Conn != nil {
		err2 = b.ipv6Conn.Close()
		b.ipv6Conn = nil
		b.ipv6PacketConn = nil
	}
	b.ipv4TxOffload = false
	b.ipv4RxOffload = false
	b.ipv6TxOffload = false
	b.ipv6RxOffload = false
	if err1 != nil {
		return err1
	}
	return err2
}

// SetMark sets a firewall mark on the socket.
// All packets sent through this socket will be
// tagged with the specified mark.
// Used for policy routing, packet filtering, etc.
func (b *NetBind) SetMark(mark uint32) error {
	var operr error
	if b.ipv4Conn != nil {
		rawConn, err := b.ipv4Conn.SyscallConn()
		if err != nil {
			return err
		}
		err = rawConn.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(
				int(fd),
				// indicates that socket option applies at the socket API level
				unix.SOL_SOCKET,
				// socket option mark
				unix.SO_MARK,
				int(mark),
			)
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	if b.ipv6Conn != nil {
		rawConn, err := b.ipv6Conn.SyscallConn()
		if err != nil {
			return err
		}
		err = rawConn.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(
				int(fd),
				unix.SOL_SOCKET,
				unix.SO_MARK,
				int(mark),
			)
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *NetBind) Send(bufs [][]byte, endpoint Endpoint) error {
	// bufs: buffers taken from device's messageBufs pool.
	b.mu.Lock()
	is6 := false
	conn := b.ipv4Conn
	br := batchWriter(b.ipv4PacketConn)
	offload := b.ipv4TxOffload
	if endpoint.DstIP().Is6() {
		is6 = true
		conn = b.ipv6Conn
		br = b.ipv6PacketConn
		offload = b.ipv6TxOffload
	}
	b.mu.Unlock()
	if conn == nil {
		return syscall.EAFNOSUPPORT
	}
	msgs := b.getMessages()
	defer b.putMessages(msgs)
	udpAddr := b.udpAddrPool.Get().(*net.UDPAddr)
	defer b.udpAddrPool.Put(udpAddr)
	if is6 {
		as16 := endpoint.DstIP().As16()
		// IP is []byte
		copy(udpAddr.IP, as16[:])
		// set IP len = 16
		udpAddr.IP = udpAddr.IP[:16]
	} else {
		as4 := endpoint.DstIP().As4()
		copy(udpAddr.IP, as4[:])
		udpAddr.IP = udpAddr.IP[:4]
	}
	udpAddr.Port = int(endpoint.(*NetEndpoint).Port())
	var (
		retried bool
		err     error
	)
	for {
		if offload {
			n := coalesceMessages(
				*msgs,
				bufs,
				endpoint.(*NetEndpoint),
				udpAddr,
			)
			err = send(br, (*msgs)[:n])
			// offload is checked again here because it's not protected
			// by `mu` and another thread could've modified it
			if err != nil && offload && errShouldDisableUDPGSO(err) {
				offload = false
				b.mu.Lock()
				if is6 {
					b.ipv6TxOffload = false
				} else {
					b.ipv4TxOffload = false
				}
				b.mu.Unlock()
				retried = true
				continue
			}
		} else {
			for i := range bufs {
				(*msgs)[i].Buffers[0] = bufs[i]
				(*msgs)[i].Addr = udpAddr
				setSrcControl(&(*msgs)[i].OOB, endpoint.(*NetEndpoint))
			}
			err = send(br, (*msgs)[:len(bufs)])
		}
		if retried {
			return ErrUDPGSODisabled{
				onLocalAddr: conn.LocalAddr().String(),
				RetryErr:    err,
			}
		}
		return err
	}
}

func send(bw batchWriter, msgs []ipv6.Message) error {
	var (
		n, offset int
		err       error
	)
	for {
		n, err = bw.WriteBatch(msgs[offset:], 0)
		if err != nil || n == len(msgs[offset:]) {
			break
		}
		offset += n
	}
	return err
}

func (*NetBind) ParseEndpoint(s string) (Endpoint, error) {
	addrPort, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &NetEndpoint{
		AddrPort: addrPort,
	}, nil
}

func (b *NetBind) BatchSize() int {
	return BatchSize
}

func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return
	}
	// tx: app coalesces, NIC splits
	// rx: NIC coalesces, app splits
	if err := rawConn.Control(func(fd uintptr) {
		// GetsockoptInt retrieves integer socket options.
		// IPPROTO_UDP: identifies UDP protocol in system calls. Used when
		// 	creating raw sockets or setting protocol-specific options.
		// UDP_SEGMENT: enables UDP segmentation offload. It allows
		//  the kernel to handle segmentation of large UDP datagrams
		//  into MTU-sized packets, reducing CPU overhead.
		_, errSyscall := unix.GetsockoptInt(
			int(fd),
			unix.IPPROTO_UDP,
			unix.UDP_SEGMENT,
		)
		txOffload = errSyscall == nil
		// UDP_GRO: is the receive-side counterpart to UDP_SEGMENT.
		//  It enables UDP Generic Receive Offload, allowing the kernel/NIC
		//  to reassemble multiple incoming packets into larger datagrams.
		opt, errSyscall := unix.GetsockoptInt(
			int(fd),
			unix.IPPROTO_UDP,
			unix.UDP_GRO,
		)
		// opt == 0 (disabled)
		// opt == 1 (enabled)
		rxOffload = errSyscall == nil && opt == 1
	}); err != nil {
		return false, false
	}
	return txOffload, rxOffload
}

func splitMessages(msgs []ipv6.Message, firstMsgAt int) (nPackets int, err error) {
	for i := firstMsgAt; i < len(msgs); i++ {
		msg := &msgs[i]
		if msg.N == 0 {
			return nPackets, err
		}
		var (
			gsoSize    int
			numToSplit = 1
			start      int
			end        = msg.N
		)
		gsoSize, err = getGSOSize(msg.OOB[:msg.NN])
		if err != nil {
			return nPackets, err
		}
		if gsoSize > 0 {
			// number of packets which coalesced packet will be split into
			numToSplit = (msg.N + gsoSize - 1) / gsoSize
			end = gsoSize
		}
		for j := 0; j < numToSplit; j++ {
			if nPackets > i {
				return nPackets, errors.New(
					"splitting coalesced packet resulted in overflow")
			}
			nBytes := copy(msgs[nPackets].Buffers[0], msg.Buffers[0][start:end])
			msgs[nPackets].N = nBytes
			msgs[nPackets].Addr = msg.Addr
			start = end
			end += gsoSize
			// check for smaller tail packet
			end = min(end, msg.N)
			nPackets++
		}
		// The last split case (i == nPackets-1):
		// When the last split packet happens to be placed
		// in the same buf as the original packet:
		// The data was already "moved in place" during the copy operation.
		// Zeroing msg.N = 0 would mark this buf as empty,
		// but it actually contains valid data.
		// This would cause the last packet to be lost.
		// i != nPackets-1:
		// When split packets go into different bufs:
		// The original buf no longer contains valid packet data after splitting.
		// We need to mark it as empty with `msg.N = 0` so it won't be processed
		// again, in case we don't overwrite it by placing split packet in it.
		if i != nPackets-1 {
			// It is legal for bytes to move within msg.Buffers[0] as a result
			// of splitting, so we only zero the source msg.N when it is not
			// the destination of the last split operation above.
			msg.N = 0
		}
	}
	return nPackets, nil
}

func coalesceMessages(
	msgs []ipv6.Message,
	bufs [][]byte,
	ep *NetEndpoint,
	addr *net.UDPAddr,
) (nMsgs int) {
	var (
		// index of msg we are currently coalescing into
		i = -1
		// number of packets coalesced into msgs[i]
		nPackets int
		// segmentation size of msgs[i]
		gsoSize int
		// flag indicating to start a new batch on next iteration of bufs
		endBatch bool
	)
	maxPayloadLen := maxIPv4PayloadLen
	if ep.DstIP().Is6() {
		maxPayloadLen = maxIPv6PayloadLen
	}
	for j, buf := range bufs {
		if j > 0 {
			bufLen := len(buf)
			msgLen := len(msgs[i].Buffers[0])
			available := cap(msgs[i].Buffers[0]) - msgLen
			if bufLen+msgLen <= maxPayloadLen &&
				bufLen <= gsoSize &&
				bufLen <= available &&
				nPackets < maxUDPSegments &&
				!endBatch {
				msgs[i].Buffers[0] = append(msgs[i].Buffers[0], buf...)
				// Check if it's the last buf. If it is, `continue` keyword
				// will move execution to the beginning of the for-loop,
				// and then execution will immediately exit the for-loop.
				if j == len(bufs)-1 {
					setGSOSize(&msgs[i].OOB, uint16(gsoSize))
				}
				nPackets++
				if bufLen < gsoSize {
					// A smaller than gsoSize packet on the tail
					// is legal, but it must end the batch.
					endBatch = true
				}
				continue
			}
		}
		// If we are here we are coalescing the first packet into msg[i],
		// where we are just "connecting" buf to msgs[i].Buffers[0].
		if nPackets > 1 {
			setGSOSize(&msgs[i].OOB, uint16(gsoSize))
		}
		i++
		nPackets = 1
		gsoSize = len(buf)
		// Reset prior to incrementing base since we are
		// preparing to start a new potential batch.
		endBatch = false
		// source address is set before GSO size in control
		setSrcControl(&msgs[i].OOB, ep)
		msgs[i].Buffers[0] = buf
		msgs[i].Addr = addr
	}
	return i + 1
}

func errShouldDisableUDPGSO(err error) bool {
	var serr *os.SyscallError
	if errors.As(err, &serr) {
		// EIO is returned by udp_send_skb() if the device
		// driver does not have tx checksumming enabled,
		// which is a hard requirement of UDP_SEGMENT.
		// See:
		// https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/tree/man7/udp.7?id=806eabd74910447f21005160e90957bde4db0183#n228
		// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/udp.c?h=v6.2&id=c9c3395d5e3dcc6daee66c6908354d47bf98cb0c#n942
		return serr.Err == unix.EIO
	}
	return false
}

type ErrUDPGSODisabled struct {
	onLocalAddr string
	RetryErr    error
}

func (e ErrUDPGSODisabled) Error() string {
	return fmt.Sprintf(
		"disabled UDP GSO on %s, NIC(s) may not support checksum offload",
		e.onLocalAddr,
	)
}

func (e ErrUDPGSODisabled) Unwrap() error {
	return e.RetryErr
}
