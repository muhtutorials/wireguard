package conn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	// Exceeding these values results in EMSGSIZE. They account for layer3 and
	// layer4 headers. IPv6 does not need to account for itself as the payload
	// length field is self excluding.
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
	udpSegmentMaxDatagrams = 64
)

var (
	// Verifies at compile time that *NetBind implements the Bind interface.
	// Only pointer receiver is allowed.
	_ Bind = (*NetBind)(nil)
	// Verifies at compile time that &NetEndpoint implements the Bind interface.
	// Pointer and value receivers are allowed.
	_ Endpoint = &NetEndpoint{}
	// If compilation fails here these are no longer the same underlying type.
	_ ipv6.Message = ipv4.Message{}
)

// TODO: Remove usage of ipv{4,6}.PacketConn when net.UDPConn has comparable
// methods for sending and receiving multiple datagrams per-syscall. See the
// proposal in https://github.com/golang/go/issues/45886#issuecomment-1218301564.
type NetBind struct {
	mu            sync.Mutex // protects all fields except as specified
	ipv4          *net.UDPConn
	ipv6          *net.UDPConn
	ipv4PC        *ipv4.PacketConn
	ipv6PC        *ipv6.PacketConn
	ipv4TxOffload bool
	ipv4RxOffload bool
	ipv6TxOffload bool
	ipv6RxOffload bool
	// these two fields are not guarded by mu
	udpAddrPool sync.Pool
	msgsPool    sync.Pool
	blackhole4  bool
	blackhole6  bool
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
				msgs := make([]ipv6.Message, IdealBatchSize)
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
	// AddrPort is the endpoint destination.
	netip.AddrPort
	// src is the current sticky source address and interface index, if
	// supported. Typically this is a PKTINFO structure from/for control
	// messages, see unix.PKTINFO for an example.
	// When a server has multiple IP addresses or multiple network interfaces,
	// it needs to know:
	// 	which local IP received an incoming packet
	// 	which interface received it
	// 	which source IP to use when replying
	src []byte
}

func (*NetBind) ParseEndpoint(s string) (Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &NetEndpoint{
		AddrPort: ap,
	}, nil
}

func (e *NetEndpoint) ClearSrc() {
	if e.src != nil {
		// Truncate src, no need to reallocate.
		e.src = e.src[:0]
	}
}

func (e *NetEndpoint) DstToString() string {
	return e.AddrPort.String()
}

func (e *NetEndpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

func (e *NetEndpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

func listenNet(network string, port int) (*net.UDPConn, int, error) {
	conn, err := listenConfig().ListenPacket(context.Background(), network, ":"+strconv.Itoa(port))
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
	return conn.(*net.UDPConn), udpAddr.Port, nil
}

// TODO: learn it
func (b *NetBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var err error
	var tries int
	if b.ipv4 != nil || b.ipv6 != nil {
		return nil, 0, ErrBindAlreadyOpen
	}
	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
	for {
		port := int(uport)
		var v4conn, v6conn *net.UDPConn
		var v4pc *ipv4.PacketConn
		var v6pc *ipv6.PacketConn
		v4conn, port, err = listenNet("udp4", port)
		// EAFNOSUPPORT: address family not supported by protocol
		if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
			return nil, 0, err
		}
		// Listen on the same port as we're using for ipv4.
		v6conn, port, err = listenNet("udp6", port)
		// EADDRINUSE: address already in use
		if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
			v4conn.Close()
			tries++
			continue
		}
		if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
			v4conn.Close()
			return nil, 0, err
		}
		var fns []ReceiveFunc
		if v4conn != nil {
			b.ipv4TxOffload, b.ipv4RxOffload = supportsUDPOffload(v4conn)
			if runtime.GOOS == "linux" || runtime.GOOS == "android" {
				v4pc = ipv4.NewPacketConn(v4conn)
				b.ipv4PC = v4pc
			}
			fns = append(fns, b.makeReceiveIPv4(v4pc, v4conn, b.ipv4RxOffload))
			b.ipv4 = v4conn
		}
		if v6conn != nil {
			b.ipv6TxOffload, b.ipv6RxOffload = supportsUDPOffload(v6conn)
			if runtime.GOOS == "linux" || runtime.GOOS == "android" {
				v6pc = ipv6.NewPacketConn(v6conn)
				b.ipv6PC = v6pc
			}
			fns = append(fns, b.makeReceiveIPv6(v6pc, v6conn, b.ipv6RxOffload))
			b.ipv6 = v6conn
		}
		if len(fns) == 0 {
			return nil, 0, syscall.EAFNOSUPPORT
		}
		return fns, uint16(port), nil
	}
}

func (b *NetBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var err1, err2 error
	if b.ipv4 != nil {
		err1 = b.ipv4.Close()
		b.ipv4 = nil
		b.ipv4PC = nil
	}
	if b.ipv6 != nil {
		err2 = b.ipv6.Close()
		b.ipv6 = nil
		b.ipv6PC = nil
	}
	b.ipv4TxOffload = false
	b.ipv4RxOffload = false
	b.ipv6TxOffload = false
	b.ipv6RxOffload = false
	b.blackhole4 = false
	b.blackhole6 = false
	if err1 != nil {
		return err1
	}
	return err2
}

func (b *NetBind) BatchSize() int {
	return BatchSize
}

func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return
	}
	if err := rawConn.Control(func(fd uintptr) {
		// GetsockoptInt retrieves integer socket options.
		// IPPROTO_UDP: identifies UDP protocol in system calls. Used when
		// 	creating raw sockets or setting protocol-specific options.
		// UDP_SEGMENT: enables UDP segmentation offload. It allows the kernel
		//  to handle segmentation of large UDP datagrams into MTU-sized packets,
		//  reducing CPU overhead.
		_, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		txOffload = errSyscall == nil
		// UDP_GRO: is the receive-side counterpart to UDP_SEGMENT.
		//  It enables UDP Generic Receive Offload, allowing the kernel/NIC
		//  to reassemble multiple incoming packets into larger datagrams.
		opt, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
		// opt == 0 (disabled)
		// opt == 1 (enabled)
		rxOffload = errSyscall == nil && opt == 1
	}); err != nil {
		return false, false
	}
	return txOffload, rxOffload
}

func (b *NetBind) makeReceiveIPv4(pc *ipv4.PacketConn, conn *net.UDPConn, rxOffload bool) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		return b.receiveIP(pc, conn, rxOffload, bufs, sizes, eps)
	}
}

func (b *NetBind) makeReceiveIPv6(pc *ipv6.PacketConn, conn *net.UDPConn, rxOffload bool) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		return b.receiveIP(pc, conn, rxOffload, bufs, sizes, eps)
	}
}

type batchReader interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

type batchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

func (b *NetBind) putMessages(msgs *[]ipv6.Message) {
	for i := range *msgs {
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		// new ipv6.Message zeroes out fields, slices are reused
		// TODO: why aren't Buffers cleared?
		(*msgs)[i] = ipv6.Message{Buffers: (*msgs)[i].Buffers, OOB: (*msgs)[i].OOB}
	}
	b.msgsPool.Put(msgs)
}

func (b *NetBind) getMessages() *[]ipv6.Message {
	return b.msgsPool.Get().(*[]ipv6.Message)
}

func (b *NetBind) receiveIP(
	br batchReader,
	conn *net.UDPConn,
	rxOffload bool,
	bufs [][]byte,
	sizes []int,
	eps []Endpoint,
) (n int, err error) {
	msgs := b.getMessages()
	for i := range bufs {
		(*msgs)[i].Buffers[0] = bufs[i]
		// set len = cap
		(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
	}
	defer b.putMessages(msgs)
	var numMsgs int
	if rxOffload {
		readAt := len(*msgs) - (BatchSize / udpSegmentMaxDatagrams)
		numMsgs, err = br.ReadBatch((*msgs)[readAt:], 0)
		if err != nil {
			return 0, err
		}
		numMsgs, err = splitCoalescedMessages(*msgs, readAt, getGSOSize)
		if err != nil {
			return 0, err
		}
	} else {
		numMsgs, err = br.ReadBatch(*msgs, 0)
		if err != nil {
			return 0, err
		}
	}
	for i := 0; i < numMsgs; i++ {
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
	return numMsgs, nil
}

type getGSOFunc func(control []byte) (int, error)

func splitCoalescedMessages(msgs []ipv6.Message, firstMsgAt int, getGSO getGSOFunc) (n int, err error) {
	for i := firstMsgAt; i < len(msgs); i++ {
		msg := &msgs[i]
		if msg.N == 0 {
			return n, err
		}
		var (
			gsoSize    int
			start      int
			end        = msg.N
			numToSplit = 1
		)
		gsoSize, err = getGSO(msg.OOB[:msg.NN])
		if err != nil {
			return n, err
		}
		if gsoSize > 0 {
			numToSplit = (msg.N + gsoSize - 1) / gsoSize
			end = gsoSize
		}
		for j := 0; j < numToSplit; j++ {
			if n > i {
				return n, errors.New("splitting coalesced packet resulted in overflow")
			}
			copied := copy(msgs[n].Buffers[0], msg.Buffers[0][start:end])
			msgs[n].N = copied
			msgs[n].Addr = msg.Addr
			start = end
			end += gsoSize
			if end > msg.N {
				end = msg.N
			}
			n++
		}
		if i != n-1 {
			// It is legal for bytes to move within msg.Buffers[0] as a result
			// of splitting, so we only zero the source msg len when it is not
			// the destination of the last split operation above.
			msg.N = 0
		}
	}
	return n, nil
}
