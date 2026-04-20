package tun

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/muhtutorials/wireguard/conn"
	"github.com/muhtutorials/wireguard/rwcancel"
	"golang.org/x/sys/unix"
)

type Event int

const (
	EventUp = 1 << iota
	EventDown
	EventMTUUpdate
)

var (
	// ErrTooManySegments is returned by Device.Read() when segmentation
	// overflows the length of supplied buffers. This error should not cause
	// reads to cease.
	ErrTooManySegments = errors.New("too many segments")
)

type Device interface {
	// File returns the file descriptor of the Device.
	File() *os.File
	// Read one or more packets from the Device (without any additional headers).
	// On a successful read it returns the number of packets read, and sets
	// packet lengths within the sizes slice. len(sizes) must be >= len(bufs).
	// A nonzero offset can be used to instruct the Device on where to begin
	// reading into each element of the bufs slice.
	Read(bufs [][]byte, sizes []int, offset int) (nPackets int, err error)
	// Write one or more packets to the Device (without any additional headers).
	// On a successful write it returns the number of packets written. A nonzero
	// offset can be used to instruct the Device on where to begin writing from
	// each packet contained within the bufs slice.
	Write(bufs [][]byte, offset int) (nPackets int, err error)
	// MTU returns the maximum transmission unit of the Device.
	// MTU is the largest size of packet that can
	// be transmitted over a network interface.
	MTU() (int, error)
	// Name returns the current name of the Device.
	Name() (string, error)
	// Events returns a channel of Device events.
	Events() <-chan Event
	// Close stops the Device and closes the Event channel.
	Close() error
	// BatchSize returns the preferred/max number of packets that can be read or
	// written in a single read/write call. BatchSize must not change over the
	// lifetime of a Device.
	BatchSize() int
}

const (
	// Opening this file acts as a "clone" operation,
	// instructing the kernel to create a new virtual network
	// interface (either TUN or TAP).
	// Here it's used to request a new TUN interface for the VPN tunnel.
	cloneDevicePath = "/dev/net/tun"
	// IFNAMSIZ is maximum interface name size:
	// 15 characters + 1 null terminator (16 bytes total).
	// 64: space for response (see getIfIndex).
	ifReqSize = unix.IFNAMSIZ + 64
)

type Tun struct {
	file   *os.File
	index  int32      // interface index
	errors chan error // async error handling
	events chan Event // device related events
	// netlink is a communication mechanism
	// between userspace and kernel
	netlinkSock int
	// wraps `netlinkSock` in `rwcancel.RWCancel`
	netlinkCancel           *rwcancel.RWCancel
	hackListenerClosed      sync.Mutex
	statusListenersShutdown chan struct{}
	batchSize               int
	// If true, indicates the TUN device will use a
	// virtio-net header in front of each packet.
	// This enables support of Generic Segmentation Offload (GSO)
	// and checksum offloading.
	vnetHdr   bool
	udpGSO    bool
	closeOnce sync.Once
	// used by Name method to set nameCache and nameErr
	nameOnce sync.Once
	// cached interface name
	nameCache string
	// cached error
	nameErr error
	readMu  sync.Mutex // guards readBuf
	// if vnetHdr is true every read is prefixed by virtioNetHdr
	readBuf [virtioNetHdrLen + 65535]byte
	// guards toWrite, tcpGROTable and udpGROTable
	writeMu sync.Mutex
	// Indexes of bufs to write.
	// Coalesced packets are copied into one common buf to create a "super"
	// packet so their own bufs should be ignored during write operation.
	toWrite     []int
	tcpGROTable *tcpGROTable
	udpGROTable *udpGROTable
}

// createNetlinkSocket creates a NETLINK socket
// that monitors network interface changes
func createNetlinkSocket() (int, error) {
	sock, err := unix.Socket(
		// kernel-user communication protocol
		unix.AF_NETLINK,
		// raw access + auto-close on exec
		unix.SOCK_RAW|unix.SOCK_CLOEXEC,
		// subscribe to routing/network events
		unix.NETLINK_ROUTE,
	)
	if err != nil {
		return -1, err
	}
	// RTMGRP_LINK: network link status changes
	// (interface up/down, etc.).
	// RTMGRP_IPV4_IFADDR: IPv4 address changes (add/remove).
	// RTMGRP_IPV6_IFADDR: IPv6 address changes (add/remove).
	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK |
			unix.RTMGRP_IPV4_IFADDR |
			unix.RTMGRP_IPV6_IFADDR,
	}
	if err := unix.Bind(sock, addr); err != nil {
		return -1, err
	}
	return sock, nil
}

// routineNetlinkListener monitors IFF_RUNNING flag inside IfInfomsg.
// IFF_RUNNING flag indicates whether a network interface has allocated
// its resources and is ready to transmit and receive packets.
// Then the method sends events through `tun.events` channel.
func (tun *Tun) routineNetlinkListener() {
	defer func() {
		unix.Close(tun.netlinkSock)
		// Blocks until routineHackListener returns,
		// thus releasing the lock. Only after that
		// we can close `tun.events` channel.
		tun.hackListenerClosed.Lock()
		close(tun.events)
		tun.netlinkCancel.Close()
	}()
	for {
		var (
			n   int
			err error
		)
		msg := make([]byte, 1<<16)
		for {
			n, _, _, _, err = unix.Recvmsg(tun.netlinkSock, msg[:], nil, 0)
			if err == nil || !rwcancel.RetriableError(err) {
				break
			}
			if !tun.netlinkCancel.ReadyRead() {
				tun.errors <- fmt.Errorf(
					"netlink socket closed: %w",
					err,
				)
				return
			}
		}
		if err != nil {
			tun.errors <- fmt.Errorf(
				"failed to receive netlink message: %w",
				err,
			)
			return
		}
		select {
		case <-tun.statusListenersShutdown:
			return
		default:
		}
		wasEverUp := false
		// NlMsghdr is netlink message header
		for remainder := msg[:n]; len(remainder) >= unix.SizeofNlMsghdr; {
			hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remainder[0]))
			if int(hdr.Len) > len(remainder) {
				break
			}
			switch hdr.Type {
			// end of a multipart netlink message
			case unix.NLMSG_DONE:
				remainder = []byte{}
			// new or updated network link
			case unix.RTM_NEWLINK:
				// interface information message
				info := *(*unix.IfInfomsg)(unsafe.Pointer(&remainder[unix.SizeofNlMsghdr]))
				// hdr.Len is total message size
				remainder = remainder[hdr.Len:]
				if info.Index != tun.index {
					// not our interface
					continue
				}
				// IFF_RUNNING indicates whether a network interface
				// has physical layer connectivity
				if info.Flags&unix.IFF_RUNNING != 0 {
					tun.events <- EventUp
					wasEverUp = true
				}
				if info.Flags&unix.IFF_RUNNING == 0 {
					// Don't emit EventDown before we've ever emitted EventUp.
					// This avoids a startup race with HackListener, which
					// might detect Up before we have finished reporting Down.
					if wasEverUp {
						tun.events <- EventDown
					}
				}
				tun.events <- EventMTUUpdate
			default:
				remainder = remainder[hdr.Len:]
			}
		}
	}
}

// routineHackListener continuously polls the TUN file descriptor
// by attempting a zero-byte write to detect whether the interface
// is administratively up or down, then sends corresponding
// events through `tun.events` channel.
// This is a hack to detect the administrative state (up/down)
// of a TUN interface without requiring privileged operations
// or complex netlink monitoring.
func (tun *Tun) routineHackListener() {
	defer tun.hackListenerClosed.Unlock()
	// this is needed for the detection to work across network namespaces
	last := 0
	const (
		up   = 1
		down = 2
	)
	for {
		rawConn, err := tun.file.SyscallConn()
		if err != nil {
			return
		}
		err2 := rawConn.Control(func(fd uintptr) {
			_, err = unix.Write(int(fd), nil)
		})
		if err2 != nil {
			return
		}
		switch err {
		// write is allowed, but writing 0 bytes is invalid input
		case unix.EINVAL: // invalid argument
			if last != up {
				// If the tunnel is up, it reports that write() is
				// allowed but we provided invalid data.
				tun.events <- EventUp
				last = up
			}
			// Device rejects any I/O because it's down
		case unix.EIO: // I/O error
			if last != down {
				// If the tunnel is down, it reports that no I/O
				// is possible, without checking our provided data.
				tun.events <- EventDown
				last = down
			}
		default:
			return
		}
		select {
		case <-time.After(time.Second):
			// nothing
		case <-tun.statusListenersShutdown:
			return
		}
	}
}

// C struct from Linux kernel
// struct ifreq {
// #define IFHWADDRLEN	6
// 	union
// 	{
// 		char	ifrn_name[IFNAMSIZ];		/* if name, e.g. "en0" */
// 	} ifr_ifrn;

// 	union {
// 		struct	sockaddr ifru_addr;
// 		struct	sockaddr ifru_dstaddr;
// 		struct	sockaddr ifru_broadaddr;
// 		struct	sockaddr ifru_netmask;
// 		struct  sockaddr ifru_hwaddr;
// 		short	ifru_flags;
// 		int	ifru_ivalue;
// 		int	ifru_mtu;
// 		struct  ifmap ifru_map;
// 		char	ifru_slave[IFNAMSIZ];	/* Just fits the size */
// 		char	ifru_newname[IFNAMSIZ];
// 		void __user *	ifru_data;
// 		struct	if_settings ifru_settings;
// 	} ifr_ifru;
// };

// getIfIndex returns the numeric index of a network interface
// given its name (e.g., "eth0", "wlan0")
func getIfIndex(name string) (int32, error) {
	// Creates an IPv4 socket (AF_INET).
	// Uses datagram/UDP socket type (SOCK_DGRAM).
	// SOCK_CLOEXEC ensures the socket is closed if the process executes another program.
	// The socket is only used for making IOCTL calls, not for actual networking.
	// AF_INET: Address family internet, uses IPv4 addresses.
	// SOCK_DGRAM: datagram socket (UDP).
	// SOCK_CLOEXEC: close on execute.
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var ifReq [ifReqSize]byte
	copy(ifReq[:], name)
	_, _, errno := unix.Syscall(
		// tells the kernel to perform an "input/output control" operation
		unix.SYS_IOCTL,
		uintptr(fd),
		// SIOCGIFINDEX: socket I/O control get interface index
		uintptr(unix.SIOCGIFINDEX),
		uintptr(unsafe.Pointer(&ifReq[0])),
	)
	if errno != 0 {
		return 0, errno
	}
	// extract result
	return *(*int32)(unsafe.Pointer(&ifReq[unix.IFNAMSIZ])), nil
}

func (tun *Tun) setMTU(n int) error {
	name, err := tun.Name()
	if err != nil {
		return err
	}
	// open datagram socket
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var ifReq [ifReqSize]byte
	// add name to ifReq
	copy(ifReq[:], name)
	// add MTU to ifReq right after name
	*(*uint32)(unsafe.Pointer(&ifReq[unix.IFNAMSIZ])) = uint32(n)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		// socket I/O control set interface MTU
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifReq[0])),
	)
	if errno != 0 {
		return fmt.Errorf("failed to set MTU of TUN device: %w", errno)
	}
	return nil
}

func (tun *Tun) MTU() (int, error) {
	name, err := tun.Name()
	if err != nil {
		return 0, err
	}
	// open datagram socket
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var ifReq [ifReqSize]byte
	copy(ifReq[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		// socket I/O control get interface MTU
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifReq[0])),
	)
	if errno != 0 {
		return 0, fmt.Errorf("failed to get MTU of TUN device: %w", errno)
	}
	return int(*(*int32)(unsafe.Pointer(&ifReq[unix.IFNAMSIZ]))), nil
}

func (tun *Tun) Name() (string, error) {
	// Do calls func only once
	tun.nameOnce.Do(func() {
		tun.nameCache, tun.nameErr = tun.nameSlow()
	})
	return tun.nameCache, tun.nameErr
}

func (tun *Tun) nameSlow() (string, error) {
	// TUNGETIFF is a TUN-specific IOCTL that only works on TUN device FDs.
	// That's why we use tun.file.SyscallConn().
	// unix.Socket() is used for generic network IOCTL that works on any socket FD.
	rawConn, err := tun.file.SyscallConn()
	if err != nil {
		return "", err
	}
	var ifReq [ifReqSize]byte
	var errno syscall.Errno
	if err := rawConn.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			// get TUN/TAP configuration
			uintptr(unix.TUNGETIFF),
			uintptr(unsafe.Pointer(&ifReq[0])),
		)
	}); err != nil {
		return "", fmt.Errorf(
			"failed to get name of TUN device: %w",
			err,
		)
	}
	if errno != 0 {
		return "", fmt.Errorf(
			"failed to get name of TUN device: %w",
			errno,
		)
	}
	// ByteSliceToString discards bytes from ifReq[:] slice
	// starting from C-string terminator (0 byte)
	return unix.ByteSliceToString(ifReq[:]), nil
}

// Read is used by RoutineReadFromTUN to read
// responses from websites requested by peers.
// bufs:
//
//	for i := range items {
//	    items[i] = d.NewQuOutItem()
//	    bufs[i] = items[i].buf[:]
//	}
//
// where item is popped from `quOutItems` pool and
// item.buf is popped from `messageBufs` pool.
// len(items) and len(sizes) = device.BatchSize()
// sizes: numbers of bytes read into bufs.
// offset: MessageTransportHeaderSize.
// It's the size of data preceding Content field in
// MessageTransport (uint32 + uint32 + uint64 = 16 byte):
//
//	type MessageTransport struct {
//	    Type     uint32
//	    Receiver uint32
//	    Counter  uint64
//	    Content  []byte
//	}
func (tun *Tun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	tun.readMu.Lock()
	defer tun.readMu.Unlock()
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		// regular packet buf
		readBuf := bufs[0][offset:]
		if tun.vnetHdr {
			// packet buf prefixed by virtioNetHdr
			readBuf = tun.readBuf[:]
		}
		n, err := tun.file.Read(readBuf)
		// EBADFD: bad file descriptor
		if errors.Is(err, syscall.EBADFD) {
			err = os.ErrClosed
		}
		if err != nil {
			return 0, err
		}
		if tun.vnetHdr {
			// Coalesced packets prefixed by virtioNetHdr were read.
			// handleVirtioRead will split them into bufs.
			return handleVirtioRead(readBuf[:n], bufs, sizes, offset)
		} else {
			// one regular packet was read
			sizes[0] = n
			return 1, nil
		}
	}
}

// handleVirtioRead splits `readBuf` into `bufs`, leaving offset
// bytes at the front of each buffer. It mutates sizes
// to reflect the size of each element of `bufs`,
// and returns the number of packets read.
func handleVirtioRead(
	// buf containing virtioNetHdr and coalesced packets
	readBuf []byte,
	bufs [][]byte,
	sizes []int,
	offset int,
) (int, error) {
	// decode bytes from readBuf into hdr
	var hdr virtioNetHdr
	if err := hdr.decode(readBuf); err != nil {
		return 0, err
	}
	// move the "cursor"
	readBuf = readBuf[virtioNetHdrLen:]
	// VIRTIO_NET_HDR_GSO_NONE:
	// 	Generic segmentation offload (GSO) is not supported
	// 	for network packets. No need to split them.
	// 	As slice goes in, so it goes out!
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_NONE {
		// VIRTIO_NET_HDR_F_NEEDS_CSUM: packet needs checksum computation
		if hdr.flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			// We are responsible for computing the checksum starting
			// at hdr.csumStart and placing it at hdr.csumOffset.
			if err := gsoNoneChecksum(
				readBuf,
				hdr.csumStart,
				hdr.csumOffset,
			); err != nil {
				return 0, err
			}
		}
		if len(readBuf) > len(bufs[0][offset:]) {
			return 0, fmt.Errorf(
				"read length %d overflows bufs element length %d",
				len(readBuf),
				len(bufs[0][offset:]),
			)
		}
		// one regular packet is read
		n := copy(bufs[0][offset:], readBuf)
		sizes[0] = n
		return 1, nil
	}
	// VIRTIO_NET_HDR_GSO_TCPV4:
	// 	TCP over IPv4 packet that needs segmentation by the host hardware
	// VIRTIO_NET_HDR_GSO_TCPV6:
	// 	TCP over IPv6 packet that needs segmentation by the host hardware
	// VIRTIO_NET_HDR_GSO_UDP_L4:
	// 	UDP packet that needs segmentation by the host hardware
	// 	at the transport layer (L4)
	if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 &&
		hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 &&
		hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		return 0, fmt.Errorf("unsupported virtio GSO type: %d", hdr.gsoType)
	}
	// extract IP version from packet
	ipVersion := readBuf[0] >> 4
	switch ipVersion {
	case 4:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 &&
			hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf(
				"IP header version: %d, GSO type: %d",
				ipVersion,
				hdr.gsoType,
			)
		}
	case 6:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 &&
			hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf(
				"IP header version: %d, GSO type: %d",
				ipVersion,
				hdr.gsoType,
			)
		}
	default:
		return 0, fmt.Errorf("invalid IP header version: %d", ipVersion)
	}
	// Don't trust hdr.hdrLen from the kernel as it can be equal to the length
	// of the entire first packet when the kernel is handling it as part of a
	// FORWARD path. Instead, parse the transport header length and add it onto
	// csumStart, which is synonymous for IP header length.
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		hdr.hdrLen = hdr.csumStart + 8 // iphLen + udphLen
	} else {
		// `csumStart+12` is offset of `data offset` field inside TCP header.
		// `data offset` field is TCP header length.
		if len(readBuf) <= int(hdr.csumStart+12) {
			return 0, errors.New("packet is too short")
		}
		// Extract `data offset` field.
		// Value stored in the `data offset` field must be multiplied
		// by 4 to get the actual header length in bytes.
		tcpHLen := uint16(readBuf[hdr.csumStart+12] >> 4 * 4)
		if tcpHLen < 20 || tcpHLen > 60 {
			// TCP header must be between 20 and 60 bytes in length.
			return 0, fmt.Errorf("TCP header length is invalid: %d", tcpHLen)
		}
		hdr.hdrLen = hdr.csumStart + tcpHLen
	}
	if len(readBuf) < int(hdr.hdrLen) {
		return 0, fmt.Errorf(
			"length of packet (%d) < virtioNetHdr.hdrLen (%d)",
			len(readBuf),
			hdr.hdrLen,
		)
	}
	// TODO: defensive programming?
	if hdr.hdrLen < hdr.csumStart {
		return 0, fmt.Errorf(
			"virtioNetHdr.hdrLen (%d) < virtioNetHdr.csumStart (%d)",
			hdr.hdrLen,
			hdr.csumStart,
		)
	}
	checksumAt := int(hdr.csumStart + hdr.csumOffset)
	// check if checksum field is inside `readBuf`
	if checksumAt+1 >= len(readBuf) {
		return 0, fmt.Errorf(
			"end of checksum offset (%d) exceeds packet length (%d)",
			checksumAt+1,
			len(readBuf),
		)
	}
	return gsoSplit(readBuf, hdr, bufs, sizes, offset, ipVersion == 6)
}

// Write is used by RoutineSequentialReceiver to write
// requests to websites sent by peers.
// bufs:
// bufs := make([][]byte, 0, maxBatchSize)
// bufs = append(bufs, item.buf[:MessageTransportOffsetContent+len(item.packet)])
// item: created in RoutineReceiveIncoming.
// offset: MessageTransportOffsetContent.
// It's the size of data preceding Content field in
// MessageTransport (uint32 + uint32 + uint64 = 16 byte):
//
//	type MessageTransport struct {
//	    Type     uint32
//	    Receiver uint32
//	    Counter  uint64
//	    Content  []byte
//	}
//
// It's passed to the method so it can be used for encoding
// virtioNetHdr, which is written to message header:
// [MessageTransportHeaderSize(offset):Content(packet)]
func (tun *Tun) Write(bufs [][]byte, offset int) (int, error) {
	tun.writeMu.Lock()
	defer func() {
		tun.toWrite = tun.toWrite[:0]
		tun.tcpGROTable.reset()
		tun.udpGROTable.reset()
		tun.writeMu.Unlock()
	}()
	var (
		total int
		errs  error
	)
	if tun.vnetHdr {
		if err := handleGRO(
			bufs,
			offset,
			tun.tcpGROTable,
			tun.udpGROTable,
			tun.udpGSO,
			&tun.toWrite,
		); err != nil {
			return 0, err
		}
		// Move back `offset` by `virtioNetHdrLen` to write `virtioNetHdr`,
		// which was encoded in front of packet in `handleGRO`.
		offset -= virtioNetHdrLen
	} else {
		// GRO (coalescing of packets) is not supported.
		// We write them as they are.
		for i := range bufs {
			tun.toWrite = append(tun.toWrite, i)
		}
	}
	for _, i := range tun.toWrite {
		n, err := tun.file.Write(bufs[i][offset:])
		// EBADFD: bad file descriptor
		if errors.Is(err, syscall.EBADFD) {
			return total, os.ErrClosed
		}
		if err != nil {
			errs = errors.Join(errs, err)
		} else {
			total += n
		}
	}
	return total, errs
}

func (tun *Tun) File() *os.File {
	return tun.file
}

func (tun *Tun) Events() <-chan Event {
	return tun.events
}

func (tun *Tun) BatchSize() int {
	return tun.batchSize
}

func (tun *Tun) Close() error {
	var err1, err2 error
	tun.closeOnce.Do(func() {
		if tun.statusListenersShutdown != nil {
			close(tun.statusListenersShutdown)
			if tun.netlinkCancel != nil {
				err1 = tun.netlinkCancel.Cancel()
			}
		} else if tun.events != nil {
			close(tun.events)
		}
		err2 = tun.file.Close()
	})
	if err1 != nil {
		return err1
	}
	return err2
}

// TUN_F_CSUM: checksum offloading.
// Offloads IP/TCP/UDP checksum calculation to hardware.
// Without this: kernel calculates checksums in software.
// With this: NIC hardware calculates checksums, and thus
// reduces CPU usage for checksum computation.
//
// TSO4: TCP segmentation offloading for IPv4.
// TSO6: TCP segmentation offloading for IPv6.
// USO4: UDP segmentation offloading for IPv4.
// USO6: UDP segmentation offloading for IPv6.
// Allows sending large TCP/UDP packets (>MTU) and letting NIC split them.
// Without offloading: kernel splits large TCP packets into MTU-sized fragments.
// With offloading: kernel sends one large packet, NIC hardware splits it,
// and thus reduces CPU overhead for packet segmentation.
const (
	tunTCPOffloads = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
	tunUDPOffloads = unix.TUN_F_USO4 | unix.TUN_F_USO6
)

// CreateTUN creates a Device with the provided name and MTU.
func CreateTUN(name string, mtu int) (Device, error) {
	// O_RDWR: open for reading and writing.
	// O_CLOEXEC: automatically close the file descriptor when exec is called.
	fd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf(
				"CreateTUN (%q) failed; %s does not exist",
				name,
				cloneDevicePath,
			)
		}
		return nil, err
	}
	ifReq, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	// IFF_VNET_HDR enables the "tun status hack" via routineHackListener()
	// where a null write will return EINVAL indicating the TUN is up.
	// IFF_TUN: creates a layer 3 TUN device (IP packets).
	// IFF_NO_PI: no packet information header. Without this flag,
	// 	TUN/TAP prepends a 4-byte header to each packet:
	// 	[flags (2 bytes)][proto (2 bytes)][packet data]
	// IFF_VNET_HDR: enables virtio-net headers for hardware
	// 	offloading. Required for TSO, GSO and checksum offloading.
	ifReq.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	// TUNSETIFF: create/attach a TUN/TAP device.
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifReq); err != nil {
		return nil, err
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// open, ioctl, nonblock must happen prior to handing
	// it to netpoll as below this line
	file := os.NewFile(uintptr(fd), cloneDevicePath)
	return CreateTUNFromFile(file, mtu)
}

// CreateTUNFromFile creates a Device from an os.File with the provided MTU.
func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	tun := &Tun{
		file:                    file,
		events:                  make(chan Event, 5),
		errors:                  make(chan error, 5),
		statusListenersShutdown: make(chan struct{}),
		tcpGROTable:             newTCPGROTable(),
		udpGROTable:             newUDPGROTable(),
		toWrite:                 make([]int, 0, conn.BatchSize),
	}
	name, err := tun.Name()
	if err != nil {
		return nil, err
	}
	if err = tun.initFromFlags(name); err != nil {
		return nil, err
	}
	// start event listener
	tun.index, err = getIfIndex(name)
	if err != nil {
		return nil, err
	}
	tun.netlinkSock, err = createNetlinkSocket()
	if err != nil {
		return nil, err
	}
	tun.netlinkCancel, err = rwcancel.New(tun.netlinkSock)
	if err != nil {
		unix.Close(tun.netlinkSock)
		return nil, err
	}
	// unlocked in routineHackListener
	tun.hackListenerClosed.Lock()
	go tun.routineNetlinkListener()
	go tun.routineHackListener()
	if err = tun.setMTU(mtu); err != nil {
		unix.Close(tun.netlinkSock)
		return nil, err
	}
	return tun, nil
}

// initFromFlags checks if TUN supports hardware offloading
func (tun *Tun) initFromFlags(name string) error {
	rawConn, err := tun.file.SyscallConn()
	if err != nil {
		return err
	}
	if err := rawConn.Control(func(fd uintptr) {
		ifReq, err := unix.NewIfreq(name)
		if err != nil {
			return
		}
		// TUNGETIFF: retrieve the configuration and flags of a TUN/TAP
		if err = unix.IoctlIfreq(int(fd), unix.TUNGETIFF, ifReq); err != nil {
			return
		}
		resp := ifReq.Uint16()
		// IFF_VNET_HDR: indicates the TUN/TAP device will use a
		// virtio-net header in front of each packet. This enables
		// communication of offloading metadata between kernel and userspace.
		// Allows userspace programs to handle hardware offloading.
		if resp&unix.IFF_VNET_HDR != 0 {
			// tunTCPOffloads were added in Linux v2.6.
			// We require their support if IFF_VNET_HDR is set.
			// TUNSETOFFLOAD is a Linux ioctl command used to enable or
			// disable hardware offloading features on TUN/TAP devices.
			if err = unix.IoctlSetInt(
				int(fd),
				unix.TUNSETOFFLOAD,
				tunTCPOffloads,
			); err != nil {
				return
			}
			tun.vnetHdr = true
			tun.batchSize = conn.BatchSize
			// tunUDPOffloads were added in Linux v6.2. We do not return an
			// error if they are unsupported at runtime.
			tun.udpGSO = unix.IoctlSetInt(
				int(fd),
				unix.TUNSETOFFLOAD,
				tunTCPOffloads|tunUDPOffloads,
			) == nil
		} else {
			tun.batchSize = 1
		}
	}); err != nil {
		return err
	}
	return err
}
