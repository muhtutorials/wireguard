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

type Device interface {
	// File returns the file descriptor of the device.
	File() *os.File
	// Read one or more packets from the Device (without any additional headers).
	// On a successful read it returns the number of packets read, and sets
	// packet lengths within the sizes slice. len(sizes) must be >= len(bufs).
	// A nonzero offset can be used to instruct the Device on where to begin
	// reading into each element of the bufs slice.
	Read(bufs [][]byte, sizes []int, offset int) (n int, err error)
	// Write one or more packets to the device (without any additional headers).
	// On a successful write it returns the number of packets written. A nonzero
	// offset can be used to instruct the Device on where to begin writing from
	// each packet contained within the bufs slice.
	Write(bufs [][]byte, offset int) (int, error)
	// MTU returns the MTU of the Device.
	// MTU (Maximum Transmission Unit) is the largest size packet
	// or frame that can be transmitted over a network interface
	MTU() (int, error)
	// Name returns the current name of the Device.
	Name() (string, error)
	// Events returns a channel of type Event, which is fed Device events.
	Events() <-chan Event
	// Close stops the Device and closes the Event channel.
	Close() error
	// BatchSize returns the preferred/max number of packets that can be read or
	// written in a single read/write call. BatchSize must not change over the
	// lifetime of a Device.
	BatchSize() int
}

const (
	cloneDevicePath = "/dev/net/tun"
	// IFNAMSIZ is maximum interface name size:
	// 15 characters + 1 null terminator (16 bytes total).
	// TODO: why do we add 64?
	ifReqSize = unix.IFNAMSIZ + 64
)

type Tun struct {
	file   *os.File
	index  int32      // if index
	errors chan error // async error handling
	events chan Event // device related events
	// netlink is a communication mechanism between
	// userspace processes and the Linux kernel
	netlinkSock             int
	netlinkCancel           *rwcancel.RWCancel
	hackListenerClosed      sync.Mutex
	statusListenersShutdown chan struct{}
	batchSize               int
	vnetHdr                 bool
	udpGSO                  bool

	closeOnce sync.Once

	nameOnce  sync.Once // guards calling initNameCache, which sets following fields
	nameCache string    // name of interface
	nameErr   error

	readMu  sync.Mutex                    // readMu guards readBuff
	readBuf [virtioNetHdrLen + 65535]byte // if vnetHdr every read is prefixed by virtioNetHdr

	writeMu     sync.Mutex // writeMu guards toWrite, tcpGROTable
	toWrite     []int      // bufs at indexes to write
	tcpGROTable *tcpGROTable
	udpGROTable *udpGROTable
}

// createNetlinkSocket creates a NETLINK socket that monitors network interface changes
func createNetlinkSocket() (int, error) {
	sock, err := unix.Socket(
		unix.AF_NETLINK,                 // kernel-user communication protocol
		unix.SOCK_RAW|unix.SOCK_CLOEXEC, // raw access + auto-close on exec
		unix.NETLINK_ROUTE,              // subscribe to routing/network events
	)
	if err != nil {
		return -1, err
	}
	// RTMGRP_LINK: network link status changes (interface up/down, etc.)
	// RTMGRP_IPV4_IFADDR: IPv4 address changes (add/remove)
	// RTMGRP_IPV6_IFADDR: IPv6 address changes (add/remove)
	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR,
	}
	if err := unix.Bind(sock, addr); err != nil {
		return -1, err
	}
	return sock, nil
}

func (tun *Tun) routineNetlinkListener() {
	defer func() {
		unix.Close(tun.netlinkSock)
		tun.hackListenerClosed.Lock()
		close(tun.events)
		tun.netlinkCancel.Close()
	}()
	for {
		msg := make([]byte, 1<<16)
		var n int
		var err error
		for {
			n, _, _, _, err = unix.Recvmsg(tun.netlinkSock, msg[:], nil, 0)
			if err == nil || !rwcancel.RetryAfterError(err) {
				break
			}
			if !tun.netlinkCancel.ReadyRead() {
				tun.errors <- fmt.Errorf("netlink socket closed: %w", err)
				return
			}
		}
		if err != nil {
			tun.errors <- fmt.Errorf("failed to receive netlink message: %w", err)
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
				// IFF_RUNNING indicates whether a network interface has physical layer connectivity
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
		case unix.EINVAL: // invalid argument
			if last != up {
				// If the tunnel is up, it reports that write() is
				// allowed but we provided invalid data.
				tun.events <- EventUp
				last = up
			}
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
	// AF_INET: Address family internet. Uses IPv4 addresses.
	// SOCK_DGRAM: connectionless, unreliable datagram socket (UDP).
	// SOCK_CLOEXEC: close on execute.
	// Creates an IPv4 socket (AF_INET).
	// Uses datagram/UDP socket type (SOCK_DGRAM).
	// SOCK_CLOEXEC ensures the socket is closed if the process executes another program.
	// The socket is only used for making ioctl calls, not for actual networking.
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
	// fd: your "network administrator's access badge"
	// ioctl: the "request form" you submit
	// interface name in ifReq: the actual network interface you want to modify
	// Uses the ioctl system call with SIOCGIFINDEX command.
	// Passes the socket file descriptor and pointer to the ifReq structure.
	// The kernel fills in the interface index in the structure.
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
	// do ioctl call
	var ifReq [ifReqSize]byte
	copy(ifReq[:], name)
	*(*uint32)(unsafe.Pointer(&ifReq[unix.IFNAMSIZ])) = uint32(n)
	// fd: your "network administrator's access badge"
	// ioctl: the "request form" you submit
	// interface name in ifReq: the actual network interface you want to modify
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
	// do ioctl call
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
	tun.nameOnce.Do(func() {
		tun.nameCache, tun.nameErr = tun.nameSlow()
	})
	return tun.nameCache, tun.nameErr
}

func (tun *Tun) nameSlow() (string, error) {
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
		return "", fmt.Errorf("failed to get name of TUN device: %w", err)
	}
	if errno != 0 {
		return "", fmt.Errorf("failed to get name of TUN device: %w", errno)
	}
	// ByteSliceToString discards bytes from ifReq[:] slice
	// starting from C-string terminator (0 byte)
	return unix.ByteSliceToString(ifReq[:]), nil
}

func (tun *Tun) Write(bufs [][]byte, offset int) (int, error) {
	tun.writeMu.Lock()
	defer func() {
		tun.tcpGROTable.reset()
		tun.udpGROTable.reset()
		tun.writeMu.Unlock()
	}()
	var (
		errs  error
		total int
	)
	tun.toWrite = tun.toWrite[:0]
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
		offset -= virtioNetHdrLen
	} else {
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

// handleVirtioRead splits `in` into `bufs`, leaving offset bytes at the front of
// each buffer. It mutates sizes to reflect the size of each element of `bufs`,
// and returns the number of packets read.
func handleVirtioRead(in []byte, bufs [][]byte, sizes []int, offset int) (int, error) {
	var hdr virtioNetHdr
	if err := hdr.decode(in); err != nil {
		return 0, err
	}
	in = in[virtioNetHdrLen:]
	// VIRTIO_NET_HDR_GSO_NONE: no generic segmentation offloading (GSO)
	// is being used for a network packet.
	// As slice goes in, so it goes out!
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_NONE {
		// VIRTIO_NET_HDR_F_NEEDS_CSUM: packet needs checksum computation
		if hdr.flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			// This means CHECKSUM_PARTIAL in skb context. We are responsible
			// for computing the checksum starting at hdr.csumStart and placing
			// at hdr.csumOffset.
			if err := gsoNoneChecksum(in, hdr.csumStart, hdr.csumOffset); err != nil {
				return 0, err
			}
		}
		if len(in) > len(bufs[0][offset:]) {
			return 0, fmt.Errorf("read len %d overflows bufs element len %d", len(in), len(bufs[0][offset:]))
		}
		n := copy(bufs[0][offset:], in)
		sizes[0] = n
		return 1, nil
	}
	// VIRTIO_NET_HDR_GSO_TCPV4: TCP over IPv4 packet that needs segmentation by the host hardware
	// VIRTIO_NET_HDR_GSO_TCPV6: TCP over IPv6 packet that needs segmentation by the host hardware
	// VIRTIO_NET_HDR_GSO_UDP_L4: UDP packet that needs segmentation by the host hardware
	// at the transport layer (L4)
	if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		return 0, fmt.Errorf("unsupported virtio GSO type: %d", hdr.gsoType)
	}
	// extracts IP version
	ipVersion := in[0] >> 4
	switch ipVersion {
	case 4:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	case 6:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	default:
		return 0, fmt.Errorf("invalid ip header version: %d", ipVersion)
	}
	// Don't trust hdr.hdrLen from the kernel as it can be equal to the length
	// of the entire first packet when the kernel is handling it as part of a
	// FORWARD path. Instead, parse the transport header length and add it onto
	// csumStart, which is synonymous for IP header length.
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		hdr.hdrLen = hdr.csumStart + 8 // iphLen + udphLen (8)
	} else {
		// `csumStart+12` is data offset field (header length)
		if len(in) <= int(hdr.csumStart+12) {
			return 0, errors.New("packet is too short")
		}
		tcpHLen := uint16(in[hdr.csumStart+12] >> 4 * 4)
		if tcpHLen < 20 || tcpHLen > 60 {
			// A TCP header must be between 20 and 60 bytes in length.
			return 0, fmt.Errorf("tcp header len is invalid: %d", tcpHLen)
		}
		hdr.hdrLen = hdr.csumStart + tcpHLen
	}
	if len(in) < int(hdr.hdrLen) {
		return 0, fmt.Errorf("length of packet (%d) < virtioNetHdr.hdrLen (%d)", len(in), hdr.hdrLen)
	}
	// NOTE: redundant defensive programming?
	if hdr.hdrLen < hdr.csumStart {
		return 0, fmt.Errorf("virtioNetHdr.hdrLen (%d) < virtioNetHdr.csumStart (%d)", hdr.hdrLen, hdr.csumStart)
	}
	checksumAt := int(hdr.csumStart + hdr.csumOffset)
	// check if checksum field is inside `in`
	if checksumAt+1 >= len(in) {
		return 0, fmt.Errorf("end of checksum offset (%d) exceeds packet length (%d)", checksumAt+1, len(in))
	}
	return gsoSplit(in, hdr, bufs, sizes, offset, ipVersion == 6)
}

func (tun *Tun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	tun.readMu.Lock()
	defer tun.readMu.Unlock()
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		readBuf := bufs[0][offset:]
		if tun.vnetHdr {
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
			return handleVirtioRead(readBuf[:n], bufs, sizes, offset)
		} else {
			sizes[0] = n
			return 1, nil
		}
	}
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
		// IFF_VNET_HDR: indicates the TUN/TAP device will use a virtio-net header in front of each packet.
		// This enables communication of offloading metadata between kernel and userspace.
		// Allows userspace programs to handle hardware offloading.
		if resp&unix.IFF_VNET_HDR != 0 {
			// tunTCPOffloads were added in Linux v2.6. We require their support
			// if IFF_VNET_HDR is set.
			// TUNSETOFFLOAD is a Linux ioctl command used to enable or
			// disable hardware offloading features on TUN/TAP devices.
			if err = unix.IoctlSetInt(int(fd), unix.TUNSETOFFLOAD, tunTCPOffloads); err != nil {
				return
			}
			tun.vnetHdr = true
			tun.batchSize = conn.BatchSize
			// tunUDPOffloads were added in Linux v6.2. We do not return an
			// error if they are unsupported at runtime.
			tun.udpGSO = unix.IoctlSetInt(int(fd), unix.TUNSETOFFLOAD, tunTCPOffloads|tunUDPOffloads) == nil
		} else {
			tun.batchSize = 1
		}
	}); err != nil {
		return err
	}
	return err
}

// CreateTUN creates a Device with the provided name and MTU.
func CreateTUN(name string, mtu int) (Device, error) {
	// O_RDWR: open for reading and writing.
	// O_CLOEXEC: automatically close the file descriptor when exec is called.
	fd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("CreateTUN (%q) failed; %s does not exist", name, cloneDevicePath)
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
	// 	offloading. Required for TSO, checksum offloading, GSO.
	ifReq.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	// TUNSETIFF: create/attach a TUN/TAP device.
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifReq); err != nil {
		return nil, err
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// open, ioctl, nonblock must happen prior to handing it to netpoll as below this line
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
	tun.hackListenerClosed.Lock()
	go tun.routineNetlinkListener()
	go tun.routineHackListener() // cross namespace
	if err = tun.setMTU(mtu); err != nil {
		unix.Close(tun.netlinkSock)
		return nil, err
	}
	return tun, nil
}

// CreateUnmonitoredTUNFromFD creates a Device from the provided file
// descriptor.
func CreateUnmonitoredTUNFromFD(fd int) (Device, string, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, "", err
	}
	// "/dev/tun" is for legacy compatibility?
	file := os.NewFile(uintptr(fd), "/dev/tun")
	tun := &Tun{
		file:        file,
		events:      make(chan Event, 5),
		errors:      make(chan error, 5),
		tcpGROTable: newTCPGROTable(),
		udpGROTable: newUDPGROTable(),
		toWrite:     make([]int, 0, conn.BatchSize),
	}
	name, err := tun.Name()
	if err != nil {
		return nil, "", err
	}
	if err = tun.initFromFlags(name); err != nil {
		return nil, "", err
	}
	return tun, name, err
}
