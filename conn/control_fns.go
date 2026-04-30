package conn

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// UDP socket read/write buffer size (7MB). The value of 7MB
// is chosen as it is the maximum supported by a default
// configuration of macOS. Some platforms will silently
// clamp the value to other maximums, such as linux
// clamping to net.core.{r,w}mem_max.
const socketBufSize = 7 << 20

// controlFn is the callback function signature from
// net.ListenConfig.Control. It is used to apply platform
// specific configuration to the socket prior to bind.
type controlFn func(network, address string, c syscall.RawConn) error

// controlFns is a list of functions that are called from
// the listen config that can apply socket options.
var controlFns = []controlFn{}

// listenConfig returns a net.ListenConfig that applies the
// controlFns to the socket prior to bind. This is used to
// apply socket buffer sizing and packet information OOB
// configuration for sticky sockets.
// net.ListenConfig allows to set a Control function that
// executes before the socket is bound. This grants low-level
// access to set socket options that must be configured early.
// net.Listen() and net.ListenPacket() functions are used
// in regular cases.
func listenConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			for _, fn := range controlFns {
				if err := fn(network, address, c); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func init() {
	controlFns = append(controlFns,
		// Attempt to set the socket buffer size beyond net.core.{r,w}mem_max
		// by using SO_*BUFFORCE. This requires CAP_NET_ADMIN, and is allowed
		// here to fail silently - the result of failure is lower performance
		// on very fast links or high latency links.
		func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// set up to *mem_max
				_ = unix.SetsockoptInt(
					int(fd),
					// option applies at the socket level
					unix.SOL_SOCKET,
					// size of the receive buffer for a socket
					unix.SO_RCVBUF,
					socketBufSize,
				)
				_ = unix.SetsockoptInt(
					int(fd),
					unix.SOL_SOCKET,
					// size of the send buffer for a socket
					unix.SO_SNDBUF,
					socketBufSize,
				)
				// set beyond *mem_max if CAP_NET_ADMIN
				_ = unix.SetsockoptInt(
					int(fd),
					unix.SOL_SOCKET,
					// override system-wide limits on the
					// receive buffer size for a socket
					unix.SO_RCVBUFFORCE,
					socketBufSize,
				)
				_ = unix.SetsockoptInt(
					int(fd),
					unix.SOL_SOCKET,
					// override system-wide limits on the
					// send buffer size for a socket
					unix.SO_SNDBUFFORCE,
					socketBufSize,
				)
			})
		},
		// Enable receiving of the packet information
		// (IP_PKTINFO for IPv4, IPV6_PKTINFO for IPv6)
		// that is used to implement sticky socket support.
		func(network, address string, c syscall.RawConn) error {
			var err error
			switch network {
			case "udp4":
				c.Control(func(fd uintptr) {
					err = unix.SetsockoptInt(
						int(fd),
						// Internet Protocol level in the socket options
						unix.IPPROTO_IP,
						// enables receiving and sending detailed
						// packet information for IPv4 sockets
						unix.IP_PKTINFO,
						1,
					)
				})
			case "udp6":
				c.Control(func(fd uintptr) {
					if err = unix.SetsockoptInt(
						int(fd),
						// IPv6 socket options
						unix.IPPROTO_IPV6,
						// enables reception of destination address and interface
						// information with received packets for IPv6 sockets
						unix.IPV6_RECVPKTINFO,
						1,
					); err != nil {
						return
					}
					err = unix.SetsockoptInt(
						int(fd),
						unix.IPPROTO_IPV6,
						// controls whether an IPv6 socket can also handle
						// IPv4 connections via IPv4-mapped IPv6 addresses
						unix.IPV6_V6ONLY,
						1,
					)
				})
			default:
				err = fmt.Errorf(
					"unhandled network: %s: %w",
					network,
					// invalid argument
					unix.EINVAL,
				)
			}
			return err
		},
		// attempt to enable UDP_GRO
		func(network, address string, c syscall.RawConn) error {
			// Kernels below 5.12 are missing 98184612aca0 ("net:
			// udp: Add support for getsockopt(..., ..., UDP_GRO,
			// ..., ...);"), which means we can't read this back
			// later. We could pipe the return value through to
			// the rest of the code, but UDP_GRO is kind of buggy
			// anyway, so just gate this here.
			major, minor := kernelVersion()
			if major < 5 || (major == 5 && minor < 12) {
				return nil
			}
			c.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(
					int(fd),
					// specifies UDP inside IPv4 header
					unix.IPPROTO_UDP,
					unix.UDP_GRO,
					1,
				)
			})
			return nil
		},
	)
}

// taken from go/src/internal/syscall/unix/kernel_version_linux.go
func kernelVersion() (major, minor int) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return
	}
	var (
		// first two numbers in uname.Release
		values   [2]int
		value, i int
	)
	for _, c := range uname.Release {
		if '0' <= c && c <= '9' {
			// convert char to int
			value = (value * 10) + int(c-'0')
		} else {
			// Note that we're assuming N.N.N here.
			// If we see anything else, we are likely to mis-parse it.
			values[i] = value
			i++
			if i >= len(values) {
				break
			}
			value = 0
		}
	}
	return values[0], values[1]
}
