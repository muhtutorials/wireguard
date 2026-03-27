package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/muhtutorials/wireguard/ipc"
)

type IPCError struct {
	code int64 // error code
	err  error // underlying/wrapped error
}

func (s IPCError) Error() string {
	return fmt.Sprintf("IPC error %d: %v", s.code, s.err)
}

func (s IPCError) ErrorCode() int64 {
	return s.code
}

func (s IPCError) Unwrap() error {
	return s.err
}

func ipcErrorf(code int64, msg string, args ...any) *IPCError {
	return &IPCError{code: code, err: fmt.Errorf(msg, args...)}
}

var bufPool = &sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// IpcGetOperation implements the WireGuard configuration protocol "get" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (d *Device) IpcGetOperation(w io.Writer) error {
	d.ipcMu.RLock()
	defer d.ipcMu.RUnlock()
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	sendf := func(format string, args ...any) {
		fmt.Fprintf(buf, format, args...)
		buf.WriteByte('\n')
	}
	// Converts a 32-byte binary key into a line of text like:
	// private_key=3c7e1a2b9f4d8e6a1b3c5d7e9f0a2b4c6d8e0f1a2b3c4d5e6f7a8b9c0d1e2f3a
	keyf := func(prefix string, key *[32]byte) {
		// '+2': 1 for '=' and 1 for '\n'
		buf.Grow(len(prefix) + len(key)*2 + 2)
		buf.WriteString(prefix)
		buf.WriteByte('=')
		// Byte value: 0x3c
		// Binary: 0011 1100
		//         └─┬┘ └─┬┘
		//         high  low
		//        (0x3) (0xc)
		// Hex string: '3'          'c'
		//              ↑            ↑
		//          first byte  second byte
		const hex = "0123456789abcdef"
		for i := range len(key) {
			high := key[i] >> 4
			low := key[i] & 0xf
			buf.WriteByte(hex[high])
			buf.WriteByte(hex[low])
		}
		buf.WriteByte('\n')
	}
	func() {
		// lock required resources
		d.net.RLock()
		defer d.net.RUnlock()
		d.keys.RLock()
		defer d.keys.RUnlock()
		d.peers.RLock()
		defer d.peers.RUnlock()
		// serialize device related values
		if !d.keys.privateKey.IsZero() {
			keyf("private_key", (*[32]byte)(&d.keys.privateKey))
		}
		if d.net.port != 0 {
			sendf("listen_port=%d", d.net.port)
		}
		if d.net.fwmark != 0 {
			sendf("fwmark=%d", d.net.fwmark)
		}
		for _, peer := range d.peers.val {
			// serialize peer state
			peer.handshake.RLock()
			keyf("public_key", (*[32]byte)(&peer.handshake.remoteStatic))
			keyf("preshared_key", (*[32]byte)(&peer.handshake.presharedKey))
			peer.handshake.RUnlock()
			sendf("protocol_version=1")
			peer.endpoint.Lock()
			if peer.endpoint.val != nil {
				sendf("endpoint=%s", peer.endpoint.val.DstToString())
			}
			peer.endpoint.Unlock()
			nano := peer.lastHandshake.Load()
			secs := nano / time.Second.Nanoseconds()
			nano %= time.Second.Nanoseconds()
			sendf("last_handshake_time_sec=%d", secs)
			sendf("last_handshake_time_nsec=%d", nano)
			sendf("tx_bytes=%d", peer.txBytes.Load())
			sendf("rx_bytes=%d", peer.rxBytes.Load())
			sendf("keepalive_interval=%d", peer.KeepaliveInterval.Load())
			d.router.PeerNodes(peer, func(prefix netip.Prefix) bool {
				sendf("allowed_ip=%s", prefix.String())
				return true
			})
		}
	}()
	// send lines (does not require resource locks)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to write output: %w", err)
	}
	return nil
}

// IpcSetOperation implements the WireGuard configuration protocol "set" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (d *Device) IpcSetOperation(r io.Reader) (err error) {
	d.ipcMu.Lock()
	defer d.ipcMu.Unlock()
	defer func() {
		if err != nil {
			d.log.Errorf("%v", err)
		}
	}()
	peer := new(ipcSetPeer)
	deviceConfig := true
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			peer.handlePostConfig()
			return nil
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ipcErrorf(ipc.IpcErrorProtocol, "failed to parse line %q", line)
		}
		if key == "public_key" {
			if deviceConfig {
				deviceConfig = false
			}
			peer.handlePostConfig()
			// Load/create the peer we are now configuring.
			if err := d.handlePublicKeyLine(peer, value); err != nil {
				return err
			}
			continue
		}
		if deviceConfig {
			return d.handleDeviceLine(key, value)
		} else {
			return d.handlePeerLine(peer, key, value)
		}
	}
	peer.handlePostConfig()
	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return nil
}

// An ipcSetPeer is the current state of an IPC set operation on a peer.
type ipcSetPeer struct {
	*Peer // current peer being operated on
	// Dummy peers are a defensive programming pattern that:
	// - Prevent nil pointer dereferences in IPC handling.
	// - Allow graceful handling of self-referential configurations.
	// - Maintain IPC state consistency after peer removal.
	// - Act as "tombstones" for removed or invalid peers
	//   while still processing configuration lines.
	dummy       bool // peer is a temporary, placeholder peer
	new         bool // newly created peer
	keepaliveOn bool // peer had keepalive turned on
}

func (peer *ipcSetPeer) handlePostConfig() {
	if peer.Peer == nil || peer.dummy {
		return
	}
	if peer.new {
		peer.endpoint.disableRoaming =
			peer.device.net.brokenRoaming && peer.endpoint.val != nil
	}
	if peer.device.isUp() {
		peer.Start()
		if peer.keepaliveOn {
			peer.SendKeepalive()
		}
		peer.SendStagedPackets()
	}
}

func (d *Device) handlePublicKeyLine(peer *ipcSetPeer, pubKey string) error {
	// Load/create the peer we are configuring.
	var publicKey NoisePublicKey
	err := publicKey.FromHex(pubKey)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to get peer by public key: %w", err)
	}
	// Ignore peer with the same public key as this device.
	d.keys.RLock()
	peer.dummy = d.keys.publicKey.Equals(publicKey)
	d.keys.RUnlock()
	if peer.dummy {
		peer.Peer = &Peer{}
	} else {
		peer.Peer = d.LookupPeer(publicKey)
	}
	peer.new = peer.Peer == nil
	if peer.new {
		peer.Peer, err = d.NewPeer(publicKey)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to create new peer: %w", err)
		}
		d.log.Verbosef("%v - UAPI: Created", peer.Peer)
	}
	return nil
}

func (d *Device) handleDeviceLine(key, value string) error {
	switch key {
	case "private_key":
		var pk NoisePrivateKey
		if err := pk.FromMaybeZeroHex(value); err != nil {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set private_key: %w",
				err,
			)
		}
		d.log.Verbosef("UAPI: Updating private key")
		d.SetPrivateKey(pk)
	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to parse listen_port: %w",
				err,
			)
		}
		// update port and rebind
		d.log.Verbosef("UAPI: Updating listen port")
		d.net.Lock()
		d.net.port = uint16(port)
		d.net.Unlock()
		if err := d.BindUpdate(); err != nil {
			return ipcErrorf(
				ipc.IpcErrorPortInUse,
				"failed to set listen_port: %w",
				err,
			)
		}
	case "fwmark":
		mark, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"invalid fwmark: %w",
				err,
			)
		}
		d.log.Verbosef("UAPI: Updating fwmark")
		if err := d.BindSetMark(uint32(mark)); err != nil {
			return ipcErrorf(
				ipc.IpcErrorPortInUse,
				"failed to update fwmark: %w",
				err,
			)
		}
	case "replace_peers":
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set replace_peers, invalid value: %v",
				value,
			)
		}
		d.log.Verbosef("UAPI: Removing all peers")
		d.RemoveAllPeers()
	default:
		return ipcErrorf(
			ipc.IpcErrorInvalid,
			"invalid UAPI device key: %v",
			key,
		)
	}
	return nil
}

func (d *Device) handlePeerLine(peer *ipcSetPeer, key, value string) error {
	switch key {
	case "update_only":
		// allow disabling of creation
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set update only, invalid value: %v",
				value,
			)
		}
		if peer.new && !peer.dummy {
			d.RemovePeer(peer.handshake.remoteStatic)
			peer.Peer = &Peer{}
			peer.dummy = true
		}
	case "remove":
		// remove currently selected peer from device
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set remove, invalid value: %v",
				value,
			)
		}
		if !peer.dummy {
			d.log.Verbosef("%v - UAPI: Removing", peer.Peer)
			d.RemovePeer(peer.handshake.remoteStatic)
		}
		peer.Peer = &Peer{}
		peer.dummy = true
	case "preshared_key":
		d.log.Verbosef("%v - UAPI: Updating preshared key", peer.Peer)
		peer.handshake.Lock()
		defer peer.handshake.Unlock()
		err := peer.handshake.presharedKey.FromHex(value)
		if err != nil {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set preshared key: %w",
				err,
			)
		}
	case "endpoint":
		d.log.Verbosef("%v - UAPI: Updating endpoint", peer.Peer)
		endpoint, err := d.net.bind.ParseEndpoint(value)
		if err != nil {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set endpoint %v: %w",
				value,
				err,
			)
		}
		peer.endpoint.Lock()
		defer peer.endpoint.Unlock()
		peer.endpoint.val = endpoint
	case "keepalive_interval":
		d.log.Verbosef(
			"%v - UAPI: Updating keepalive interval",
			peer.Peer,
		)
		secs, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set keepalive interval: %w",
				err,
			)
		}
		old := peer.KeepaliveInterval.Swap(uint32(secs))
		// Send immediate keepalive if we're turning it on and before it wasn't on.
		peer.keepaliveOn = old == 0 && secs != 0
	case "replace_allowed_ips":
		d.log.Verbosef("%v - UAPI: Removing all allowedips", peer.Peer)
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to replace allowedips, invalid value: %v",
				value,
			)
		}
		if peer.dummy {
			return nil
		}
		d.router.RemoveByPeer(peer.Peer)
	case "allowed_ip":
		add := true
		verb := "Adding"
		if len(value) > 0 && value[0] == '-' {
			add = false
			verb = "Removing"
			value = value[1:]
		}
		d.log.Verbosef("%v - UAPI: %s allowedip", peer.Peer, verb)
		// Parse a CIDR where the address has host bits set
		// prefix, _ := netip.ParsePrefix("192.168.1.100/24")
		// fmt.Println("Original prefix:", prefix)
		// fmt.Println("Address:", prefix.Addr())
		// fmt.Println("Masked address:", prefix.Masked().Addr())
		// fmt.Println("Bits:", prefix.Bits())
		// Output:
		// 	Original prefix: 192.168.1.100/24
		// 	Address: 192.168.1.100
		// 	Masked address: 192.168.1.0
		// 	Bits: 24
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set allowed ip: %w",
				err,
			)
		}
		if peer.dummy {
			return nil
		}
		if add {
			d.router.Insert(prefix, peer.Peer)
		} else {
			d.router.Remove(prefix, peer.Peer)
		}
	case "protocol_version":
		if value != "1" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"invalid protocol version: %v",
				value,
			)
		}
	default:
		return ipcErrorf(
			ipc.IpcErrorInvalid,
			"invalid UAPI peer key: %v",
			key,
		)
	}
	return nil
}

func (d *Device) IpcGet() (string, error) {
	buf := new(strings.Builder)
	if err := d.IpcGetOperation(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (d *Device) IpcSet(config string) error {
	return d.IpcSetOperation(strings.NewReader(config))
}

func (device *Device) IpcHandle(socket net.Conn) {
	defer socket.Close()
	r := bufio.NewReader(socket)
	w := bufio.NewWriter(socket)
	buf := bufio.NewReadWriter(r, w)
	for {
		op, err := buf.ReadString('\n')
		if err != nil {
			return
		}
		// handle operation
		switch op {
		case "set=1\n":
			err = device.IpcSetOperation(buf.Reader)
		case "get=1\n":
			var nextByte byte
			nextByte, err = buf.ReadByte()
			if err != nil {
				return
			}
			if nextByte != '\n' {
				err = ipcErrorf(
					ipc.IpcErrorInvalid,
					"trailing character in UAPI get: %q",
					nextByte,
				)
				break
			}
			err = device.IpcGetOperation(buf.Writer)
		default:
			device.log.Errorf("invalid UAPI operation: %v", op)
			return
		}
		// write status
		var status *IPCError
		if err != nil && !errors.As(err, &status) {
			// shouldn't happen
			status = ipcErrorf(ipc.IpcErrorUnknown, "other UAPI error: %w", err)
		}
		if status != nil {
			device.log.Errorf("%v", status)
			fmt.Fprintf(buf, "errno=%d\n\n", status.ErrorCode())
		} else {
			fmt.Fprintf(buf, "errno=0\n\n")
		}
		buf.Flush()
	}
}
