package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/muhtutorials/wireguard/rwcancel"
	"golang.org/x/sys/unix"
)

// Negative error codes that WireGuard sends over the socket to clients.
// Using negative values ensures they don't conflict with valid
// positive return values (like file descriptors).
const (
	IpcErrorIO        = -int64(unix.EIO)
	IpcErrorProtocol  = -int64(unix.EPROTO)
	IpcErrorInvalid   = -int64(unix.EINVAL)
	IpcErrorPortInUse = -int64(unix.EADDRINUSE)
	IpcErrorUnknown   = -55 // ENOANO
)

// default location for WireGuard control sockets
const sockDir = "/var/run/wireguard"

func sockPath(iface string) string {
	// e.g., "/var/run/wireguard/wg0.sock"
	return fmt.Sprintf("%s/%s.sock", sockDir, iface)
}

func UAPIOpen(name string) (*os.File, error) {
	// Creates "/var/run/wireguard" if it doesn't exist.
	// 0o755: rwx r-x r-x
	if err := os.MkdirAll(sockDir, 0o755); err != nil {
		return nil, err
	}
	socketPath := sockPath(name)
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, err
	}
	// Umask (user file-creation mode mask) is a permission mask that
	// determines which permission bits are disabled when new files
	// or directories are created. It subtracts permissions from
	// the default creation mode.
	// Default file creation mode: Typically 0666 (rw-rw-rw-).
	// Default directory creation mode: Typically 0777 (rwxrwxrwx).
	// Umask removes permissions: Actual permissions = default mode & ^umask.
	// Temporarily sets umask to 0o077 (blocks group and other permissions).
	// Ensures socket file is created with 0600 permissions (owner read/write only).
	oldUmask := unix.Umask(0o077)
	// restores original umask after function returns
	defer unix.Umask(oldUmask)
	// ListenUnix creates a Unix domain socket listener.
	// It's used for inter-process communication (IPC)
	// on the same machine using Unix domain sockets,
	// which are more efficient than TCP/IP for local communication.
	listener, err := net.ListenUnix("unix", addr)
	if err == nil {
		return listener.File()
	}
	// test socket, if not in use cleanup and try again
	if _, err := net.Dial("unix", socketPath); err == nil {
		// socket is in use (connection successful), return error
		return nil, errors.New("unix socket in use")
	}
	// if not in use, remove the stale socket and retry creation
	if err := os.Remove(socketPath); err != nil {
		return nil, err
	}
	listener, err = net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}
	return listener.File()
}

type UAPIListener struct {
	listener        net.Listener // unix socket listener
	connNew         chan net.Conn
	connErr         chan error
	inotifyFd       int
	inotifyRWCancel *rwcancel.RWCancel
}

func UAPIListen(name string, file *os.File) (net.Listener, error) {
	// take an *os.File (already open file descriptor)
	// and convert it into a net.Listener
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}
	// type-assert to check if this is actually a Unix domain socket listener
	if unixListener, ok := listener.(*net.UnixListener); ok {
		// Ensure the socket file is automatically deleted
		// from the filesystem when the listener closes.
		// Prevents stale socket files from being left behind.
		unixListener.SetUnlinkOnClose(true)
	}
	uapi := &UAPIListener{
		listener: listener,
		connNew:  make(chan net.Conn, 1),
		connErr:  make(chan error, 1),
	}
	// watch for deletion of socket
	socketPath := sockPath(name)
	uapi.inotifyFd, err = unix.InotifyInit()
	if err != nil {
		return nil, err
	}
	_, err = unix.InotifyAddWatch(
		uapi.inotifyFd,
		socketPath,
		unix.IN_ATTRIB|
			unix.IN_DELETE|
			unix.IN_DELETE_SELF,
	)
	if err != nil {
		return nil, err
	}
	uapi.inotifyRWCancel, err = rwcancel.New(uapi.inotifyFd)
	if err != nil {
		unix.Close(uapi.inotifyFd)
		return nil, err
	}
	go func(l *UAPIListener) {
		defer uapi.inotifyRWCancel.Close()
		// Zero-length because the code doesn't care about the event data,
		// it only cares that an event occurred or the read was cancelled.
		var buf [0]byte
		for {
			// Start with lstat to avoid race condition.
			// Checks socket existence first with os.Lstat() before blocking.
			// os.Lstat returns FileInfo.
			// A FileInfo describes a file and is returned by [Stat].
			// type FileInfo interface {
			//     Name() string       // base name of the file
			//     Size() int64        // length in bytes for regular files; system-dependent for others
			//     Mode() FileMode     // file mode bits
			//     ModTime() time.Time // modification time
			//     IsDir() bool        // abbreviation for Mode().IsDir()
			//     Sys() any           // underlying data source (can return nil)
			// }
			if _, err := os.Lstat(socketPath); os.IsNotExist(err) {
				l.connErr <- err
				return
			}
			_, err := uapi.inotifyRWCancel.Read(buf[:])
			if err != nil {
				l.connErr <- err
				return
			}
		}
	}(uapi)
	// watch for new connections
	go func(l *UAPIListener) {
		for {
			conn, err := l.listener.Accept()
			if err != nil {
				l.connErr <- err
				break
			}
			l.connNew <- conn
		}
	}(uapi)
	return uapi, nil
}

func (l *UAPIListener) Accept() (net.Conn, error) {
	for {
		select {
		case conn := <-l.connNew:
			return conn, nil
		case err := <-l.connErr:
			return nil, err
		}
	}
}

func (l *UAPIListener) Close() error {
	err1 := unix.Close(l.inotifyFd)
	err2 := l.inotifyRWCancel.Cancel()
	err3 := l.listener.Close()
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}

func (l *UAPIListener) Addr() net.Addr {
	return l.listener.Addr()
}
