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

// Default location for WireGuard control sockets.
// This directory (folder) contains socket files
// like wg0.sock, wg1.sock and so on.
// Socket files have zero size and they're only
// used for communication between processes.
const sockDir = "/var/run/wireguard"

// sockPath creates a path like "/var/run/wireguard/wg0.sock"
// sock extension has no special meaning!
// Linux identifies file types by the file mode
// (permissions/type bits), not by file extension:
//
//	srw------- 1 root root 0 Mar 30 10:00 wg0.sock
//	's' (the first character) shows this is a socket file.
//
// Linux files have type indicators in the first character of ls -l:
//
//	Type	           Char     Example
//	Regular file         -    -rw-r--r--
//	Directory            d    drwxr-xr-x
//	Symbolic link        l    lrwxrwxrwx
//	Socket               s    srw-------
//	Named pipe (FIFO)    p    prw-------
//	Character device     c    crw-rw-rw-
//	Block device	     b    brw-rw----
func sockPath(iface string) string {
	return fmt.Sprintf("%s/%s.sock", sockDir, iface)
}

// UAPIOpen creates a socket for IPC, e.g. "/var/run/wireguard/wg0.sock".
func UAPIOpen(name string) (*os.File, error) {
	// Creates "/var/run/wireguard" directory if it doesn't exist.
	// 0o755: rwx r-x r-x
	if err := os.MkdirAll(sockDir, 0o755); err != nil {
		return nil, err
	}
	// socket path
	path := sockPath(name)
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, err
	}
	// Umask (user file-creation mode mask) is a permission mask that
	// determines which permission bits are disabled when new files
	// or directories are created. It subtracts permissions from
	// the default creation mode.
	// Default file creation mode: typically 0666 (rw-rw-rw-).
	// Default directory creation mode: typically 0777 (rwxrwxrwx).
	// Umask removes permissions: actual permissions = default mode & ^umask.
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
	if _, err := net.Dial("unix", path); err == nil {
		// socket is in use (connection successful), return error
		return nil, errors.New("unix socket in use")
	}
	// if not in use, remove the stale socket and retry creation
	if err := os.Remove(path); err != nil {
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

// UAPIListen creates a net.Listener which listens
// for IPC connections.
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
	path := sockPath(name) // socket path
	// InotifyInit provides access to the Linux kernel's
	// file system event monitoring subsystem.
	// It returns a file descriptor that can be used to
	// watch for file system events like modifications,
	// deletions, and attribute changes.
	uapi.inotifyFd, err = unix.InotifyInit()
	if err != nil {
		return nil, err
	}
	_, err = unix.InotifyAddWatch(
		uapi.inotifyFd,
		path,
		// metadata changed (permissions, timestamps, etc.)
		unix.IN_ATTRIB|
			// file/directory deleted from watched directory
			unix.IN_DELETE|
			// watched file/directory was deleted
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
	// watch for socket file deletion
	go func(l *UAPIListener) {
		defer uapi.inotifyRWCancel.Close()
		// Zero-length because the code doesn't care about the event data,
		// it only cares that an event occurred or the read was cancelled.
		var buf [0]byte
		for {
			// When socket is deleted `uapi.inotifyRWCancel.Read(buf[:])`
			// will unblock (triggered by unix.IN_DELETE_SELF flag) and program
			// will loop back to `os.Lstat(path)` where `os.IsNotExist(err)`
			// will be true and therefore function will return.
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				l.connErr <- err
				return
			}
			// This read blocks until:
			// - An inotify event occurs (file was deleted/changed).
			// - The read is cancelled (via rwcancel when shutting down).
			_, err := uapi.inotifyRWCancel.Read(buf[:])
			if err != nil {
				// error if inotifyFd deleted
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
	select {
	case conn := <-l.connNew:
		return conn, nil
	case err := <-l.connErr:
		return nil, err
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
