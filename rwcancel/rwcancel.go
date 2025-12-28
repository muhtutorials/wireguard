package rwcancel

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type RWCancel struct {
	fd int      // file descriptor
	r  *os.File // closing reader
	w  *os.File // closing writer
}

func New(fd int) (*RWCancel, error) {
	// Sets the non-blocking flag on a file descriptor.
	//
	// Blocking I/O (Default):
	// read() will WAIT until data is available
	// data := make([]byte, 1024)
	// n, err := syscall.Read(fd, data)  // hangs here if no data
	//
	// Non-blocking I/O
	// read() returns IMMEDIATELY, even if no data
	// n, err := syscall.Read(fd, data)
	// if err != nil && err == syscall.EAGAIN {
	//     No data available yet, try again later
	// }
	err := unix.SetNonblock(fd, true)
	if err != nil {
		return nil, err
	}
	rw := &RWCancel{fd: fd}
	// os.Pipe() creates a unidirectional inter-process communication channel (pipe).
	// Write End (w) → [PIPE BUFFER] → Read End (r)
	if rw.r, rw.w, err = os.Pipe(); err != nil {
		return nil, err
	}
	return rw, nil
}

// RetryAfterError checks if error is retryable
func RetryAfterError(err error) bool {
	// EAGAIN: resource temporarily unavailable
	// EINTR: interrupted system call
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR)
}

func (rw *RWCancel) ReadyRead() bool {
	// pipe read end for cancellation signaling
	closeFd := int32(rw.r.Fd())
	// type PollFd struct {
	//     Fd      int32   // file descriptor to monitor
	//	   Events  int16   // events to watch for (input)
	//	   Revents int16   // events that occurred (output)
	// }
	// POLLIN: data available to read
	pollFds := []unix.PollFd{
		{
			Fd:     int32(rw.fd),
			Events: unix.POLLIN,
		},
		{
			Fd:     closeFd,
			Events: unix.POLLIN,
		},
	}
	var err error
	for {
		_, err = unix.Poll(pollFds, -1) // -1 = wait forever
		if err == nil || !RetryAfterError(err) {
			break
		}
	}
	if err != nil {
		return false
	}
	// Revents is returned events.
	// if pfd.Revents & POLLIN != 0 { // "&" is used if several events are monitored
	//     socket has data to read
	// }
	if pollFds[1].Revents != 0 {
		return false
	}
	return pollFds[0].Revents != 0
}

func (rw *RWCancel) ReadyWrite() bool {
	closeFd := int32(rw.r.Fd())
	// POLLOUT: ready for writing
	pollFds := []unix.PollFd{
		{
			Fd:     int32(rw.fd),
			Events: unix.POLLOUT,
		},
		{
			Fd:     closeFd,
			Events: unix.POLLIN,
		},
	}
	var err error
	for {
		_, err = unix.Poll(pollFds, -1)
		if err == nil || !RetryAfterError(err) {
			break
		}
	}
	if err != nil {
		return false
	}
	if pollFds[1].Revents != 0 {
		return false
	}
	return pollFds[0].Revents != 0
}

func (rw *RWCancel) Read(p []byte) (int, error) {
	for {
		n, err := unix.Read(rw.fd, p)
		if err == nil || !RetryAfterError(err) {
			return n, err
		}
		if !rw.ReadyRead() {
			return 0, os.ErrClosed
		}
	}
}

func (rw *RWCancel) Write(p []byte) (int, error) {
	for {
		n, err := unix.Write(rw.fd, p)
		if err == nil || !RetryAfterError(err) {
			return n, err
		}
		if !rw.ReadyWrite() {
			return 0, os.ErrClosed
		}
	}
}

func (rw *RWCancel) Cancel() error {
	_, err := rw.w.Write([]byte{0})
	return err
}

func (rw *RWCancel) Close() {
	rw.r.Close()
	rw.w.Close()
}
