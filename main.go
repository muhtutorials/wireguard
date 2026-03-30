package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"

	"github.com/muhtutorials/wireguard/conn"
	"github.com/muhtutorials/wireguard/device"
	"github.com/muhtutorials/wireguard/ipc"
	"github.com/muhtutorials/wireguard/tun"
	"golang.org/x/sys/unix"
)

const Version = "0.0.20250522"

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

func printUsage() {
	fmt.Printf("Usage: %s [-f/--foreground] INTERFACE-NAME\n", os.Args[0])
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf(
			"Userspace WireGuard daemon v%s for %s-%s.\n",
			Version,
			runtime.GOOS,
			runtime.GOARCH,
		)
		return
	}
	var foreground bool
	// interface name
	var name string
	if len(os.Args) < 2 || len(os.Args) > 3 {
		printUsage()
		return
	}
	// Foreground mode:
	// - The process stays attached to the terminal.
	// - Output goes to stdout/stderr (visible in the terminal).
	// - The process will terminate when the terminal closes or receives Ctrl+C.
	// - Used for debugging, development, or when you want to see logs directly.
	switch os.Args[1] {
	case "-f", "--foreground":
		foreground = true
		if len(os.Args) != 3 {
			printUsage()
			return
		}
		name = os.Args[2]
	default:
		foreground = false
		if len(os.Args) != 2 {
			printUsage()
			return
		}
		name = os.Args[1]
	}
	if !foreground {
		foreground = os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1"
	}
	// get log level (default: info)
	logLevel := func() int {
		switch os.Getenv("LOG_LEVEL") {
		case "verbose", "debug":
			return device.LogLevelVerbose
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelError
	}()
	// open TUN device (or use supplied fd)
	tunDevice, err := func() (tun.Device, error) {
		tunFdStr := os.Getenv(ENV_WG_TUN_FD)
		if tunFdStr == "" {
			return tun.CreateTUN(name, device.DefaultMTU)
		}
		// construct tun device from supplied fd
		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}
		if err = unix.SetNonblock(int(fd), true); err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(fd), "")
		return tun.CreateTUNFromFile(file, device.DefaultMTU)
	}()
	if err == nil {
		realName, err2 := tunDevice.Name()
		if err2 == nil {
			name = realName
		}
	}
	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", name),
	)
	logger.Verbosef("Starting wireguard version %s", Version)
	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}
	// open UAPI file (or use supplied fd)
	uapiFile, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
		if uapiFdStr == "" {
			return ipc.UAPIOpen(name)
		}
		// use supplied fd
		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), ""), nil
	}()
	if err != nil {
		logger.Errorf("UAPI listen error: %v", err)
		os.Exit(ExitSetupFailed)
		return
	}
	// Background mode (foreground = false):
	// 1. Daemonization: The program spawns a child process and exits.
	// 2. File descriptor passing: It passes file descriptors
	//    for the TUN device and UAPI socket (file descriptors 3 and 4).
	// 3. Output redirection:
	//    - If logging is enabled, stdout/stderr are kept.
	//    - If silent mode, all outputs go to os.DevNull (discarded).
	//    - stdin always goes to os.DevNull.
	if !foreground {
		env := os.Environ()
		env = append(env, fmt.Sprintf("%s=3", ENV_WG_TUN_FD))
		env = append(env, fmt.Sprintf("%s=4", ENV_WG_UAPI_FD))
		env = append(env, fmt.Sprintf("%s=1", ENV_WG_PROCESS_FOREGROUND))
		files := [3]*os.File{}
		// os.DevNull provides the platform-specific path to the null device.
		// It's used for discarding output.
		if os.Getenv("LOG_LEVEL") != "" && logLevel != device.LogLevelSilent {
			files[0], _ = os.Open(os.DevNull)
			files[1] = os.Stdout
			files[2] = os.Stderr
		} else {
			files[0], _ = os.Open(os.DevNull)
			files[1], _ = os.Open(os.DevNull)
			files[2], _ = os.Open(os.DevNull)
		}
		attr := &os.ProcAttr{
			Files: []*os.File{
				files[0], // stdin
				files[1], // stdout
				files[2], // stderr
				tunDevice.File(),
				uapiFile,
			},
			Dir: ".",
			Env: env,
		}
		path, err := os.Executable()
		if err != nil {
			logger.Errorf("Failed to determine executable: %v", err)
			os.Exit(ExitSetupFailed)
		}
		// The parent process creates the daemon child.
		// The parent doesn't need to monitor or wait for the child.
		// The parent exits immediately, leaving the child running as a daemon.
		// Release() cleans up the handle since the parent won't call Wait().
		process, err := os.StartProcess(path, os.Args, attr)
		if err != nil {
			logger.Errorf("Failed to daemonize: %v", err)
			os.Exit(ExitSetupFailed)
		}
		process.Release()
		return
	}
	device := device.NewDevice(tunDevice, conn.New(), logger)
	logger.Verbosef("Device started")
	errs := make(chan error)
	term := make(chan os.Signal, 1)
	uapi, err := ipc.UAPIListen(name, uapiFile)
	if err != nil {
		logger.Errorf("Failed to listen on uapi socket: %v", err)
		os.Exit(ExitSetupFailed)
	}
	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()
	logger.Verbosef("UAPI listener started")
	// Wait for program to terminate.
	// signal.Notify registers a channel to receive notifications
	// about specific operating system signals.
	signal.Notify(term, unix.SIGTERM, os.Interrupt)
	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}
	// clean up
	uapi.Close()
	device.Close()
	logger.Verbosef("Shutting down")
}
