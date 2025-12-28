package tun

import (
	"fmt"
)

func (tun *Tun) operateOnFd(fn func(fd uintptr)) {
	sysconn, err := tun.file.SyscallConn()
	if err != nil {
		tun.errors <- fmt.Errorf("unable to find sysconn for tunfile: %s", err.Error())
		return
	}
	err = sysconn.Control(fn)
	if err != nil {
		tun.errors <- fmt.Errorf("unable to control sysconn for tunfile: %s", err.Error())
	}
}
