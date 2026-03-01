package device

import (
	"fmt"

	"github.com/muhtutorials/wireguard/tun"
)

// maximum transmission unit
const DefaultMTU = 1420

func (d *Device) RoutineTUNEventReader() {
	d.log.Verbosef("Routine: event worker - started")
	for event := range d.tun.device.Events() {
		if event&tun.EventUp != 0 {
			d.log.Verbosef("Interface up requested")
			d.Up()
		}
		if event&tun.EventDown != 0 {
			d.log.Verbosef("Interface down requested")
			d.Down()
		}
		if event&tun.EventMTUUpdate != 0 {
			mtu, err := d.tun.device.MTU()
			if err != nil {
				d.log.Errorf("Failed to load updated MTU of device: %v", err)
				continue
			}
			if mtu < 0 {
				d.log.Errorf("MTU not updated to negative value: %v", mtu)
				continue
			}
			var tooLarge string
			if mtu > MaxContentSize {
				tooLarge = fmt.Sprintf(" (too large, capped at %v)", MaxContentSize)
				mtu = MaxContentSize
			}
			old := d.tun.mtu.Swap(int32(mtu))
			if int(old) != mtu {
				d.log.Verbosef("MTU updated: %v%s", mtu, tooLarge)
			}
		}
	}
	d.log.Verbosef("Routine: event worker - stopped")
}
