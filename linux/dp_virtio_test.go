// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
)

type virtioSuite struct{}

var _ = Suite(&virtioSuite{})

func (s *virtioSuite) TestHandleVirtioDevicePathNode(c *C) {
	restoreSysfs := MockSysfsPath("testdata/sys")
	defer restoreSysfs()

	builder := &devicePathBuilderImpl{
		dev: &dev{
			node: "/dev/sdd", part: 1,
			interfaceType: interfaceTypeSCSI,
			devPath: efi.DevicePath{
				&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
				&efi.PCIDevicePathNode{Function: 4, Device: 0x02},
				&efi.PCIDevicePathNode{Function: 0, Device: 0x00}},
			devPathIsFull: true},
		processed: []string{"pci0000:00", "0000:00:02.4", "0000:05:00.0"},
		remaining: []string{"virtio4", "host1", "target1:0:0", "1:0:0:2", "block", "sdd"}}
	c.Check(handleVirtioDevicePathNode(builder, builder.dev), IsNil)
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00", "0000:00:02.4", "0000:05:00.0", "virtio4"})
	c.Check(builder.remaining, DeepEquals, []string{"host1", "target1:0:0", "1:0:0:2", "block", "sdd"})
	c.Check(builder.dev.interfaceType, Equals, interfaceType(interfaceTypeSCSI))
	c.Check(builder.dev.devPath, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 4, Device: 0x02},
		&efi.PCIDevicePathNode{Function: 0, Device: 0x00}})
	c.Check(builder.dev.devPathIsFull, Equals, true)
}
