// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
)

type nvmeSuite struct{}

var _ = Suite(&nvmeSuite{})

func (s *nvmeSuite) TestHandleNVMEDevicePathNode(c *C) {
	restoreSysfs := MockSysfsPath("testdata/sys")
	defer restoreSysfs()

	builder := &devicePathBuilderImpl{
		dev: &dev{
			node: "/dev/nvme0n1", part: 1,
			interfaceType: interfaceTypeNVME,
			devPath: efi.DevicePath{
				&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
				&efi.PCIDevicePathNode{Function: 0, Device: 0x1d},
				&efi.PCIDevicePathNode{Function: 0, Device: 0}},
			devPathIsFull: true},
		processed: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0"},
		remaining: []string{"nvme", "nvme0", "nvme0n1"}}
	c.Check(handleNVMEDevicePathNode(builder, builder.dev), IsNil)
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"})
	c.Check(builder.remaining, DeepEquals, []string{})
	c.Check(builder.dev.interfaceType, Equals, interfaceType(interfaceTypeNVME))
	c.Check(builder.dev.devPath, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 0, Device: 0x1d},
		&efi.PCIDevicePathNode{Function: 0, Device: 0},
		&efi.NVMENamespaceDevicePathNode{NamespaceID: 1}})
	c.Check(builder.dev.devPathIsFull, Equals, true)
}
