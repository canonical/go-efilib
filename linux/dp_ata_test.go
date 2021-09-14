// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
)

type ataSuite struct{}

var _ = Suite(&ataSuite{})

func (s *ataSuite) TestHandleATADevicePathNode(c *C) {
	restoreSysfs := MockSysfsPath("testdata/sys")
	defer restoreSysfs()

	builder := &devicePathBuilderImpl{
		dev: &dev{
			node: "/dev/sda", part: 1,
			interfaceType: interfaceTypeSATA,
			devPath: efi.DevicePath{
				&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
				&efi.PCIDevicePathNode{Function: 2, Device: 0x1f}},
			devPathIsFull: true},
		processed: []string{"pci0000:00", "0000:00:1f.2"},
		remaining: []string{"ata1", "host1", "target1:0:0", "1:0:0:0", "block", "sda"}}
	c.Check(handleATADevicePathNode(builder, builder.dev), IsNil)
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00", "0000:00:1f.2", "ata1", "host1", "target1:0:0", "1:0:0:0", "block", "sda"})
	c.Check(builder.remaining, DeepEquals, []string{})
	c.Check(builder.dev.interfaceType, Equals, interfaceType(interfaceTypeSATA))
	c.Check(builder.dev.devPath, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 2, Device: 0x1f},
		&efi.SATADevicePathNode{PortMultiplierPortNumber: 0xffff}})
	c.Check(builder.dev.devPathIsFull, Equals, true)
}
