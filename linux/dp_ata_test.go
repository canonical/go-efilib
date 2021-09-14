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

func (s *ataSuite) TestHandleATADevicePathNodeSATA1(c *C) {
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
		&efi.SATADevicePathNode{
			HBAPortNumber:            0,
			PortMultiplierPortNumber: 0xffff}})
	c.Check(builder.dev.devPathIsFull, Equals, true)
}

func (s *ataSuite) TestHandleATADevicePathNodeSATA2(c *C) {
	restoreSysfs := MockSysfsPath("testdata/sys")
	defer restoreSysfs()

	builder := &devicePathBuilderImpl{
		dev: &dev{
			node: "/dev/sdb", part: 1,
			interfaceType: interfaceTypeSATA,
			devPath: efi.DevicePath{
				&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
				&efi.PCIDevicePathNode{Function: 2, Device: 0x1f}},
			devPathIsFull: true},
		processed: []string{"pci0000:00", "0000:00:1f.2"},
		remaining: []string{"ata4", "host2", "target2:0:0", "2:0:0:0", "block", "sdb"}}
	c.Check(handleATADevicePathNode(builder, builder.dev), IsNil)
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00", "0000:00:1f.2", "ata4", "host2", "target2:0:0", "2:0:0:0", "block", "sdb"})
	c.Check(builder.remaining, DeepEquals, []string{})
	c.Check(builder.dev.interfaceType, Equals, interfaceType(interfaceTypeSATA))
	c.Check(builder.dev.devPath, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 2, Device: 0x1f},
		&efi.SATADevicePathNode{
			HBAPortNumber:            3,
			PortMultiplierPortNumber: 0xffff}})
	c.Check(builder.dev.devPathIsFull, Equals, true)
}

func (s *ataSuite) TestHandleATADevicePathNodeIDE1(c *C) {
	restoreSysfs := MockSysfsPath("testdata/sys")
	defer restoreSysfs()

	builder := &devicePathBuilderImpl{
		dev: &dev{
			node: "/dev/sdc", part: 1,
			interfaceType: interfaceTypeIDE,
			devPath: efi.DevicePath{
				&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
				&efi.PCIDevicePathNode{Function: 1, Device: 0x01}},
			devPathIsFull: true},
		processed: []string{"pci0000:00", "0000:00:01.1"},
		remaining: []string{"ata7", "host3", "target3:0:0", "3:0:0:0", "block", "sdc"}}
	c.Check(handleATADevicePathNode(builder, builder.dev), IsNil)
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00", "0000:00:01.1", "ata7", "host3", "target3:0:0", "3:0:0:0", "block", "sdc"})
	c.Check(builder.remaining, DeepEquals, []string{})
	c.Check(builder.dev.interfaceType, Equals, interfaceType(interfaceTypeIDE))
	c.Check(builder.dev.devPath, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 1, Device: 0x01},
		&efi.ATAPIDevicePathNode{
			Controller: efi.ATAPIControllerPrimary,
			Drive:      efi.ATAPIDriveMaster}})
	c.Check(builder.dev.devPathIsFull, Equals, true)
}

func (s *ataSuite) TestHandleATADevicePathNodeIDE2(c *C) {
	restoreSysfs := MockSysfsPath("testdata/sys")
	defer restoreSysfs()

	builder := &devicePathBuilderImpl{
		dev: &dev{
			node: "/dev/sdc", part: 1,
			interfaceType: interfaceTypeIDE,
			devPath: efi.DevicePath{
				&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
				&efi.PCIDevicePathNode{Function: 1, Device: 0x01}},
			devPathIsFull: true},
		processed: []string{"pci0000:00", "0000:00:01.1"},
		remaining: []string{"ata8", "host4", "target4:0:1", "4:0:1:0", "block", "sdd"}}
	c.Check(handleATADevicePathNode(builder, builder.dev), IsNil)
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00", "0000:00:01.1", "ata8", "host4", "target4:0:1", "4:0:1:0", "block", "sdd"})
	c.Check(builder.remaining, DeepEquals, []string{})
	c.Check(builder.dev.interfaceType, Equals, interfaceType(interfaceTypeIDE))
	c.Check(builder.dev.devPath, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 1, Device: 0x01},
		&efi.ATAPIDevicePathNode{
			Controller: efi.ATAPIControllerSecondary,
			Drive:      efi.ATAPIDriveSlave}})
	c.Check(builder.dev.devPathIsFull, Equals, true)
}
