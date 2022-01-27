// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
)

type sataSuite struct {
	TarFileMixin
}

var _ = Suite(&sataSuite{})

func (s *sataSuite) TestHandleSATADevicePathNode1(c *C) {
	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	builder := &devicePathBuilderImpl{
		iface: interfaceTypeSATA,
		devPath: efi.DevicePath{
			&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
			&efi.PCIDevicePathNode{Function: 2, Device: 0x1f}},
		processed: []string{"pci0000:00", "0000:00:1f.2"},
		remaining: []string{"ata1", "host1", "target1:0:0", "1:0:0:0", "block", "sda"}}
	c.Check(handleSATADevicePathNode(builder), IsNil)
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00", "0000:00:1f.2", "ata1", "host1", "target1:0:0", "1:0:0:0", "block", "sda"})
	c.Check(builder.remaining, DeepEquals, []string{})
	c.Check(builder.iface, Equals, interfaceTypeSATA)
	c.Check(builder.devPath, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 2, Device: 0x1f},
		&efi.SATADevicePathNode{
			HBAPortNumber:            0,
			PortMultiplierPortNumber: 0xffff}})
}

func (s *sataSuite) TestHandleSATADevicePathNode2(c *C) {
	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	builder := &devicePathBuilderImpl{
		iface: interfaceTypeSATA,
		devPath: efi.DevicePath{
			&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
			&efi.PCIDevicePathNode{Function: 2, Device: 0x1f}},
		processed: []string{"pci0000:00", "0000:00:1f.2"},
		remaining: []string{"ata4", "host2", "target2:0:0", "2:0:0:0", "block", "sdb"}}
	c.Check(handleSATADevicePathNode(builder), IsNil)
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00", "0000:00:1f.2", "ata4", "host2", "target2:0:0", "2:0:0:0", "block", "sdb"})
	c.Check(builder.remaining, DeepEquals, []string{})
	c.Check(builder.iface, Equals, interfaceTypeSATA)
	c.Check(builder.devPath, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 2, Device: 0x1f},
		&efi.SATADevicePathNode{
			HBAPortNumber:            3,
			PortMultiplierPortNumber: 0xffff}})
}
