// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
)

type scsiSuite struct {
	TarFileMixin
}

var _ = Suite(&scsiSuite{})

func (s *scsiSuite) TestHandleSCSIDevicePathNode(c *C) {
	restore := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restore()

	builder := &devicePathBuilderImpl{
		iface: interfaceTypeSCSI,
		devPath: efi.DevicePath{
			&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
			&efi.PCIDevicePathNode{Function: 4, Device: 0x02},
			&efi.PCIDevicePathNode{Function: 0, Device: 0x00}},
		processed: []string{"pci0000:00", "0000:00:02.4", "0000:05:00.0", "virtio4"},
		remaining: []string{"host5", "target5:0:0", "5:0:0:2", "block", "sde"}}
	c.Check(handleSCSIDevicePathNode(builder), IsNil)
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00", "0000:00:02.4", "0000:05:00.0", "virtio4", "host5", "target5:0:0", "5:0:0:2", "block", "sde"})
	c.Check(builder.remaining, DeepEquals, []string{})
	c.Check(builder.iface, Equals, interfaceTypeSCSI)
	c.Check(builder.devPath, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 4, Device: 0x02},
		&efi.PCIDevicePathNode{Function: 0, Device: 0x00},
		&efi.SCSIDevicePathNode{PUN: 0, LUN: 2}})
}
