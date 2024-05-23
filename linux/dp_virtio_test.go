// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"path/filepath"

	efi "github.com/canonical/go-efilib"
	. "gopkg.in/check.v1"
)

type virtioSuite struct {
	TarFileMixin
}

var _ = Suite(&virtioSuite{})

func (s *virtioSuite) TestHandleVirtioSCSIDevicePathNode(c *C) {
	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	state := &devicePathBuilderState{
		Interface: interfaceTypeVirtio,
		Path: efi.DevicePath{
			&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
			&efi.PCIDevicePathNode{Function: 4, Device: 0x02},
			&efi.PCIDevicePathNode{Function: 0, Device: 0x00}},
		processed: []string{"pci0000:00", "0000:00:02.4", "0000:05:00.0"},
		remaining: []string{"virtio4", "host1", "target1:0:0", "1:0:0:2", "block", "sdd"}}
	c.Check(handleVirtioDevicePathNode(state), IsNil)
	c.Check(state.processed, DeepEquals, []string{"pci0000:00", "0000:00:02.4", "0000:05:00.0", "virtio4"})
	c.Check(state.remaining, DeepEquals, []string{"host1", "target1:0:0", "1:0:0:2", "block", "sdd"})
	c.Check(state.Interface, Equals, interfaceTypeSCSI)
	c.Check(state.Path, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 4, Device: 0x02},
		&efi.PCIDevicePathNode{Function: 0, Device: 0x00}})
}

func (s *virtioSuite) TestHandleVirtioBlockDevicePathNode(c *C) {
	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	state := &devicePathBuilderState{
		Interface: interfaceTypeVirtio,
		Path: efi.DevicePath{
			&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
			&efi.PCIDevicePathNode{Function: 3, Device: 0x02},
			&efi.PCIDevicePathNode{Function: 0, Device: 0x00}},
		processed: []string{"pci0000:00", "0000:00:02.3", "0000:04:00.0"},
		remaining: []string{"virtio3", "block", "vda"}}
	c.Check(handleVirtioDevicePathNode(state), IsNil)
	c.Check(state.processed, DeepEquals, []string{"pci0000:00", "0000:00:02.3", "0000:04:00.0", "virtio3", "block", "vda"})
	c.Check(state.remaining, DeepEquals, []string{})
	c.Check(state.Interface, Equals, interfaceTypeVirtio)
	c.Check(state.Path, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 3, Device: 0x02},
		&efi.PCIDevicePathNode{Function: 0, Device: 0x00}})
}
