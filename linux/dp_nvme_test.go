// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"path/filepath"

	efi "github.com/canonical/go-efilib"
	. "gopkg.in/check.v1"
)

type nvmeSuite struct {
	TarFileMixin
}

var _ = Suite(&nvmeSuite{})

func (s *nvmeSuite) TestHandleNVMEDevicePathNode(c *C) {
	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	state := &devicePathBuilderState{
		Interface: interfaceTypeNVME,
		Path: efi.DevicePath{
			&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
			&efi.PCIDevicePathNode{Function: 0, Device: 0x1d},
			&efi.PCIDevicePathNode{Function: 0, Device: 0}},
		processed: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0"},
		remaining: []string{"nvme", "nvme0", "nvme0n1"}}
	c.Check(handleNVMEDevicePathNode(state), IsNil)
	c.Check(state.processed, DeepEquals, []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"})
	c.Check(state.remaining, DeepEquals, []string{})
	c.Check(state.Interface, Equals, interfaceTypeNVME)
	c.Check(state.Path, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 0, Device: 0x1d},
		&efi.PCIDevicePathNode{Function: 0, Device: 0},
		&efi.NVMENamespaceDevicePathNode{NamespaceID: 1}})
}
