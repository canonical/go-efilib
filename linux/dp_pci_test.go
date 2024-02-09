// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"path/filepath"

	efi "github.com/canonical/go-efilib"
	. "gopkg.in/check.v1"
)

type pciSuite struct {
	TarFileMixin
}

var _ = Suite(&pciSuite{})

func (s *pciSuite) TestHandlePCIDevicePathNodeBridge(c *C) {
	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	state := &devicePathBuilderState{
		Interface: interfaceTypePCI,
		Path:      efi.DevicePath{&efi.ACPIDevicePathNode{HID: 0x0a0341d0}},
		processed: []string{"pci0000:00"},
		remaining: []string{"0000:00:1d.0"}}
	c.Check(handlePCIDevicePathNode(state), IsNil)
	c.Check(state.processed, DeepEquals, []string{"pci0000:00", "0000:00:1d.0"})
	c.Check(state.remaining, DeepEquals, []string{})
	c.Check(state.Interface, Equals, interfaceTypePCI)
	c.Check(state.Path, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 0, Device: 0x1d}})
}

func (s *pciSuite) TestHandlePCIDevicePathNodeNVME(c *C) {
	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	state := &devicePathBuilderState{
		Interface: interfaceTypePCI,
		Path: efi.DevicePath{
			&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
			&efi.PCIDevicePathNode{Function: 0, Device: 0x1d}},
		processed: []string{"pci0000:00", "0000:00:1d.0"},
		remaining: []string{"0000:3d:00.0"}}
	c.Check(handlePCIDevicePathNode(state), IsNil)
	c.Check(state.processed, DeepEquals, []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0"})
	c.Check(state.remaining, DeepEquals, []string{})
	c.Check(state.Interface, Equals, interfaceTypeNVME)
	c.Check(state.Path, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 0, Device: 0x1d},
		&efi.PCIDevicePathNode{Function: 0, Device: 0}})
}
