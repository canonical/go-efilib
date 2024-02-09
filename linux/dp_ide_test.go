// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"path/filepath"

	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
)

type ideSuite struct {
	TarFileMixin
}

var _ = Suite(&ideSuite{})

func (s *ideSuite) TestHandleIDEDevicePathNode1(c *C) {
	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	state := &devicePathBuilderState{
		Interface: interfaceTypeIDE,
		Path: efi.DevicePath{
			&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
			&efi.PCIDevicePathNode{Function: 1, Device: 0x01}},
		processed: []string{"pci0000:00", "0000:00:01.1"},
		remaining: []string{"ata7", "host3", "target3:0:0", "3:0:0:0", "block", "sdc"}}
	c.Check(handleIDEDevicePathNode(state), IsNil)
	c.Check(state.processed, DeepEquals, []string{"pci0000:00", "0000:00:01.1", "ata7", "host3", "target3:0:0", "3:0:0:0", "block", "sdc"})
	c.Check(state.remaining, DeepEquals, []string{})
	c.Check(state.Interface, Equals, interfaceTypeIDE)
	c.Check(state.Path, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 1, Device: 0x01},
		&efi.ATAPIDevicePathNode{
			Controller: efi.ATAPIControllerPrimary,
			Drive:      efi.ATAPIDriveMaster}})
}

func (s *ideSuite) TestHandleIDEDevicePathNode2(c *C) {
	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	state := &devicePathBuilderState{
		Interface: interfaceTypeIDE,
		Path: efi.DevicePath{
			&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
			&efi.PCIDevicePathNode{Function: 1, Device: 0x01}},
		processed: []string{"pci0000:00", "0000:00:01.1"},
		remaining: []string{"ata8", "host4", "target4:0:1", "4:0:1:0", "block", "sdd"}}
	c.Check(handleIDEDevicePathNode(state), IsNil)
	c.Check(state.processed, DeepEquals, []string{"pci0000:00", "0000:00:01.1", "ata8", "host4", "target4:0:1", "4:0:1:0", "block", "sdd"})
	c.Check(state.remaining, DeepEquals, []string{})
	c.Check(state.Interface, Equals, interfaceTypeIDE)
	c.Check(state.Path, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 1, Device: 0x01},
		&efi.ATAPIDevicePathNode{
			Controller: efi.ATAPIControllerSecondary,
			Drive:      efi.ATAPIDriveSlave}})
}
