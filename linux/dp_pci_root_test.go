// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"path/filepath"

	efi "github.com/canonical/go-efilib"
	. "gopkg.in/check.v1"
)

type pciRootSuite struct {
	TarFileMixin
}

var _ = Suite(&pciRootSuite{})

func (s *pciRootSuite) TestHandlePCIRootDevicePathNodeSkip(c *C) {
	state := &devicePathBuilderState{remaining: []string{"ACPI0004:00"}}
	c.Check(handlePCIRootDevicePathNode(state), Equals, errSkipDevicePathNodeHandler)
}

func (s *pciRootSuite) TestHandlePCIRootDevicePathNode(c *C) {
	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	state := &devicePathBuilderState{remaining: []string{"pci0000:00"}}
	c.Check(handlePCIRootDevicePathNode(state), IsNil)
	c.Check(state.processed, DeepEquals, []string{"pci0000:00"})
	c.Check(state.remaining, DeepEquals, []string{})
	c.Check(state.Interface, Equals, interfaceTypePCI)
	c.Check(state.Path, DeepEquals, efi.DevicePath{&efi.ACPIDevicePathNode{HID: 0x0a0341d0}})
}
