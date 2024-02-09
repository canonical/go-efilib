// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"path/filepath"

	efi "github.com/canonical/go-efilib"
	. "gopkg.in/check.v1"
)

type vmbusRootSuite struct {
	TarFileMixin
}

var _ = Suite(&vmbusRootSuite{})

func (s *vmbusRootSuite) TestHandleVMBusRootDevicePathNodeSkip(c *C) {
	state := &devicePathBuilderState{remaining: []string{"ACPI0004:00"}}
	c.Check(handleVMBusRootDevicePathNode(state), Equals, errSkipDevicePathNodeHandler)
}

func (s *vmbusRootSuite) TestHandleVMBusRootDevicePathNode(c *C) {
	restore := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restore()

	state := &devicePathBuilderState{
		Interface: interfaceTypeUnknown,
		processed: []string{"LNXSYSTM:00", "LNXSYBUS:00", "ACPI0004:00"},
		remaining: []string{"VMBUS:00", "f8b3781b-1e82-4818-a1c3-63d806ec15bb", "host6", "target6:0:0", "6:0:0:0", "block", "sdf"}}
	c.Check(handleVMBusRootDevicePathNode(state), IsNil)
	c.Check(state.processed, DeepEquals, []string{"LNXSYSTM:00", "LNXSYBUS:00", "ACPI0004:00", "VMBUS:00"})
	c.Check(state.remaining, DeepEquals, []string{"f8b3781b-1e82-4818-a1c3-63d806ec15bb", "host6", "target6:0:0", "6:0:0:0", "block", "sdf"})
	c.Check(state.Interface, Equals, interfaceTypeVMBus)
	c.Check(state.Path, DeepEquals, efi.DevicePath{
		&efi.ACPIExtendedDevicePathNode{HIDStr: "VMBus"}})
}
