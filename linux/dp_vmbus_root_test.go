// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
)

type vmbusRootSuite struct {
	TarFileMixin
}

var _ = Suite(&vmbusRootSuite{})

func (s *vmbusRootSuite) TestHandleVMBusRootDevicePathNodeSkip(c *C) {
	builder := &devicePathBuilderImpl{remaining: []string{"ACPI0004:00"}}
	c.Check(handleVMBusRootDevicePathNode(builder), Equals, errSkipDevicePathNodeHandler)
}

func (s *vmbusRootSuite) TestHandleVMBusRootDevicePathNode(c *C) {
	restore := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restore()

	builder := &devicePathBuilderImpl{
		iface:     interfaceTypeUnknown,
		processed: []string{"LNXSYSTM:00", "LNXSYBUS:00", "ACPI0004:00"},
		remaining: []string{"VMBUS:00", "f8b3781b-1e82-4818-a1c3-63d806ec15bb", "host6", "target6:0:0", "6:0:0:0", "block", "sdf"}}
	c.Check(handleVMBusRootDevicePathNode(builder), IsNil)
	c.Check(builder.processed, DeepEquals, []string{"LNXSYSTM:00", "LNXSYBUS:00", "ACPI0004:00", "VMBUS:00"})
	c.Check(builder.remaining, DeepEquals, []string{"f8b3781b-1e82-4818-a1c3-63d806ec15bb", "host6", "target6:0:0", "6:0:0:0", "block", "sdf"})
	c.Check(builder.iface, Equals, interfaceTypeVMBus)
	c.Check(builder.devPath, DeepEquals, efi.DevicePath{
		&efi.ACPIExtendedDevicePathNode{HIDStr: "VMBus"}})
}
