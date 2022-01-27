// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
)

type pciRootSuite struct {
	TarFileMixin
}

var _ = Suite(&pciRootSuite{})

func (s *pciRootSuite) TestHandlePCIRootDevicePathNodeSkip(c *C) {
	builder := &devicePathBuilderImpl{remaining: []string{"ACPI0004:00"}}
	c.Check(handlePCIRootDevicePathNode(builder), Equals, errSkipDevicePathNodeHandler)
}

func (s *pciRootSuite) TestHandlePCIRootDevicePathNode(c *C) {
	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	builder := &devicePathBuilderImpl{remaining: []string{"pci0000:00"}}
	c.Check(handlePCIRootDevicePathNode(builder), IsNil)
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00"})
	c.Check(builder.remaining, DeepEquals, []string{})
	c.Check(builder.iface, Equals, interfaceTypePCI)
	c.Check(builder.devPath, DeepEquals, efi.DevicePath{&efi.ACPIDevicePathNode{HID: 0x0a0341d0}})
}
