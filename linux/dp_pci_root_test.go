// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
)

type pciRootSuite struct{}

var _ = Suite(&pciRootSuite{})

func (s *pciRootSuite) TestHandlePCIRootDevicePathNodeSkip(c *C) {
	builder := &devicePathBuilderImpl{remaining: []string{"0000:00:1d.0"}}
	c.Check(handlePCIRootDevicePathNode(builder, nil), Equals, errSkipDevicePathNodeHandler)
}

func (s *pciRootSuite) TestHandlePCIRootDevicePathNode(c *C) {
	restoreSysfs := MockSysfsPath("testdata/sys")
	defer restoreSysfs()

	builder := &devicePathBuilderImpl{
		dev:       &dev{node: "/dev/nvme0n1", part: 1},
		remaining: []string{"pci0000:00"}}
	c.Check(handlePCIRootDevicePathNode(builder, builder.dev), IsNil)
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00"})
	c.Check(builder.remaining, DeepEquals, []string{})
	c.Check(builder.dev.devPath, DeepEquals, efi.DevicePath{&efi.ACPIDevicePathNode{HID: 0x0a0341d0}})
	c.Check(builder.dev.devPathIsFull, Equals, true)
}
