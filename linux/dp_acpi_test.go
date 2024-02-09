// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"path/filepath"

	efi "github.com/canonical/go-efilib"
	. "gopkg.in/check.v1"
)

type acpiSuite struct {
	TarFileMixin
}

var _ = Suite(&acpiSuite{})

func (s *acpiSuite) TestDecodeACPIOrPNPId1(c *C) {
	id, str := decodeACPIOrPNPId("PNP0a03")
	c.Check(id, Equals, efi.EISAID(0x0a0341d0))
	c.Check(str, Equals, "")
}

func (s *acpiSuite) TestDecodeACPIOrPNPId2(c *C) {
	id, str := decodeACPIOrPNPId("ACPI0008")
	c.Check(id, Equals, efi.EISAID(0))
	c.Check(str, Equals, "ACPI0008")
}

func (s *acpiSuite) TestMaybeUseSimpleACPIDevicePathNode1(c *C) {
	node, ok := maybeUseSimpleACPIDevicePathNode(&efi.ACPIExtendedDevicePathNode{HID: 0x0a0341d0}).(*efi.ACPIDevicePathNode)
	c.Assert(ok, Equals, true)
	c.Check(node.HID, Equals, efi.EISAID(0x0a0341d0))
	c.Check(node.UID, Equals, uint32(0))
}

func (s *acpiSuite) TestMaybeUseSimpleACPIDevicePathNode2(c *C) {
	node, ok := maybeUseSimpleACPIDevicePathNode(&efi.ACPIExtendedDevicePathNode{HID: 0x0a0341d0, CID: 0x0a0341d0}).(*efi.ACPIDevicePathNode)
	c.Assert(ok, Equals, true)
	c.Check(node.HID, Equals, efi.EISAID(0x0a0341d0))
	c.Check(node.UID, Equals, uint32(0))
}

func (s *acpiSuite) TestMaybeUseSimpleACPIDevicePathNode3(c *C) {
	node, ok := maybeUseSimpleACPIDevicePathNode(&efi.ACPIExtendedDevicePathNode{HID: 0x0a0841d0, CID: 0x0a0341d0}).(*efi.ACPIExtendedDevicePathNode)
	c.Assert(ok, Equals, true)
	c.Check(node.HID, Equals, efi.EISAID(0x0a0841d0))
	c.Check(node.UID, Equals, uint32(0))
	c.Check(node.CID, Equals, efi.EISAID(0x0a0341d0))
	c.Check(node.HIDStr, Equals, "")
	c.Check(node.UIDStr, Equals, "")
	c.Check(node.CIDStr, Equals, "")
}

func (s *acpiSuite) TestNewACPIExtendedDevicePathNode(c *C) {
	sysfs := filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys")

	node, err := newACPIExtendedDevicePathNode(filepath.Join(sysfs, "devices/LNXSYSTM:00/LNXSYBUS:00/PNP0A08:00"))
	c.Assert(err, IsNil)
	c.Check(node, DeepEquals, &efi.ACPIExtendedDevicePathNode{
		HID: 0x0a0841d0,
		CID: 0x0a0341d0})
}

func (s *acpiSuite) TestHandleACPIDevicePathNode(c *C) {
	restore := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restore()

	state := &devicePathBuilderState{remaining: []string{"LNXSYSTM:00", "LNXSYBUS:00", "PNP0A08:00"}}
	c.Check(handleACPIDevicePathNode(state), IsNil)
	c.Check(state.processed, DeepEquals, []string{"LNXSYSTM:00"})
	c.Check(state.remaining, DeepEquals, []string{"LNXSYBUS:00", "PNP0A08:00"})
	c.Check(state.Interface, Equals, interfaceTypeUnknown)
	c.Check(state.Path, DeepEquals, efi.DevicePath(nil))
}

func (s *acpiSuite) TestHandleACPIDevicePathNodeSkip(c *C) {
	restore := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restore()

	state := &devicePathBuilderState{remaining: []string{"virtual", "block", "loop1"}}
	c.Check(handleACPIDevicePathNode(state), Equals, errSkipDevicePathNodeHandler)
}
