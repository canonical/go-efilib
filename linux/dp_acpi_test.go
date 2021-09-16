// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
)

type acpiSuite struct {
	TarFileMixin
}

var _ = Suite(&acpiSuite{})

func (s *acpiSuite) TestDecodeACPIOrPNPId1(c *C) {
	vendor, product, err := decodeACPIOrPNPId("PNP0a03")
	c.Check(err, IsNil)
	c.Check(vendor, Equals, "PNP")
	c.Check(product, Equals, uint16(0x0a03))
}

func (s *acpiSuite) TestDecodeACPIOrPNPId2(c *C) {
	vendor, product, err := decodeACPIOrPNPId("ACPI0008")
	c.Check(err, IsNil)
	c.Check(vendor, Equals, "ACPI")
	c.Check(product, Equals, uint16(0x0008))
}

func (s *acpiSuite) TestDecodeACPIOrPNPIdInvalid1(c *C) {
	_, _, err := decodeACPIOrPNPId("XXXXX0000")
	c.Check(err, ErrorMatches, "invalid length")
}

func (s *acpiSuite) TestDecodeACPIOrPNPIdInvalid2(c *C) {
	_, _, err := decodeACPIOrPNPId("XXXXX000")
	c.Check(err, ErrorMatches, "invalid ID")
}

func (s *acpiSuite) TestNewEISAIDOrStringPNP(c *C) {
	id, str, err := newEISAIDOrString("PNP", 0x0a08)
	c.Check(err, IsNil)
	c.Check(id, Equals, efi.EISAID(0x0a0841d0))
	c.Check(str, Equals, "")
}

func (s *acpiSuite) TestNewEISAIDOrStringACPI(c *C) {
	id, str, err := newEISAIDOrString("ACPI", 0x0001)
	c.Check(err, IsNil)
	c.Check(id, Equals, efi.EISAID(0))
	c.Check(str, Equals, "ACPI0001")
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

	node, err := newACPIExtendedDevicePathNode(filepath.Join(sysfs, "devices/pci0000:00"))
	c.Assert(err, IsNil)
	c.Check(node, DeepEquals, &efi.ACPIExtendedDevicePathNode{
		HID: 0x0a0841d0,
		CID: 0x0a0341d0})
}
