// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package guids_test

import (
	"testing"

	efi "github.com/canonical/go-efilib"
	. "github.com/canonical/go-efilib/guids"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type guidsSuite struct{}

var _ = Suite(&guidsSuite{})

func (s *guidsSuite) TestAbsoluteAbtInstaller(c *C) {
	guid := efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d})
	name, known := IndustryStandardString(guid)
	c.Check(name, Equals, "AbsoluteAbtInstaller")
	c.Check(known, Equals, true)
}

func (s *guidsSuite) TestCpuDxe(c *C) {
	guid := efi.MakeGUID(0xee993080, 0x5197, 0x4d4e, 0xb63c, [...]byte{0xf1, 0xf7, 0x41, 0x3e, 0x33, 0xce})
	name, known := IndustryStandardString(guid)
	c.Check(name, Equals, "CpuDxe")
	c.Check(known, Equals, true)
}

func (s *guidsSuite) TestUnknown(c *C) {
	guid := efi.MakeGUID(0x840ae51a, 0x12a5, 0x4cc5, 0x9c1c, [...]byte{0x3c, 0x84, 0x4c, 0xc4, 0x6b, 0x53})
	_, known := IndustryStandardString(guid)
	c.Check(known, Equals, false)
}

func (s *guidsSuite) TestListAll(c *C) {
	guids := ListAllKnown()
	c.Check(guids, DeepEquals, allGuids)
}

func (s *guidsSuite) TestFvFileIntegration(c *C) {
	file := efi.FWFileDevicePathNode(efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}))
	c.Check(file.String(), Equals, "FvFile(AbsoluteAbtInstaller)")
}
