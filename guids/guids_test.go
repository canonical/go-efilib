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
	name, known := FileNameString(guid)
	c.Check(name, Equals, "AbsoluteAbtInstaller")
	c.Check(known, Equals, true)
}
