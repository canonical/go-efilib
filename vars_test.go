// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	. "gopkg.in/check.v1"

	. "github.com/canonical/go-efilib"
)

type varsSuite struct {
	restoreBackend func()
}

var _ = Suite(&varsSuite{})

func (s *varsSuite) SetUpTest(c *C) {
	s.restoreBackend = MockVarsBackend(NullVarsBackend{})
}

func (s *varsSuite) TearDownTest(c *C) {
	s.restoreBackend()
}

func (s *varsSuite) TestNullReadVariable(c *C) {
	_, _, err := ReadVariable("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}))
	c.Check(err, Equals, ErrVarsUnavailable)
}

func (s *varsSuite) TestNullWriteVariable(c *C) {
	err := WriteVariable("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, DecodeHexString(c, "0001"))
	c.Check(err, Equals, ErrVarsUnavailable)
}

func (s *varsSuite) TestNullListVariables(c *C) {
	_, err := ListVariables()
	c.Check(err, Equals, ErrVarsUnavailable)
}
