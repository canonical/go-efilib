// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	. "github.com/canonical/go-efilib"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

type varsSuite struct{}

func (s *varsSuite) mockForRead(c *C) func() {
	return MockVarsRoot("testdata", unix.EFIVARFS_MAGIC)
}

var _ = Suite(&varsSuite{})

type testReadVarData struct {
	name          string
	guid          GUID
	expectedData  []byte
	expectedAttrs VariableAttributes
}

func (s *varsSuite) testReadVar(c *C, data *testReadVarData) {
	restore := s.mockForRead(c)
	defer restore()

	val, attrs, err := ReadVar(data.name, data.guid)
	c.Check(err, IsNil)
	c.Check(val, DeepEquals, data.expectedData)
	c.Check(attrs, Equals, data.expectedAttrs)
}

func (s *varsSuite) TestReadVar1(c *C) {
	s.testReadVar(c, &testReadVarData{
		name:          "SecureBoot",
		guid:          MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		expectedData:  []byte{0x01},
		expectedAttrs: AttributeBootserviceAccess | AttributeRuntimeAccess})
}

func (s *varsSuite) TestReadVar2(c *C) {
	s.testReadVar(c, &testReadVarData{
		name:          "Test",
		guid:          MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		expectedData:  decodeHexString(c, "a5a5a5a5"),
		expectedAttrs: AttributeNonVolatile | AttributeBootserviceAccess | AttributeRuntimeAccess})
}

func (s *varsSuite) TestReadVarNotFound(c *C) {
	restore := s.mockForRead(c)
	defer restore()

	_, _, err := ReadVar("NotFound", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVariableNotFound)
}

func (s *varsSuite) TestReadVarVarsUnavailable1(c *C) {
	restore := MockVarsRoot("testdata", unix.SYSFS_MAGIC)
	defer restore()

	_, _, err := ReadVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVarsUnavailable)
}

func (s *varsSuite) TestReadVarVarsUnavailable2(c *C) {
	restore := MockVarsRoot("/path/to/nonexistant/directory", unix.EFIVARFS_MAGIC)
	defer restore()

	_, _, err := ReadVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVarsUnavailable)
}
