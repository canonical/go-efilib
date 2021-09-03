// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"bytes"

	. "github.com/canonical/go-efilib"

	. "gopkg.in/check.v1"
)

type guidSuite struct{}

var _ = Suite(&guidSuite{})

type testMakeGUIDData struct {
	a        uint32
	b        uint16
	c        uint16
	d        uint16
	e        [6]uint8
	expected []byte
}

func (s *guidSuite) testMakeGUID(c *C, data *testMakeGUIDData) {
	g := MakeGUID(data.a, data.b, data.c, data.d, data.e)
	var expected GUID
	copy(expected[:], data.expected)
	c.Check(g, Equals, expected)
}

func (s *guidSuite) TestMakeGUID1(c *C) {
	s.testMakeGUID(c, &testMakeGUIDData{
		a: 0x8be4df61, b: 0x93ca, c: 0x11d2, d: 0xaa0d, e: [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c},
		expected: decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8c")})
}

func (s *guidSuite) TestMakeGUID2(c *C) {
	s.testMakeGUID(c, &testMakeGUIDData{
		a: 0xd719b2cb, b: 0x3d3a, c: 0x4596, d: 0xa3bc, e: [...]uint8{0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f},
		expected: decodeHexString(c, "cbb219d73a3d9645a3bcdad00e67656f")})
}

type testGUIDStringData struct {
	x        []byte
	expected string
}

func (s *guidSuite) testGUIDString(c *C, data *testGUIDStringData) {
	var g GUID
	copy(g[:], data.x)
	c.Check(g.String(), Equals, data.expected)
}

func (s *guidSuite) TestGUIDString1(c *C) {
	s.testGUIDString(c, &testGUIDStringData{
		x:        decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8c"),
		expected: "8be4df61-93ca-11d2-aa0d-00e098032b8c"})
}

func (s *guidSuite) TestGUIDString2(c *C) {
	s.testGUIDString(c, &testGUIDStringData{
		x:        decodeHexString(c, "cbb219d73a3d9645a3bcdad00e67656f"),
		expected: "d719b2cb-3d3a-4596-a3bc-dad00e67656f"})
}

type testReadGUIDData struct {
	r        *bytes.Reader
	expected []byte
}

func (s *guidSuite) testReadGUID(c *C, data *testReadGUIDData) {
	start := data.r.Len()
	out, err := ReadGUID(data.r)
	c.Check(err, IsNil)
	c.Check(start-data.r.Len(), Equals, 16)
	var expected GUID
	copy(expected[:], data.expected)
	c.Check(out, Equals, expected)
}

func (s *guidSuite) TestReadGUID1(c *C) {
	s.testReadGUID(c, &testReadGUIDData{
		r:        bytes.NewReader(decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8c")),
		expected: decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8c")})
}

func (s *guidSuite) TestReadGUID2(c *C) {
	s.testReadGUID(c, &testReadGUIDData{
		r:        bytes.NewReader(decodeHexString(c, "cbb219d73a3d9645a3bcdad00e67656f")),
		expected: decodeHexString(c, "cbb219d73a3d9645a3bcdad00e67656f")})
}

func (s *guidSuite) TestReadGUID3(c *C) {
	s.testReadGUID(c, &testReadGUIDData{
		r:        bytes.NewReader(decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8caaaaaaaaaaaaaa")),
		expected: decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8c")})
}

type testDecodeGUIDStringData struct {
	str      string
	expected GUID
}

func (s *guidSuite) testDecodeGUIDString(c *C, data *testDecodeGUIDStringData) {
	guid, err := DecodeGUIDString(data.str)
	c.Check(err, IsNil)
	c.Check(guid, Equals, data.expected)
}

func (s *guidSuite) TestDecodeGUIDString1(c *C) {
	s.testDecodeGUIDString(c, &testDecodeGUIDStringData{
		str:      "8be4df61-93ca-11d2-aa0d-00e098032b8c",
		expected: MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c})})
}

func (s *guidSuite) TestDecodeGUIDString2(c *C) {
	s.testDecodeGUIDString(c, &testDecodeGUIDStringData{
		str:      "{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
		expected: MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c})})
}

func (s *guidSuite) TestDecodeGUIDString3(c *C) {
	s.testDecodeGUIDString(c, &testDecodeGUIDStringData{
		str:      "d719b2cb-3d3a-4596-a3bc-dad00e67656f",
		expected: MakeGUID(0xd719b2cb, 0x3d3a, 0x4596, 0xa3bc, [...]uint8{0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f})})
}

func (s *guidSuite) TestDecodeGUIDStringInvalid(c *C) {
	_, err := DecodeGUIDString("8be4df61-93ca-11d2-aa0d00e098032b8c")
	c.Check(err, ErrorMatches, "invalid format")
}
