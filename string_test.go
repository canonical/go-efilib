// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	. "gopkg.in/check.v1"

	. "github.com/canonical/go-efilib"
)

type stringSuite struct{}

var _ = Suite(&stringSuite{})

func (s *stringSuite) TestUTF16ConversionASCII(c *C) {
	u8 := "abcdefg"
	u16 := ConvertUTF8ToUTF16(u8)
	c.Check(u16, DeepEquals, []uint16{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67})
	c.Check(ConvertUTF16ToUTF8(append(u16, 0)), Equals, u8)
}

func (s *stringSuite) TestUCS2ConversionASCII(c *C) {
	u8 := "abcdefg"
	u16 := ConvertUTF8ToUCS2(u8)
	c.Check(u16, DeepEquals, []uint16{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67})
	c.Check(ConvertUTF16ToUTF8(append(u16, 0)), Equals, u8)
}

func (s *stringSuite) TestUTF16ConversionBMP(c *C) {
	u8 := "αβγδεζη"
	u16 := ConvertUTF8ToUTF16(u8)
	c.Check(u16, DeepEquals, []uint16{0x3b1, 0x3b2, 0x3b3, 0x3b4, 0x3b5, 0x3b6, 0x3b7})
	c.Check(ConvertUTF16ToUTF8(append(u16, 0)), Equals, u8)
}

func (s *stringSuite) TestUCS2ConversionBMP(c *C) {
	u8 := "αβγδεζη"
	u16 := ConvertUTF8ToUCS2(u8)
	c.Check(u16, DeepEquals, []uint16{0x3b1, 0x3b2, 0x3b3, 0x3b4, 0x3b5, 0x3b6, 0x3b7})
	c.Check(ConvertUTF16ToUTF8(append(u16, 0)), Equals, u8)
}

func (s *stringSuite) TestUTF16ConversionSymbols(c *C) {
	u8 := "😸💩🌷❗"
	u16 := ConvertUTF8ToUTF16(u8)
	c.Check(u16, DeepEquals, []uint16{0xd83d, 0xde38, 0xd83d, 0xdca9, 0xd83c, 0xdf37, 0x2757})
	c.Check(ConvertUTF16ToUTF8(append(u16, 0)), Equals, u8)
}

func (s *stringSuite) TestUCS2ConversionSymbols(c *C) {
	u8 := "😸💩🌷❗"
	u16 := ConvertUTF8ToUCS2(u8)
	c.Check(u16, DeepEquals, []uint16{0xfffd, 0xfffd, 0xfffd, 0x2757})
	c.Check(ConvertUTF16ToUTF8(append(u16, 0)), Equals, "���❗")
}
