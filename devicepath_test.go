// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"bytes"

	. "github.com/canonical/go-efilib"

	. "gopkg.in/check.v1"
)

type dpSuite struct{}

var _ = Suite(&dpSuite{})

func (s *dpSuite) TestReadDevicePath(c *C) {
	r := bytes.NewReader(decodeHexString(c, "02010c00d041030a0000000001010600001d0101060000000317100001000000000000000000000004012a000100"+
		"0000000800000000000000001000000000007b94de66b2fd2545b75230d66bb2b9600202040434005c004500460049005c007500620075006e00740075005c007"+
		"300680069006d007800360034002e0065006600690000007fff0400"))
	path, err := ReadDevicePath(r)
	c.Assert(err, IsNil)
	c.Check(path.String(), Equals, "\\PciRoot(0x0)\\Pci(0x1d,0x0)\\Pci(0x0,0x0)\\NVMe(0x1-0x00-0x00-0x00-0x00-0x00-0x00-0x00-0x00)"+
		"\\HD(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960,0x0000000000000800,0x0000000000100000)\\\\EFI\\ubuntu\\shimx64.efi")
}

func (s *dpSuite) TestWriteDevicePath(c *C) {
	src := decodeHexString(c, "02010c00d041030a0000000001010600001d0101060000000317100001000000000000000000000004012a000100"+
		"0000000800000000000000001000000000007b94de66b2fd2545b75230d66bb2b9600202040434005c004500460049005c007500620075006e00740075005c007"+
		"300680069006d007800360034002e0065006600690000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(src))
	c.Assert(err, IsNil)

	w := new(bytes.Buffer)
	c.Check(path.WriteTo(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, src)
}
