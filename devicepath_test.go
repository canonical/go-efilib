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
	c.Check(path.String(), Equals, "\\PciRoot(0x0)\\Pci(0x1d,0x0)\\Pci(0x0,0x0)\\NVMe(0x1-00-00-00-00-00-00-00-00)"+
		"\\HD(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960)\\\\EFI\\ubuntu\\shimx64.efi")

	expected := DevicePath{
		&ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x0},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x1d},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0},
		&NVMENamespaceDevicePathNode{
			NamespaceID:   0x1,
			NamespaceUUID: 0x0},
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}
	c.Check(path, DeepEquals, expected)
}

func (s *dpSuite) TestReadDevicePathUnrecognizedType(c *C) {
	r := bytes.NewReader(decodeHexString(c, "02ff1800000000000000000000000000564d42757300000001553400a2e5179b9108dd42b65380"+
		"b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656030208000000000004012a000f0000000028000000"+
		"0000000050030000000000dbfe3389532f0b49a2455c7fa1f986320202040434005c004500460049005c007500620075006e00740075005c0073"+
		"00680069006d007800360034002e0065006600690000007fff0400"))
	path, err := ReadDevicePath(r)
	c.Assert(err, IsNil)
	c.Check(path.String(), Equals, "\\AcpiPath(255,000000000000000000000000564d427573000000)"+
		"\\HardwarePath(85,a2e5179b9108dd42b65380b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656)"+
		"\\Scsi(0x0,0x0)\\HD(15,GPT,8933fedb-2f53-490b-a245-5c7fa1f98632)\\\\EFI\\ubuntu\\shimx64.efi")

	expected := DevicePath{
		&RawDevicePathNode{
			Type:    ACPIDevicePath,
			SubType: 0xff,
			Data:    decodeHexString(c, "000000000000000000000000564d427573000000")},
		&RawDevicePathNode{
			Type:    HardwareDevicePath,
			SubType: 0x55,
			Data:    decodeHexString(c, "a2e5179b9108dd42b65380b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656")},
		&SCSIDevicePathNode{
			PUN: 0,
			LUN: 0},
		&HardDriveDevicePathNode{
			PartitionNumber: 15,
			PartitionStart:  0x2800,
			PartitionSize:   0x35000,
			Signature:       MakeGUID(0x8933fedb, 0x2f53, 0x490b, 0xa245, [...]uint8{0x5c, 0x7f, 0xa1, 0xf9, 0x86, 0x32}),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}
	c.Check(path, DeepEquals, expected)
}

func (s *dpSuite) TestReadDevicePath2(c *C) {
	r := bytes.NewReader(decodeHexString(c, "02021800000000000000000000000000564d42757300000001043400a2e5179b9108dd42b65380"+
		"b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656030208000000000004012a000f0000000028000000"+
		"0000000050030000000000dbfe3389532f0b49a2455c7fa1f986320202040434005c004500460049005c007500620075006e00740075005c0073"+
		"00680069006d007800360034002e0065006600690000007fff0400"))
	path, err := ReadDevicePath(r)
	c.Assert(err, IsNil)
	c.Check(path.String(), Equals, "\\AcpiEx(VMBus,<nil>,0x0)"+
		"\\VenHw(9b17e5a2-0891-42dd-b653-80b5c22809ba,d96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656)"+
		"\\Scsi(0x0,0x0)\\HD(15,GPT,8933fedb-2f53-490b-a245-5c7fa1f98632)\\\\EFI\\ubuntu\\shimx64.efi")

	expected := DevicePath{
		&ACPIExtendedDevicePathNode{HIDStr: "VMBus"},
		&VendorDevicePathNode{
			Type: HardwareDevicePath,
			GUID: MakeGUID(0x9b17e5a2, 0x0891, 0x42dd, 0xb653, [...]uint8{0x80, 0xb5, 0xc2, 0x28, 0x09, 0xba}),
			Data: decodeHexString(c, "d96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656")},
		&SCSIDevicePathNode{
			PUN: 0,
			LUN: 0},
		&HardDriveDevicePathNode{
			PartitionNumber: 15,
			PartitionStart:  0x2800,
			PartitionSize:   0x35000,
			Signature:       MakeGUID(0x8933fedb, 0x2f53, 0x490b, 0xa245, [...]uint8{0x5c, 0x7f, 0xa1, 0xf9, 0x86, 0x32}),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}
	c.Check(path, DeepEquals, expected)
}

func (s *dpSuite) TestWriteDevicePath(c *C) {
	src := decodeHexString(c, "02010c00d041030a0000000001010600001d0101060000000317100001000000000000000000000004012a000100"+
		"0000000800000000000000001000000000007b94de66b2fd2545b75230d66bb2b9600202040434005c004500460049005c007500620075006e00740075005c007"+
		"300680069006d007800360034002e0065006600690000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(src))
	c.Assert(err, IsNil)

	w := new(bytes.Buffer)
	c.Check(path.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, src)
}

func (d *dpSuite) TestNewFilePathDevicePathNode(c *C) {
	p := NewFilePathDevicePathNode("EFI/ubuntu/shimx64.efi")
	c.Check(p, Equals, FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi"))
}

func (d *dpSuite) TestEISAID(c *C) {
	id := EISAID(0xa5a541d0)
	c.Check(id.Vendor(), Equals, "PNP")
	c.Check(id.Product(), DeepEquals, uint16(0xa5a5))
}
