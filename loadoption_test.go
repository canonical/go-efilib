// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"bytes"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-efilib"
)

type loadoptionSuite struct{}

var _ = Suite(&loadoptionSuite{})

type testReadLoadOptionData struct {
	data     []byte
	expected *LoadOption
}

func (s *loadoptionSuite) testReadLoadOption(c *C, data *testReadLoadOptionData) {
	opt, err := ReadLoadOption(bytes.NewReader(data.data))
	c.Check(err, IsNil)
	c.Check(opt, DeepEquals, data.expected)
}

func (s *loadoptionSuite) TestReadLoadOption1(c *C) {
	s.testReadLoadOption(c, &testReadLoadOptionData{
		data: DecodeHexString(c, "0100000062007500620075006e0074007500000004012a0001000000000800000000000000001000000000007b94de66b2fd25"+
			"45b75230d66bb2b9600202040434005c004500460049005c007500620075006e00740075005c007300680069006d007800360034002e006500660069"+
			"0000007fff0400"),
		expected: &LoadOption{
			Attributes:  1,
			Description: "ubuntu",
			FilePath: DevicePath{
				&HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
					MBRType:         GPT},
				FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")},
			OptionalData: []byte{}}})
}

func (s *loadoptionSuite) TestReadLoadOption2(c *C) {
	s.testReadLoadOption(c, &testReadLoadOptionData{
		data: DecodeHexString(c, "0100000062004c0069006e007500780020004600690072006d0077006100720065002000550070006400610074006500720000"+
			"0004012a0001000000000800000000000000001000000000007b94de66b2fd2545b75230d66bb2b9600202040434005c004500460049005c00750062007500"+
			"6e00740075005c007300680069006d007800360034002e0065006600690000007fff04005c00660077007500700064007800360034002e006500660069000000"),
		expected: &LoadOption{
			Attributes:  1,
			Description: "Linux Firmware Updater",
			FilePath: DevicePath{
				&HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
					MBRType:         GPT},
				FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")},
			OptionalData: DecodeHexString(c, "5c00660077007500700064007800360034002e006500660069000000")}})
}

func (s *loadoptionSuite) TestReadLoadOption3(c *C) {
	s.testReadLoadOption(c, &testReadLoadOptionData{
		data: DecodeHexString(c, "010000002c004700720061007000680069006300200053006500740075007000000004071400edc5b6bdf36b0949837c353f6d"+
			"cbb6a2040614006478286b9c75c442b435a74ab694cd3b7fff0400"),
		expected: &LoadOption{
			Attributes:  1,
			Description: "Graphic Setup",
			FilePath: DevicePath{
				MediaFvDevicePathNode(MakeGUID(0xbdb6c5ed, 0x6bf3, 0x4909, 0x837c, [...]uint8{0x35, 0x3f, 0x6d, 0xcb, 0xb6, 0xa2})),
				MediaFvFileDevicePathNode(MakeGUID(0x6b287864, 0x759c, 0x42c4, 0xb435, [...]uint8{0xa7, 0x4a, 0xb6, 0x94, 0xcd, 0x3b}))},
			OptionalData: []byte{}}})
}

type testWriteLoadOptionData struct {
	option   *LoadOption
	expected []byte
}

func (s *loadoptionSuite) testWriteLoadOption(c *C, data *testWriteLoadOptionData) {
	w := new(bytes.Buffer)
	c.Check(data.option.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, data.expected)
}

func (s *loadoptionSuite) TestWriteLoadOption(c *C) {
	s.testWriteLoadOption(c, &testWriteLoadOptionData{
		expected: DecodeHexString(c, "0100000062007500620075006e0074007500000004012a0001000000000800000000000000001000000000007b94de66b2fd25"+
			"45b75230d66bb2b9600202040434005c004500460049005c007500620075006e00740075005c007300680069006d007800360034002e006500660069"+
			"0000007fff0400"),
		option: &LoadOption{
			Attributes:  1,
			Description: "ubuntu",
			FilePath: DevicePath{
				&HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
					MBRType:         GPT},
				FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}})
}

func (s *loadoptionSuite) TestWriteLoadOption2(c *C) {
	s.testWriteLoadOption(c, &testWriteLoadOptionData{
		expected: DecodeHexString(c, "0100000062004c0069006e007500780020004600690072006d0077006100720065002000550070006400610074006500720000"+
			"0004012a0001000000000800000000000000001000000000007b94de66b2fd2545b75230d66bb2b9600202040434005c004500460049005c00750062007500"+
			"6e00740075005c007300680069006d007800360034002e0065006600690000007fff04005c00660077007500700064007800360034002e006500660069000000"),
		option: &LoadOption{
			Attributes:  1,
			Description: "Linux Firmware Updater",
			FilePath: DevicePath{
				&HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
					MBRType:         GPT},
				FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")},
			OptionalData: DecodeHexString(c, "5c00660077007500700064007800360034002e006500660069000000")}})
}

func (s *loadoptionSuite) TestWriteLoadOption3(c *C) {
	s.testWriteLoadOption(c, &testWriteLoadOptionData{
		expected: DecodeHexString(c, "010000002c004700720061007000680069006300200053006500740075007000000004071400edc5b6bdf36b0949837c353f6d"+
			"cbb6a2040614006478286b9c75c442b435a74ab694cd3b7fff0400"),
		option: &LoadOption{
			Attributes:  1,
			Description: "Graphic Setup",
			FilePath: DevicePath{
				MediaFvDevicePathNode(MakeGUID(0xbdb6c5ed, 0x6bf3, 0x4909, 0x837c, [...]uint8{0x35, 0x3f, 0x6d, 0xcb, 0xb6, 0xa2})),
				MediaFvFileDevicePathNode(MakeGUID(0x6b287864, 0x759c, 0x42c4, 0xb435, [...]uint8{0xa7, 0x4a, 0xb6, 0x94, 0xcd, 0x3b}))},
			OptionalData: []byte{}}})
}
