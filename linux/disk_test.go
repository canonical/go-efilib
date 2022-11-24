// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux_test

import (
	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
	. "github.com/canonical/go-efilib/linux"
)

type diskSuite struct{}

var _ = Suite(&diskSuite{})

type testNewHardDriveDevicePathNodeFromDeviceData struct {
	part     int
	expected *efi.HardDriveDevicePathNode
}

func (s *diskSuite) testNewHardDriveDevicePathNodeFromDevice(c *C, data *testNewHardDriveDevicePathNodeFromDeviceData) {
	node, err := NewHardDriveDevicePathNodeFromDevice("../testdata/partitiontables/valid", data.part)
	c.Assert(err, IsNil)
	c.Check(node, DeepEquals, data.expected)
}

func (s *diskSuite) TestNewHardDriveDevicePathNodeFromDevice1(c *C) {
	s.testNewHardDriveDevicePathNodeFromDevice(c, &testNewHardDriveDevicePathNodeFromDeviceData{
		part: 1,
		expected: &efi.HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x22,
			PartitionSize:   0x12c,
			Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x506fddfc, 0xad5e, 0x4548, 0xb7dd, [...]uint8{0xe7, 0x73, 0x62, 0x17, 0x5c, 0x31})),
			MBRType:         efi.GPT}})
}

func (s *diskSuite) TestNewHardDriveDevicePathNodeFromDevice2(c *C) {
	s.testNewHardDriveDevicePathNodeFromDevice(c, &testNewHardDriveDevicePathNodeFromDeviceData{
		part: 3,
		expected: &efi.HardDriveDevicePathNode{
			PartitionNumber: 3,
			PartitionStart:  0x1b2,
			PartitionSize:   0x2d,
			Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x94da1fcc, 0x1c0f, 0x5645, 0xabf9, [...]uint8{0xff, 0x9a, 0xc4, 0x68, 0x24, 0x2d})),
			MBRType:         efi.GPT}})
}
