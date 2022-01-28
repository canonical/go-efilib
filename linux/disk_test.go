// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux_test

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
	. "github.com/canonical/go-efilib/linux"
)

type diskSuite struct{}

var _ = Suite(&diskSuite{})

type testNewHardDriveDevicePathNodeFromDeviceData struct {
	part     int
	expected *efi.HardDriveDevicePathNode
}

func (s *diskSuite) testNewHardDriveDevicePathNodeFromDevice(c *C, data *testNewHardDriveDevicePathNodeFromDeviceData) {
	node, err := NewHardDriveDevicePathNodeFromDevice("../testdata/partitiontables/cloudimg", data.part)
	c.Assert(err, IsNil)
	c.Check(node, DeepEquals, data.expected)
}

func (s *diskSuite) TestNewHardDriveDevicePathNodeFromDevice1(c *C) {
	s.testNewHardDriveDevicePathNodeFromDevice(c, &testNewHardDriveDevicePathNodeFromDeviceData{
		part: 1,
		expected: &efi.HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x37800,
			PartitionSize:   0x42e7df,
			Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x15eae969, 0x91f2, 0x437b, 0x95cc, [...]uint8{0xec, 0x11, 0xd3, 0x40, 0x95, 0x9b})),
			MBRType:         efi.GPT}})
}

func (s *diskSuite) TestNewHardDriveDevicePathNodeFromDevice2(c *C) {
	s.testNewHardDriveDevicePathNodeFromDevice(c, &testNewHardDriveDevicePathNodeFromDeviceData{
		part: 14,
		expected: &efi.HardDriveDevicePathNode{
			PartitionNumber: 14,
			PartitionStart:  0x800,
			PartitionSize:   0x2000,
			Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x71c94a7b, 0xfa01, 0x416c, 0x9cdd, [...]uint8{0x60, 0x02, 0x5b, 0x54, 0xd8, 0xd2})),
			MBRType:         efi.GPT}})
}
