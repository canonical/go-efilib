// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package mbr_test

import (
	"os"
	"testing"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-efilib/mbr"
)

func Test(t *testing.T) { TestingT(t) }

type mbrSuite struct{}

var _ = Suite(&mbrSuite{})

func (s *mbrSuite) TestReadRecordLegacy(c *C) {
	f, err := os.Open("../testdata/partitiontables/mbr")
	c.Assert(err, IsNil)
	defer f.Close()

	r, err := ReadRecord(f)
	c.Assert(err, IsNil)
	c.Check(r.UniqueSignature, Equals, uint32(0xa773bf3f))
	c.Check(r.Partitions[0], DeepEquals, PartitionEntry{
		BootIndicator:   0x80,
		StartAddress:    Address{0x20, 0x21, 0x0},
		Type:            0x83,
		EndAddress:      Address{0x45, 0x2d, 0xd8},
		StartingLBA:     0x800,
		NumberOfSectors: 0x1300000})
	c.Check(r.Partitions[1], DeepEquals, PartitionEntry{
		StartAddress:    Address{0x45, 0x2e, 0xd8},
		Type:            0x5,
		EndAddress:      Address{0x6a, 0x51, 0x19},
		StartingLBA:     0x1300800,
		NumberOfSectors: 0xff800})
	c.Check(r.Partitions[2], DeepEquals, PartitionEntry{})
	c.Check(r.Partitions[3], DeepEquals, PartitionEntry{})
}

func (s *mbrSuite) TestReadRecordProtectiveMBR(c *C) {
	f, err := os.Open("../testdata/partitiontables/valid")
	c.Assert(err, IsNil)
	defer f.Close()

	r, err := ReadRecord(f)
	c.Assert(err, IsNil)
	c.Check(r.UniqueSignature, Equals, uint32(0))
	c.Check(r.Partitions[0], DeepEquals, PartitionEntry{
		StartAddress:    Address{0x0, 0x2, 0x0},
		Type:            0xee,
		EndAddress:      Address{0xff, 0xff, 0xff},
		StartingLBA:     0x1,
		NumberOfSectors: 0x1ff})
	c.Check(r.Partitions[1], DeepEquals, PartitionEntry{})
	c.Check(r.Partitions[2], DeepEquals, PartitionEntry{})
	c.Check(r.Partitions[3], DeepEquals, PartitionEntry{})
}
