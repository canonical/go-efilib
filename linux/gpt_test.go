// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux_test

import (
	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
	. "github.com/canonical/go-efilib/linux"
)

type gptSuite struct{}

var _ = Suite(&gptSuite{})

type testReadPartitionTableData struct {
	path            string
	role            efi.PartitionTableRole
	checkCrc        bool
	expectedHeader  *efi.PartitionTableHeader
	expectedEntries map[int]*efi.PartitionEntry
}

func (s *gptSuite) testReadPartitionTable(c *C, data *testReadPartitionTableData) {
	table, err := ReadPartitionTable(data.path, data.role, data.checkCrc)
	c.Assert(err, IsNil)

	c.Check(table.Hdr, DeepEquals, data.expectedHeader)
	c.Assert(table.Entries, HasLen, int(data.expectedHeader.NumberOfPartitionEntries))
	expected := make([]*efi.PartitionEntry, len(table.Entries))
	for i := 0; i < len(expected); i++ {
		expected[i] = new(efi.PartitionEntry)
	}
	for i, e := range data.expectedEntries {
		expected[i] = e
	}
	c.Check(table.Entries, DeepEquals, expected)
}

func (s *gptSuite) TestReadPartitionTablePrimaryOK(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path:     "../testdata/partitiontables/valid",
		role:     efi.PrimaryPartitionTable,
		checkCrc: true,
		expectedHeader: &efi.PartitionTableHeader{
			HeaderSize:               0x5c,
			MyLBA:                    0x1,
			AlternateLBA:             0x1ff,
			FirstUsableLBA:           0x22,
			LastUsableLBA:            0x1de,
			DiskGUID:                 efi.MakeGUID(0x0eab22a8, 0x78e2, 0x9b4d, 0xb3fa, [...]uint8{0x7f, 0xdb, 0x73, 0x66, 0xd1, 0x5c}),
			PartitionEntryLBA:        0x2,
			NumberOfPartitionEntries: 0x80,
			SizeOfPartitionEntry:     0x80,
			PartitionEntryArrayCRC32: 0x9bc862a2,
		},
		expectedEntries: map[int]*efi.PartitionEntry{
			0: &efi.PartitionEntry{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0x506fddfc, 0xad5e, 0x4548, 0xb7dd, [...]uint8{0xe7, 0x73, 0x62, 0x17, 0x5c, 0x31}),
				StartingLBA:         34,
				EndingLBA:           333},
			1: &efi.PartitionEntry{
				PartitionTypeGUID:   efi.MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: efi.MakeGUID(0x5ff783fc, 0xa97c, 0x684f, 0xacd8, [...]uint8{0xe1, 0x70, 0x28, 0xf6, 0x1c, 0x5f}),
				StartingLBA:         334,
				EndingLBA:           433},
			2: &efi.PartitionEntry{
				PartitionTypeGUID:   efi.MakeGUID(0x21686148, 0x6449, 0x6e6f, 0x744e, [...]uint8{0x65, 0x65, 0x64, 0x45, 0x46, 0x49}),
				UniquePartitionGUID: efi.MakeGUID(0x94da1fcc, 0x1c0f, 0x5645, 0xabf9, [...]uint8{0xff, 0x9a, 0xc4, 0x68, 0x24, 0x2d}),
				StartingLBA:         434,
				EndingLBA:           478},
		},
	})
}

func (s *gptSuite) TestReadPartitionTableBackupOK(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path:     "../testdata/partitiontables/valid",
		role:     efi.BackupPartitionTable,
		checkCrc: true,
		expectedHeader: &efi.PartitionTableHeader{
			HeaderSize:               0x5c,
			MyLBA:                    0x1ff,
			AlternateLBA:             0x1,
			FirstUsableLBA:           0x22,
			LastUsableLBA:            0x1de,
			DiskGUID:                 efi.MakeGUID(0x0eab22a8, 0x78e2, 0x9b4d, 0xb3fa, [...]uint8{0x7f, 0xdb, 0x73, 0x66, 0xd1, 0x5c}),
			PartitionEntryLBA:        0x1df,
			NumberOfPartitionEntries: 0x80,
			SizeOfPartitionEntry:     0x80,
			PartitionEntryArrayCRC32: 0x9bc862a2,
		},
		expectedEntries: map[int]*efi.PartitionEntry{
			0: &efi.PartitionEntry{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0x506fddfc, 0xad5e, 0x4548, 0xb7dd, [...]uint8{0xe7, 0x73, 0x62, 0x17, 0x5c, 0x31}),
				StartingLBA:         34,
				EndingLBA:           333},
			1: &efi.PartitionEntry{
				PartitionTypeGUID:   efi.MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: efi.MakeGUID(0x5ff783fc, 0xa97c, 0x684f, 0xacd8, [...]uint8{0xe1, 0x70, 0x28, 0xf6, 0x1c, 0x5f}),
				StartingLBA:         334,
				EndingLBA:           433},
			2: &efi.PartitionEntry{
				PartitionTypeGUID:   efi.MakeGUID(0x21686148, 0x6449, 0x6e6f, 0x744e, [...]uint8{0x65, 0x65, 0x64, 0x45, 0x46, 0x49}),
				UniquePartitionGUID: efi.MakeGUID(0x94da1fcc, 0x1c0f, 0x5645, 0xabf9, [...]uint8{0xff, 0x9a, 0xc4, 0x68, 0x24, 0x2d}),
				StartingLBA:         434,
				EndingLBA:           478},
		},
	})
}

func (s *gptSuite) TestReadPartitionTableInvalidPrimaryNoCheck(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path: "../testdata/partitiontables/invalid-primary-hdr-checksum",
		role: efi.PrimaryPartitionTable,
		expectedHeader: &efi.PartitionTableHeader{
			HeaderSize:               0x5c,
			MyLBA:                    0x1,
			AlternateLBA:             0x1ff,
			FirstUsableLBA:           0x22,
			LastUsableLBA:            0x1de,
			DiskGUID:                 efi.MakeGUID(0x0eab22a8, 0x78e2, 0x9b4d, 0xb3fa, [...]uint8{0x7f, 0xdb, 0x73, 0x66, 0xd1, 0x5c}),
			PartitionEntryLBA:        0x2,
			NumberOfPartitionEntries: 0x80,
			SizeOfPartitionEntry:     0x80,
			PartitionEntryArrayCRC32: 0x9bc862a2,
		},
		expectedEntries: map[int]*efi.PartitionEntry{
			0: &efi.PartitionEntry{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0x506fddfc, 0xad5e, 0x4548, 0xb7dd, [...]uint8{0xe7, 0x73, 0x62, 0x17, 0x5c, 0x31}),
				StartingLBA:         34,
				EndingLBA:           333},
			1: &efi.PartitionEntry{
				PartitionTypeGUID:   efi.MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: efi.MakeGUID(0x5ff783fc, 0xa97c, 0x684f, 0xacd8, [...]uint8{0xe1, 0x70, 0x28, 0xf6, 0x1c, 0x5f}),
				StartingLBA:         334,
				EndingLBA:           433},
			2: &efi.PartitionEntry{
				PartitionTypeGUID:   efi.MakeGUID(0x21686148, 0x6449, 0x6e6f, 0x744e, [...]uint8{0x65, 0x65, 0x64, 0x45, 0x46, 0x49}),
				UniquePartitionGUID: efi.MakeGUID(0x94da1fcc, 0x1c0f, 0x5645, 0xabf9, [...]uint8{0xff, 0x9a, 0xc4, 0x68, 0x24, 0x2d}),
				StartingLBA:         434,
				EndingLBA:           478},
		},
	})
}

func (s *gptSuite) TestReadPartitionTableInvalidPrimaryHeader1(c *C) {
	_, err := ReadPartitionTable("../testdata/partitiontables/invalid-primary-hdr-checksum", efi.PrimaryPartitionTable, true)
	c.Check(err, Equals, efi.ErrCRCCheck)
}
