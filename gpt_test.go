// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"bytes"
	"fmt"
	"os"

	. "github.com/canonical/go-efilib"

	. "gopkg.in/check.v1"
)

type gptSuite struct{}

var _ = Suite(&gptSuite{})

type testReadPartitionTableHeaderData struct {
	r        *bytes.Reader
	checkCrc bool
	expected *PartitionTableHeader
	errMatch string
}

func (s *gptSuite) testReadPartitionTableHeader(c *C, data *testReadPartitionTableHeaderData) {
	start := data.r.Len()
	out, err := ReadPartitionTableHeader(data.r, data.checkCrc)
	if data.errMatch == "" {
		c.Check(err, IsNil)
		c.Check(out, DeepEquals, data.expected)
	} else {
		c.Check(err, ErrorMatches, data.errMatch)
	}
	c.Check(start-data.r.Len(), Equals, 92)
}

func (s *gptSuite) TestReadPartitionTableHeader1(c *C) {
	s.testReadPartitionTableHeader(c, &testReadPartitionTableHeaderData{
		r: bytes.NewReader(DecodeHexString(c, "4546492050415254000001005c000000edeb4e64000000000100000000000000af5277ee000000002200000000"+
			"0000008e5277ee00000000c273aea42f0e1345bd3c456da7f7f0fd02000000000000008000000080000000f628450b")),
		checkCrc: true,
		expected: &PartitionTableHeader{
			HeaderSize:               92,
			MyLBA:                    1,
			AlternateLBA:             4000797359,
			FirstUsableLBA:           34,
			LastUsableLBA:            4000797326,
			DiskGUID:                 MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
			PartitionEntryLBA:        2,
			NumberOfPartitionEntries: 128,
			SizeOfPartitionEntry:     128,
			PartitionEntryArrayCRC32: 189081846}})
}

func (s *gptSuite) TestReadPartitionTableHeader2(c *C) {
	s.testReadPartitionTableHeader(c, &testReadPartitionTableHeaderData{
		r: bytes.NewReader(DecodeHexString(c, "4546492050415254000001005c000000edeb4e64000000000100000000000000af5277ee000000002200000000"+
			"0000008e5277ee00000000c273aea42f0e1345bd3c456da7f7f0fd02000000000000008000000080000000f628450ba5a5a5a5a5a5a5a5")),
		checkCrc: true,
		expected: &PartitionTableHeader{
			HeaderSize:               92,
			MyLBA:                    1,
			AlternateLBA:             4000797359,
			FirstUsableLBA:           34,
			LastUsableLBA:            4000797326,
			DiskGUID:                 MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
			PartitionEntryLBA:        2,
			NumberOfPartitionEntries: 128,
			SizeOfPartitionEntry:     128,
			PartitionEntryArrayCRC32: 189081846}})
}

func (s *gptSuite) TestReadPartitionTableHeader3(c *C) {
	s.testReadPartitionTableHeader(c, &testReadPartitionTableHeaderData{
		r: bytes.NewReader(DecodeHexString(c, "4546492050415254000001005c000000edeb4e65000000000100000000000000af5277ee000000002200000000"+
			"0000008e5277ee00000000c273aea42f0e1345bd3c456da7f7f0fd02000000000000008000000080000000f628450b")),
		checkCrc: true,
		errMatch: "CRC check failed"})
}

func (s *gptSuite) TestReadPartitionTableHeader4(c *C) {
	s.testReadPartitionTableHeader(c, &testReadPartitionTableHeaderData{
		r: bytes.NewReader(DecodeHexString(c, "4546492050415254000001005c000000edeb4e65000000000100000000000000af5277ee000000002200000000"+
			"0000008e5277ee00000000c273aea42f0e1345bd3c456da7f7f0fd02000000000000008000000080000000f628450b")),
		expected: &PartitionTableHeader{
			HeaderSize:               92,
			MyLBA:                    1,
			AlternateLBA:             4000797359,
			FirstUsableLBA:           34,
			LastUsableLBA:            4000797326,
			DiskGUID:                 MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
			PartitionEntryLBA:        2,
			NumberOfPartitionEntries: 128,
			SizeOfPartitionEntry:     128,
			PartitionEntryArrayCRC32: 189081846}})
}

func (s *gptSuite) TestWritePartitionTableHeader(c *C) {
	header := PartitionTableHeader{
		HeaderSize:               92,
		MyLBA:                    1,
		AlternateLBA:             4000797359,
		FirstUsableLBA:           34,
		LastUsableLBA:            4000797326,
		DiskGUID:                 MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
		PartitionEntryLBA:        2,
		NumberOfPartitionEntries: 128,
		SizeOfPartitionEntry:     128,
		PartitionEntryArrayCRC32: 189081846}

	w := new(bytes.Buffer)
	c.Check(header.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, DecodeHexString(c, "4546492050415254000001005c000000edeb4e64000000000100000000000000af5277ee00000000"+
		"22000000000000008e5277ee00000000c273aea42f0e1345bd3c456da7f7f0fd02000000000000008000000080000000f628450b"))
}

type testDecodePartitionEntriesData struct {
	r        *bytes.Reader
	num      uint32
	sz       uint32
	expected []*PartitionEntry
}

func (s *gptSuite) testDecodePartitionEntries(c *C, data *testDecodePartitionEntriesData) {
	start := data.r.Len()
	ents, err := ReadPartitionEntries(data.r, data.num, data.sz)
	c.Check(err, IsNil)
	c.Check(ents, DeepEquals, data.expected)
	c.Check(start-data.r.Len(), Equals, int(data.num*data.sz))
}

func (s *gptSuite) TestDecodePartitionEntries1(c *C) {
	s.testDecodePartitionEntries(c, &testDecodePartitionEntriesData{
		r: bytes.NewReader(DecodeHexString(c, "28732ac11ff8d211ba4b00a0c93ec93b7b94de66b2fd2545b75230d66bb2b9600008000000000000ff071000"+
			"0000000000000000000000004500460049002000530079007300740065006d00200050006100720074006900740069006f006e00000000000000000000000000"+
			"0000000000000000000000000000000000000000")),
		num: 1,
		sz:  128,
		expected: []*PartitionEntry{{
			PartitionTypeGUID:   MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
			UniquePartitionGUID: MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
			StartingLBA:         2048,
			EndingLBA:           1050623,
			Attributes:          0,
			PartitionName:       "EFI System Partition"}}})
}

func (s *gptSuite) TestDecodePartitionEntries2(c *C) {
	s.testDecodePartitionEntries(c, &testDecodePartitionEntriesData{
		r: bytes.NewReader(DecodeHexString(c, "af3dc60f838472478e793d69d8477de4dc171b63b7ed1d4da7616dce3efce4150008100000000000ffe72600000"+
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"+
			"0000000000000000000000000000000000000")),
		num: 1,
		sz:  128,
		expected: []*PartitionEntry{{
			PartitionTypeGUID:   MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
			UniquePartitionGUID: MakeGUID(0x631b17dc, 0xedb7, 0x4d1d, 0xa761, [...]uint8{0x6d, 0xce, 0x3e, 0xfc, 0xe4, 0x15}),
			StartingLBA:         1050624,
			EndingLBA:           2549759,
			Attributes:          0,
			PartitionName:       ""}}})
}

func (s *gptSuite) TestDecodePartitionEntries3(c *C) {
	s.testDecodePartitionEntries(c, &testDecodePartitionEntriesData{
		r: bytes.NewReader(DecodeHexString(c, "af3dc60f838472478e793d69d8477de4dc171b63b7ed1d4da7616dce3efce4150008100000000000ffe72600000"+
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"+
			"000000000000000000000000000000000000028732ac11ff8d211ba4b00a0c93ec93b7b94de66b2fd2545b75230d66bb2b9600008000000000000ff071000000"+
			"0000000000000000000004500460049002000530079007300740065006d00200050006100720074006900740069006f006e00000000000000000000000000000"+
			"0000000000000000000000000000000000000")),
		num: 2,
		sz:  128,
		expected: []*PartitionEntry{
			{
				PartitionTypeGUID:   MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: MakeGUID(0x631b17dc, 0xedb7, 0x4d1d, 0xa761, [...]uint8{0x6d, 0xce, 0x3e, 0xfc, 0xe4, 0x15}),
				StartingLBA:         1050624,
				EndingLBA:           2549759,
				Attributes:          0,
				PartitionName:       ""},
			{
				PartitionTypeGUID:   MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
				StartingLBA:         2048,
				EndingLBA:           1050623,
				Attributes:          0,
				PartitionName:       "EFI System Partition"}}})
}

type testWritePartitionEntryData struct {
	entry    *PartitionEntry
	expected []byte
}

func (s *gptSuite) testWritePartitionEntry(c *C, data *testWritePartitionEntryData) {
	w := new(bytes.Buffer)
	c.Check(data.entry.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, data.expected)
}

func (s *gptSuite) TestWritePartitionEntry1(c *C) {
	s.testWritePartitionEntry(c, &testWritePartitionEntryData{
		entry: &PartitionEntry{
			PartitionTypeGUID:   MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
			UniquePartitionGUID: MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
			StartingLBA:         2048,
			EndingLBA:           1050623,
			Attributes:          0,
			PartitionName:       "EFI System Partition"},
		expected: DecodeHexString(c, "28732ac11ff8d211ba4b00a0c93ec93b7b94de66b2fd2545b75230d66bb2b9600008000000000000ff071000"+
			"0000000000000000000000004500460049002000530079007300740065006d00200050006100720074006900740069006f006e00000000000000000000000000"+
			"0000000000000000000000000000000000000000"),
	})
}

func (s *gptSuite) TestWritePartitionEntry2(c *C) {
	s.testWritePartitionEntry(c, &testWritePartitionEntryData{
		entry: &PartitionEntry{
			PartitionTypeGUID:   MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
			UniquePartitionGUID: MakeGUID(0x631b17dc, 0xedb7, 0x4d1d, 0xa761, [...]uint8{0x6d, 0xce, 0x3e, 0xfc, 0xe4, 0x15}),
			StartingLBA:         1050624,
			EndingLBA:           2549759,
			Attributes:          0,
			PartitionName:       ""},
		expected: DecodeHexString(c, "af3dc60f838472478e793d69d8477de4dc171b63b7ed1d4da7616dce3efce4150008100000000000ffe72600000"+
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"+
			"0000000000000000000000000000000000000"),
	})
}

type testReadPartitionTableData struct {
	path            string
	role            PartitionTableRole
	checkCrc        bool
	expectedHeader  *PartitionTableHeader
	expectedEntries map[int]*PartitionEntry
	expectedErr     error
}

func (s *gptSuite) testReadPartitionTable(c *C, data *testReadPartitionTableData) {
	f, err := os.Open(data.path)
	c.Assert(err, IsNil)
	defer f.Close()

	fi, err := f.Stat()
	c.Assert(err, IsNil)

	table, err := ReadPartitionTable(f, fi.Size(), 512, data.role, data.checkCrc)
	c.Assert(err, Equals, data.expectedErr)
	c.Check(table.Hdr, DeepEquals, data.expectedHeader)
	c.Assert(table.Entries, HasLen, int(data.expectedHeader.NumberOfPartitionEntries))
	expected := make([]*PartitionEntry, len(table.Entries))
	for i := 0; i < len(expected); i++ {
		expected[i] = new(PartitionEntry)
	}
	for i, e := range data.expectedEntries {
		expected[i] = e
	}
	c.Check(table.Entries, DeepEquals, expected)
	fmt.Println(table)
}

func (s *gptSuite) TestReadPartitionTablePrimaryOK(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path:     "testdata/partitiontables/valid",
		role:     PrimaryPartitionTable,
		checkCrc: true,
		expectedHeader: &PartitionTableHeader{
			HeaderSize:               0x5c,
			MyLBA:                    0x1,
			AlternateLBA:             0x1ff,
			FirstUsableLBA:           0x22,
			LastUsableLBA:            0x1de,
			DiskGUID:                 MakeGUID(0x0eab22a8, 0x78e2, 0x9b4d, 0xb3fa, [...]uint8{0x7f, 0xdb, 0x73, 0x66, 0xd1, 0x5c}),
			PartitionEntryLBA:        0x2,
			NumberOfPartitionEntries: 0x80,
			SizeOfPartitionEntry:     0x80,
			PartitionEntryArrayCRC32: 0x9bc862a2,
		},
		expectedEntries: map[int]*PartitionEntry{
			0: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: MakeGUID(0x506fddfc, 0xad5e, 0x4548, 0xb7dd, [...]uint8{0xe7, 0x73, 0x62, 0x17, 0x5c, 0x31}),
				StartingLBA:         34,
				EndingLBA:           333},
			1: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: MakeGUID(0x5ff783fc, 0xa97c, 0x684f, 0xacd8, [...]uint8{0xe1, 0x70, 0x28, 0xf6, 0x1c, 0x5f}),
				StartingLBA:         334,
				EndingLBA:           433},
			2: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x21686148, 0x6449, 0x6e6f, 0x744e, [...]uint8{0x65, 0x65, 0x64, 0x45, 0x46, 0x49}),
				UniquePartitionGUID: MakeGUID(0x94da1fcc, 0x1c0f, 0x5645, 0xabf9, [...]uint8{0xff, 0x9a, 0xc4, 0x68, 0x24, 0x2d}),
				StartingLBA:         434,
				EndingLBA:           478},
		},
	})
}

func (s *gptSuite) TestReadPartitionTableBackupOK(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path:     "testdata/partitiontables/valid",
		role:     BackupPartitionTable,
		checkCrc: true,
		expectedHeader: &PartitionTableHeader{
			HeaderSize:               0x5c,
			MyLBA:                    0x1ff,
			AlternateLBA:             0x1,
			FirstUsableLBA:           0x22,
			LastUsableLBA:            0x1de,
			DiskGUID:                 MakeGUID(0x0eab22a8, 0x78e2, 0x9b4d, 0xb3fa, [...]uint8{0x7f, 0xdb, 0x73, 0x66, 0xd1, 0x5c}),
			PartitionEntryLBA:        0x1df,
			NumberOfPartitionEntries: 0x80,
			SizeOfPartitionEntry:     0x80,
			PartitionEntryArrayCRC32: 0x9bc862a2,
		},
		expectedEntries: map[int]*PartitionEntry{
			0: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: MakeGUID(0x506fddfc, 0xad5e, 0x4548, 0xb7dd, [...]uint8{0xe7, 0x73, 0x62, 0x17, 0x5c, 0x31}),
				StartingLBA:         34,
				EndingLBA:           333},
			1: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: MakeGUID(0x5ff783fc, 0xa97c, 0x684f, 0xacd8, [...]uint8{0xe1, 0x70, 0x28, 0xf6, 0x1c, 0x5f}),
				StartingLBA:         334,
				EndingLBA:           433},
			2: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x21686148, 0x6449, 0x6e6f, 0x744e, [...]uint8{0x65, 0x65, 0x64, 0x45, 0x46, 0x49}),
				UniquePartitionGUID: MakeGUID(0x94da1fcc, 0x1c0f, 0x5645, 0xabf9, [...]uint8{0xff, 0x9a, 0xc4, 0x68, 0x24, 0x2d}),
				StartingLBA:         434,
				EndingLBA:           478},
		},
	})
}

func (s *gptSuite) TestReadPartitionTableBackupInvalidBackupLocation(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path:     "testdata/partitiontables/invalid-backup-location",
		role:     BackupPartitionTable,
		checkCrc: true,
		expectedHeader: &PartitionTableHeader{
			HeaderSize:               0x5c,
			MyLBA:                    0x1ff,
			AlternateLBA:             0x1,
			FirstUsableLBA:           0x22,
			LastUsableLBA:            0x1de,
			DiskGUID:                 MakeGUID(0x0eab22a8, 0x78e2, 0x9b4d, 0xb3fa, [...]uint8{0x7f, 0xdb, 0x73, 0x66, 0xd1, 0x5c}),
			PartitionEntryLBA:        0x1df,
			NumberOfPartitionEntries: 0x80,
			SizeOfPartitionEntry:     0x80,
			PartitionEntryArrayCRC32: 0x9bc862a2,
		},
		expectedEntries: map[int]*PartitionEntry{
			0: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: MakeGUID(0x506fddfc, 0xad5e, 0x4548, 0xb7dd, [...]uint8{0xe7, 0x73, 0x62, 0x17, 0x5c, 0x31}),
				StartingLBA:         34,
				EndingLBA:           333},
			1: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: MakeGUID(0x5ff783fc, 0xa97c, 0x684f, 0xacd8, [...]uint8{0xe1, 0x70, 0x28, 0xf6, 0x1c, 0x5f}),
				StartingLBA:         334,
				EndingLBA:           433},
			2: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x21686148, 0x6449, 0x6e6f, 0x744e, [...]uint8{0x65, 0x65, 0x64, 0x45, 0x46, 0x49}),
				UniquePartitionGUID: MakeGUID(0x94da1fcc, 0x1c0f, 0x5645, 0xabf9, [...]uint8{0xff, 0x9a, 0xc4, 0x68, 0x24, 0x2d}),
				StartingLBA:         434,
				EndingLBA:           478},
		},
		expectedErr: ErrInvalidBackupPartitionTableLocation,
	})
}

func (s *gptSuite) TestReadPartitionTablePrimaryInvalidAlternate(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path:     "testdata/partitiontables/invalid-backup-hdr-checksum",
		role:     PrimaryPartitionTable,
		checkCrc: true,
		expectedHeader: &PartitionTableHeader{
			HeaderSize:               0x5c,
			MyLBA:                    0x1,
			AlternateLBA:             0x1ff,
			FirstUsableLBA:           0x22,
			LastUsableLBA:            0x1de,
			DiskGUID:                 MakeGUID(0x0eab22a8, 0x78e2, 0x9b4d, 0xb3fa, [...]uint8{0x7f, 0xdb, 0x73, 0x66, 0xd1, 0x5c}),
			PartitionEntryLBA:        0x2,
			NumberOfPartitionEntries: 0x80,
			SizeOfPartitionEntry:     0x80,
			PartitionEntryArrayCRC32: 0x9bc862a2,
		},
		expectedEntries: map[int]*PartitionEntry{
			0: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: MakeGUID(0x506fddfc, 0xad5e, 0x4548, 0xb7dd, [...]uint8{0xe7, 0x73, 0x62, 0x17, 0x5c, 0x31}),
				StartingLBA:         34,
				EndingLBA:           333},
			1: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: MakeGUID(0x5ff783fc, 0xa97c, 0x684f, 0xacd8, [...]uint8{0xe1, 0x70, 0x28, 0xf6, 0x1c, 0x5f}),
				StartingLBA:         334,
				EndingLBA:           433},
			2: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x21686148, 0x6449, 0x6e6f, 0x744e, [...]uint8{0x65, 0x65, 0x64, 0x45, 0x46, 0x49}),
				UniquePartitionGUID: MakeGUID(0x94da1fcc, 0x1c0f, 0x5645, 0xabf9, [...]uint8{0xff, 0x9a, 0xc4, 0x68, 0x24, 0x2d}),
				StartingLBA:         434,
				EndingLBA:           478},
		},
	})
}

func (s *gptSuite) TestReadPartitionTableBackupInvalidAlternate(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path:     "testdata/partitiontables/invalid-primary-hdr-checksum",
		role:     BackupPartitionTable,
		checkCrc: true,
		expectedHeader: &PartitionTableHeader{
			HeaderSize:               0x5c,
			MyLBA:                    0x1ff,
			AlternateLBA:             0x1,
			FirstUsableLBA:           0x22,
			LastUsableLBA:            0x1de,
			DiskGUID:                 MakeGUID(0x0eab22a8, 0x78e2, 0x9b4d, 0xb3fa, [...]uint8{0x7f, 0xdb, 0x73, 0x66, 0xd1, 0x5c}),
			PartitionEntryLBA:        0x1df,
			NumberOfPartitionEntries: 0x80,
			SizeOfPartitionEntry:     0x80,
			PartitionEntryArrayCRC32: 0x9bc862a2,
		},
		expectedEntries: map[int]*PartitionEntry{
			0: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: MakeGUID(0x506fddfc, 0xad5e, 0x4548, 0xb7dd, [...]uint8{0xe7, 0x73, 0x62, 0x17, 0x5c, 0x31}),
				StartingLBA:         34,
				EndingLBA:           333},
			1: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: MakeGUID(0x5ff783fc, 0xa97c, 0x684f, 0xacd8, [...]uint8{0xe1, 0x70, 0x28, 0xf6, 0x1c, 0x5f}),
				StartingLBA:         334,
				EndingLBA:           433},
			2: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x21686148, 0x6449, 0x6e6f, 0x744e, [...]uint8{0x65, 0x65, 0x64, 0x45, 0x46, 0x49}),
				UniquePartitionGUID: MakeGUID(0x94da1fcc, 0x1c0f, 0x5645, 0xabf9, [...]uint8{0xff, 0x9a, 0xc4, 0x68, 0x24, 0x2d}),
				StartingLBA:         434,
				EndingLBA:           478},
		},
	})
}

func (s *gptSuite) TestReadPartitionTableInvalidPrimaryNoCheck(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path: "testdata/partitiontables/invalid-primary-hdr-checksum",
		role: PrimaryPartitionTable,
		expectedHeader: &PartitionTableHeader{
			HeaderSize:               0x5c,
			MyLBA:                    0x1,
			AlternateLBA:             0x1ff,
			FirstUsableLBA:           0x22,
			LastUsableLBA:            0x1de,
			DiskGUID:                 MakeGUID(0x0eab22a8, 0x78e2, 0x9b4d, 0xb3fa, [...]uint8{0x7f, 0xdb, 0x73, 0x66, 0xd1, 0x5c}),
			PartitionEntryLBA:        0x2,
			NumberOfPartitionEntries: 0x80,
			SizeOfPartitionEntry:     0x80,
			PartitionEntryArrayCRC32: 0x9bc862a2,
		},
		expectedEntries: map[int]*PartitionEntry{
			0: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: MakeGUID(0x506fddfc, 0xad5e, 0x4548, 0xb7dd, [...]uint8{0xe7, 0x73, 0x62, 0x17, 0x5c, 0x31}),
				StartingLBA:         34,
				EndingLBA:           333},
			1: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: MakeGUID(0x5ff783fc, 0xa97c, 0x684f, 0xacd8, [...]uint8{0xe1, 0x70, 0x28, 0xf6, 0x1c, 0x5f}),
				StartingLBA:         334,
				EndingLBA:           433},
			2: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x21686148, 0x6449, 0x6e6f, 0x744e, [...]uint8{0x65, 0x65, 0x64, 0x45, 0x46, 0x49}),
				UniquePartitionGUID: MakeGUID(0x94da1fcc, 0x1c0f, 0x5645, 0xabf9, [...]uint8{0xff, 0x9a, 0xc4, 0x68, 0x24, 0x2d}),
				StartingLBA:         434,
				EndingLBA:           478},
		},
	})
}

func (s *gptSuite) TestReadPartitionTableInvalidBackupNoCheck(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path: "testdata/partitiontables/invalid-backup-hdr-checksum",
		role: BackupPartitionTable,
		expectedHeader: &PartitionTableHeader{
			HeaderSize:               0x5c,
			MyLBA:                    0x1ff,
			AlternateLBA:             0x1,
			FirstUsableLBA:           0x22,
			LastUsableLBA:            0x1de,
			DiskGUID:                 MakeGUID(0x0eab22a8, 0x78e2, 0x9b4d, 0xb3fa, [...]uint8{0x7f, 0xdb, 0x73, 0x66, 0xd1, 0x5c}),
			PartitionEntryLBA:        0x1df,
			NumberOfPartitionEntries: 0x80,
			SizeOfPartitionEntry:     0x80,
			PartitionEntryArrayCRC32: 0x9bc862a2,
		},
		expectedEntries: map[int]*PartitionEntry{
			0: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: MakeGUID(0x506fddfc, 0xad5e, 0x4548, 0xb7dd, [...]uint8{0xe7, 0x73, 0x62, 0x17, 0x5c, 0x31}),
				StartingLBA:         34,
				EndingLBA:           333},
			1: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: MakeGUID(0x5ff783fc, 0xa97c, 0x684f, 0xacd8, [...]uint8{0xe1, 0x70, 0x28, 0xf6, 0x1c, 0x5f}),
				StartingLBA:         334,
				EndingLBA:           433},
			2: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x21686148, 0x6449, 0x6e6f, 0x744e, [...]uint8{0x65, 0x65, 0x64, 0x45, 0x46, 0x49}),
				UniquePartitionGUID: MakeGUID(0x94da1fcc, 0x1c0f, 0x5645, 0xabf9, [...]uint8{0xff, 0x9a, 0xc4, 0x68, 0x24, 0x2d}),
				StartingLBA:         434,
				EndingLBA:           478},
		},
	})
}

type testReadPartitionTableInvalidData struct {
	path     string
	role     PartitionTableRole
	checkCrc bool
}

func (s *gptSuite) testReadPartitionTableInvalid(c *C, data *testReadPartitionTableInvalidData) error {
	f, err := os.Open(data.path)
	c.Assert(err, IsNil)
	defer f.Close()

	fi, err := f.Stat()
	c.Assert(err, IsNil)

	_, err = ReadPartitionTable(f, fi.Size(), 512, data.role, data.checkCrc)
	return err
}

func (s *gptSuite) TestReadPartitionTableInvalidPMBR(c *C) {
	c.Check(s.testReadPartitionTableInvalid(c, &testReadPartitionTableInvalidData{
		path: "testdata/partitiontables/invalid-pmbr",
		role: PrimaryPartitionTable,
	}), Equals, ErrStandardMBRFound)
}

func (s *gptSuite) TestReadPartitionTableInvalidPrimaryHeader1(c *C) {
	c.Check(s.testReadPartitionTableInvalid(c, &testReadPartitionTableInvalidData{
		path:     "testdata/partitiontables/invalid-primary-hdr-checksum",
		role:     PrimaryPartitionTable,
		checkCrc: true,
	}), Equals, ErrCRCCheck)
}

func (s *gptSuite) TestReadPartitionTableInvalidPrimaryHeader2(c *C) {
	c.Check(s.testReadPartitionTableInvalid(c, &testReadPartitionTableInvalidData{
		path:     "testdata/partitiontables/invalid-primary-array-checksum",
		role:     PrimaryPartitionTable,
		checkCrc: true,
	}), Equals, ErrCRCCheck)
}
