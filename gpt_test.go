// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"bytes"
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
	path                  string
	role                  PartitionTableRole
	checkCrc              bool
	expectedGUID          GUID
	expectedEntries       map[int]*PartitionEntry
	expectedEntriesLength int
	errMatch              string
}

func (s *gptSuite) testReadPartitionTable(c *C, data *testReadPartitionTableData) {
	f, err := os.Open(data.path)
	c.Assert(err, IsNil)
	defer f.Close()

	fi, err := f.Stat()
	c.Assert(err, IsNil)

	table, err := ReadPartitionTable(f, fi.Size(), 512, data.role, data.checkCrc)
	if data.errMatch == "" {
		c.Check(err, IsNil)
		c.Check(table.DiskGUID, DeepEquals, data.expectedGUID)
		c.Assert(table.Entries, HasLen, data.expectedEntriesLength)
		expected := make([]*PartitionEntry, len(table.Entries))
		for i := 0; i < len(expected); i++ {
			expected[i] = new(PartitionEntry)
		}
		for i, e := range data.expectedEntries {
			expected[i] = e
		}
		c.Check(table.Entries, DeepEquals, expected)
	} else {
		c.Check(err, ErrorMatches, data.errMatch)
	}
}

func (s *gptSuite) TestReadPartitionTable1(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path:         "testdata/partitiontables/cloudimg",
		role:         PrimaryPartitionTable,
		checkCrc:     true,
		expectedGUID: MakeGUID(0x2dbb8d7d, 0x5972, 0x4517, 0x9c5a, [...]uint8{0x2d, 0xb1, 0x11, 0x95, 0x85, 0x01}),
		expectedEntries: map[int]*PartitionEntry{
			0: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: MakeGUID(0x15eae969, 0x91f2, 0x437b, 0x95cc, [...]uint8{0xec, 0x11, 0xd3, 0x40, 0x95, 0x9b}),
				StartingLBA:         227328,
				EndingLBA:           4612062},
			13: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x21686148, 0x6449, 0x6e6f, 0x744e, [...]uint8{0x65, 0x65, 0x64, 0x45, 0x46, 0x49}),
				UniquePartitionGUID: MakeGUID(0x71c94a7b, 0xfa01, 0x416c, 0x9cdd, [...]uint8{0x60, 0x02, 0x5b, 0x54, 0xd8, 0xd2}),
				StartingLBA:         2048,
				EndingLBA:           10239},
			14: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: MakeGUID(0x6992c444, 0x90c6, 0x4842, 0x8d5a, [...]uint8{0x44, 0xc4, 0x56, 0xea, 0x6c, 0xc9}),
				StartingLBA:         10240,
				EndingLBA:           227327},
		},
		expectedEntriesLength: 128,
	})
}

func (s *gptSuite) TestReadPartitionTable2(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path:     "testdata/partitiontables/cloudimg-invalid-hdr-checksum",
		role:     PrimaryPartitionTable,
		checkCrc: true,
		errMatch: "CRC check failed",
	})
}

func (s *gptSuite) TestReadPartitionTable3(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path:     "testdata/partitiontables/cloudimg-invalid-array-checksum",
		role:     PrimaryPartitionTable,
		checkCrc: true,
		errMatch: "CRC check failed",
	})
}

func (s *gptSuite) TestReadPartitionTable4(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path:         "testdata/partitiontables/cloudimg-invalid-hdr-checksum",
		role:         PrimaryPartitionTable,
		expectedGUID: MakeGUID(0x2dbb8d7d, 0x5972, 0x4517, 0x9c5a, [...]uint8{0x2d, 0xb1, 0x11, 0x95, 0x85, 0x01}),
		expectedEntries: map[int]*PartitionEntry{
			0: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: MakeGUID(0x15eae969, 0x91f2, 0x437b, 0x95cc, [...]uint8{0xec, 0x11, 0xd3, 0x40, 0x95, 0x9b}),
				StartingLBA:         227328,
				EndingLBA:           4612062},
			13: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0x21686148, 0x6449, 0x6e6f, 0x744e, [...]uint8{0x65, 0x65, 0x64, 0x45, 0x46, 0x49}),
				UniquePartitionGUID: MakeGUID(0x71c94a7b, 0xfa01, 0x416c, 0x9cdd, [...]uint8{0x60, 0x02, 0x5b, 0x54, 0xd8, 0xd2}),
				StartingLBA:         2048,
				EndingLBA:           10239},
			14: &PartitionEntry{
				PartitionTypeGUID:   MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: MakeGUID(0x6992c444, 0x90c6, 0x4842, 0x8d5a, [...]uint8{0x44, 0xc4, 0x56, 0xea, 0x6c, 0xc9}),
				StartingLBA:         10240,
				EndingLBA:           227327},
		},
		expectedEntriesLength: 128,
	})
}

func (s *gptSuite) TestReadPartitionTable5(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path:         "testdata/partitiontables/backup",
		role:         BackupPartitionTable,
		checkCrc:     true,
		expectedGUID: MakeGUID(0x0eab22a8, 0x78e2, 0x9b4d, 0xb3fa, [...]uint8{0x7f, 0xdb, 0x73, 0x66, 0xd1, 0x5c}),
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
		expectedEntriesLength: 128,
	})
}

func (s *gptSuite) TestReadPartitionTable6(c *C) {
	s.testReadPartitionTable(c, &testReadPartitionTableData{
		path:     "testdata/partitiontables/backup",
		role:     PrimaryPartitionTable,
		checkCrc: true,
		errMatch: "CRC check failed",
	})
}
