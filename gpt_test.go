package efi_test

import (
	"bytes"

	. "github.com/canonical/go-efilib"

	. "gopkg.in/check.v1"
)

type gptSuite struct{}

var _ = Suite(&gptSuite{})

type testReadPartitionTableHeaderData struct {
	r        *bytes.Reader
	expected *PartitionTableHeader
}

func (s *gptSuite) testReadPartitionTableHeader(c *C, data *testReadPartitionTableHeaderData) {
	start := data.r.Len()
	out, err := ReadPartitionTableHeader(data.r)
	c.Assert(err, IsNil)
	c.Check(start-data.r.Len(), Equals, 92)
	c.Check(out, DeepEquals, data.expected)
}

func (s *gptSuite) TestReadPartitionTableHeader1(c *C) {
	s.testReadPartitionTableHeader(c, &testReadPartitionTableHeaderData{
		r: bytes.NewReader(decodeHexString(c, "4546492050415254000001005c000000edeb4e64000000000100000000000000af5277ee000000002200000000"+
			"0000008e5277ee00000000c273aea42f0e1345bd3c456da7f7f0fd02000000000000008000000080000000f628450b")),
		expected: &PartitionTableHeader{
			TableHeader: TableHeader{
				Signature:  0x5452415020494645,
				Revision:   0x10000,
				HeaderSize: 92,
				CRC:        0x644eebed,
				Reserved:   0},
			MyLBA:                    1,
			AlternateLBA:             4000797359,
			FirstUsableLBA:           34,
			LastUsableLBA:            4000797326,
			DiskGUID:                 MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
			PartitionEntryLBA:        2,
			NumberOfPartitionEntries: 128,
			SizeOfPartitionEntry:     128,
			PartitionEntryArrayCRC32: 0x0b4528f6}})
}

func (s *gptSuite) TestReadPartitionTableHeader2(c *C) {
	s.testReadPartitionTableHeader(c, &testReadPartitionTableHeaderData{
		r: bytes.NewReader(decodeHexString(c, "4546492050415254000001005c000000edeb4e64000000000100000000000000af5277ee000000002200000000"+
			"0000008e5277ee00000000c273aea42f0e1345bd3c456da7f7f0fd02000000000000008000000080000000f628450ba5a5a5a5a5a5a5a5")),
		expected: &PartitionTableHeader{
			TableHeader: TableHeader{
				Signature:  0x5452415020494645,
				Revision:   0x10000,
				HeaderSize: 92,
				CRC:        0x644eebed,
				Reserved:   0},
			MyLBA:                    1,
			AlternateLBA:             4000797359,
			FirstUsableLBA:           34,
			LastUsableLBA:            4000797326,
			DiskGUID:                 MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
			PartitionEntryLBA:        2,
			NumberOfPartitionEntries: 128,
			SizeOfPartitionEntry:     128,
			PartitionEntryArrayCRC32: 0x0b4528f6}})
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
		r: bytes.NewReader(decodeHexString(c, "28732ac11ff8d211ba4b00a0c93ec93b7b94de66b2fd2545b75230d66bb2b9600008000000000000ff071000"+
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
		r: bytes.NewReader(decodeHexString(c, "af3dc60f838472478e793d69d8477de4dc171b63b7ed1d4da7616dce3efce4150008100000000000ffe72600000"+
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
		r: bytes.NewReader(decodeHexString(c, "af3dc60f838472478e793d69d8477de4dc171b63b7ed1d4da7616dce3efce4150008100000000000ffe72600000"+
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
