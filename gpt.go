package efi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

// PartitionTableHeader correponds to the EFI_PARTITION_TABLE_HEADER type.
type PartitionTableHeader struct {
	TableHeader
	MyLBA                    LBA
	AlternateLBA             LBA
	FirstUsableLBA           LBA
	LastUsableLBA            LBA
	DiskGUID                 GUID
	PartitionEntryLBA        LBA
	NumberOfPartitionEntries uint32
	SizeOfPartitionEntry     uint32
	PartitionEntryArrayCRC32 uint32
}

// ReadPartitionTableHeader reads a EFI_PARTITION_TABLE_HEADER from the supplied io.Reader.
// It doesn't check that the header is valid.
func ReadPartitionTableHeader(r io.Reader) (out *PartitionTableHeader, err error) {
	out = &PartitionTableHeader{}
	if err := binary.Read(r, binary.LittleEndian, out); err != nil {
		return nil, err
	}
	return out, nil
}

// PartitionEntry corresponds to the EFI_PARTITION_ENTRY type.
type PartitionEntry struct {
	PartitionTypeGUID   GUID
	UniquePartitionGUID GUID
	StartingLBA         LBA
	EndingLBA           LBA
	Attributes          uint64
	PartitionName       string
}

func (e *PartitionEntry) String() string {
	return fmt.Sprintf("PartitionTypeGUID: %s, UniquePartitionGUID: %s, PartitionName: \"%s\"", e.PartitionTypeGUID, e.UniquePartitionGUID, e.PartitionName)
}

// ReadPartitionEntries reads EFI_PARTITION_ENTRIES of the specified size from the supplied
// io.Reader
func ReadPartitionEntries(r io.Reader, num, sz uint32) (out []*PartitionEntry, err error) {
	b := new(bytes.Buffer)
	for i := uint32(0); i < num; i++ {
		b.Reset()

		if _, err := io.CopyN(b, r, int64(sz)); err != nil {
			return nil, err
		}

		var e struct {
			PartitionTypeGUID   GUID
			UniquePartitionGUID GUID
			StartingLBA         LBA
			EndingLBA           LBA
			Attributes          uint64
			PartitionName       [36]uint16
		}
		if err := binary.Read(b, binary.LittleEndian, &e); err != nil {
			return nil, err
		}

		var name bytes.Buffer
		for _, c := range utf16.Decode(e.PartitionName[:]) {
			if c == rune(0) {
				break
			}
			name.WriteRune(c)
		}

		out = append(out, &PartitionEntry{
			PartitionTypeGUID:   e.PartitionTypeGUID,
			UniquePartitionGUID: e.UniquePartitionGUID,
			StartingLBA:         e.StartingLBA,
			EndingLBA:           e.EndingLBA,
			Attributes:          e.Attributes,
			PartitionName:       name.String()})
	}

	return out, nil
}
