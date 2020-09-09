package efi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

type PhysicalAddress uint64

// GUID corresponds to the EFI_GUID type.
type GUID [16]byte

func (guid GUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(guid[0:4]),
		binary.LittleEndian.Uint16(guid[4:6]),
		binary.LittleEndian.Uint16(guid[6:8]),
		binary.BigEndian.Uint16(guid[8:10]),
		guid[10:16])
}

// MakeGUID makes a new GUID from the supplied arguments.
func MakeGUID(a uint32, b, c, d uint16, e [6]uint8) (out GUID) {
	binary.LittleEndian.PutUint32(out[0:4], a)
	binary.LittleEndian.PutUint16(out[4:6], b)
	binary.LittleEndian.PutUint16(out[6:8], c)
	binary.BigEndian.PutUint16(out[8:10], d)
	copy(out[10:], e[:])
	return
}

// ReadGUID reads a EFI_GUID from the supplied io.Reader.
func ReadGUID(r io.Reader) (out GUID, err error) {
	_, err = io.ReadFull(r, out[:])
	return
}

// TableHeader corresponds to the EFI_TABLE_HEADER type.
type TableHeader struct {
	Signature  uint64
	Revision   uint32
	HeaderSize uint32
	CRC        uint32
	Reserved   uint32
}

// LBA corresponds to the EFI_LBA type.
type LBA uint64

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
func ReadPartitionTableHeader(r io.Reader) (out *PartitionTableHeader, err error) {
	out = &PartitionTableHeader{}
	if err := binary.Read(r, binary.LittleEndian, out); err != nil {
		return nil, err
	}
	return
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

// PartitionEntryRaw corresponds to the EFI_PARTITION_ENTRY type in raw byte form. This type exists because the partition table
// header can specify a partition entry size of greather than the size of EFI_PARTITION_ENTRY (128 bytes).
type PartitionEntryRaw []byte

// ReadPartitionEntry reads a EFI_PARTITION_ENTRY of the specified size from the supplied io.Reader.
func ReadPartitionEntry(r io.Reader, sz uint32) (out PartitionEntryRaw, err error) {
	out = make(PartitionEntryRaw, sz)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return
}

// Decode decodes the raw EFI_PARTITION_ENTRY and returns the decoded PartitionEntry.
func (er PartitionEntryRaw) Decode() (*PartitionEntry, error) {
	r := bytes.NewReader(er)

	var e struct {
		PartitionTypeGUID   GUID
		UniquePartitionGUID GUID
		StartingLBA         LBA
		EndingLBA           LBA
		Attributes          uint64
		PartitionName       [36]uint16
	}
	if err := binary.Read(r, binary.LittleEndian, &e); err != nil {
		return nil, err
	}

	var name bytes.Buffer
	for _, c := range utf16.Decode(e.PartitionName[:]) {
		if c == rune(0) {
			break
		}
		name.WriteRune(c)
	}

	return &PartitionEntry{
		PartitionTypeGUID:   e.PartitionTypeGUID,
		UniquePartitionGUID: e.UniquePartitionGUID,
		StartingLBA:         e.StartingLBA,
		EndingLBA:           e.EndingLBA,
		Attributes:          e.Attributes,
		PartitionName:       name.String()}, nil
}

func (e PartitionEntryRaw) String() string {
	decoded, err := e.Decode()
	if err != nil {
		return fmt.Sprintf("invalid entry: %v", err)
	}
	return decoded.String()
}
