// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"unicode/utf16"

	"golang.org/x/xerrors"

	"github.com/canonical/go-efilib/internal/ioerr"
	"github.com/canonical/go-efilib/internal/uefi"
)

// PartitionTableHeader correponds to the EFI_PARTITION_TABLE_HEADER type.
type PartitionTableHeader struct {
	HeaderSize               uint32
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

// WriteTo serializes this PartitionTableHeader to w. The CRC field is
// computed automatically.
func (h *PartitionTableHeader) WriteTo(w io.Writer) error {
	hdr := uefi.EFI_PARTITION_TABLE_HEADER{
		Hdr: uefi.EFI_TABLE_HEADER{
			Signature:  uefi.EFI_PTAB_HEADER_ID,
			Revision:   0x10000,
			HeaderSize: h.HeaderSize},
		MyLBA:                    uefi.EFI_LBA(h.MyLBA),
		AlternateLBA:             uefi.EFI_LBA(h.AlternateLBA),
		FirstUsableLBA:           uefi.EFI_LBA(h.FirstUsableLBA),
		LastUsableLBA:            uefi.EFI_LBA(h.LastUsableLBA),
		DiskGUID:                 uefi.EFI_GUID(h.DiskGUID),
		PartitionEntryLBA:        uefi.EFI_LBA(h.PartitionEntryLBA),
		NumberOfPartitionEntries: h.NumberOfPartitionEntries,
		SizeOfPartitionEntry:     h.SizeOfPartitionEntry,
		PartitionEntryArrayCRC32: h.PartitionEntryArrayCRC32}

	hdrSize := binary.Size(hdr)
	if h.HeaderSize < uint32(hdrSize) {
		return errors.New("invalid HeaderSize")
	}

	reserved := make([]byte, int(h.HeaderSize)-hdrSize)

	crc := crc32.NewIEEE()
	binary.Write(crc, binary.LittleEndian, &hdr)
	crc.Write(reserved)

	hdr.Hdr.CRC = crc.Sum32()

	if err := binary.Write(w, binary.LittleEndian, &hdr); err != nil {
		return err
	}
	_, err := w.Write(reserved)
	return err
}

// ReadPartitionTableHeader reads a EFI_PARTITION_TABLE_HEADER from the supplied io.Reader.
// If the header signature or revision is incorrect, an error will be returned. If
// checkCrc is true and the header has an invalid CRC, an error will be returned.
// If checkCrc is false, then a CRC check is not performed.
func ReadPartitionTableHeader(r io.Reader, checkCrc bool) (*PartitionTableHeader, error) {
	hdr, crc, err := uefi.Read_EFI_PARTITION_TABLE_HEADER(r)
	if err != nil {
		return nil, err
	}
	if hdr.Hdr.Signature != uefi.EFI_PTAB_HEADER_ID {
		return nil, errors.New("invalid signature")
	}
	if hdr.Hdr.Revision != 0x10000 {
		return nil, errors.New("unexpected revision")
	}
	if checkCrc && hdr.Hdr.CRC != crc {
		return nil, errors.New("CRC check failed")
	}

	return &PartitionTableHeader{
		HeaderSize:               hdr.Hdr.HeaderSize,
		MyLBA:                    LBA(hdr.MyLBA),
		AlternateLBA:             LBA(hdr.AlternateLBA),
		FirstUsableLBA:           LBA(hdr.FirstUsableLBA),
		LastUsableLBA:            LBA(hdr.LastUsableLBA),
		DiskGUID:                 GUID(hdr.DiskGUID),
		PartitionEntryLBA:        LBA(hdr.PartitionEntryLBA),
		NumberOfPartitionEntries: hdr.NumberOfPartitionEntries,
		SizeOfPartitionEntry:     hdr.SizeOfPartitionEntry,
		PartitionEntryArrayCRC32: hdr.PartitionEntryArrayCRC32}, nil
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

// WriteTo serializes this PartitionEntry to w. Note that it doesn't write
// any bytes beyond the end of the EFI_PARTITION_ENTRY structure, so if the
// caller is writing several entries and the partition table header defines
// an entry size of greater than 128 bytes, the caller is responsible for
// inserting the 0 padding bytes.
func (e *PartitionEntry) WriteTo(w io.Writer) error {
	entry := uefi.EFI_PARTITION_ENTRY{
		PartitionTypeGUID:   uefi.EFI_GUID(e.PartitionTypeGUID),
		UniquePartitionGUID: uefi.EFI_GUID(e.UniquePartitionGUID),
		StartingLBA:         uefi.EFI_LBA(e.StartingLBA),
		EndingLBA:           uefi.EFI_LBA(e.EndingLBA),
		Attributes:          e.Attributes}

	name := bytes.NewReader([]byte(e.PartitionName))
	var unicodeName []rune
	for {
		c, _, err := name.ReadRune()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		unicodeName = append(unicodeName, c)
	}

	utf16Name := utf16.Encode(unicodeName)
	if len(utf16Name) > len(entry.PartitionName) {
		return errors.New("PartitionName is too long")
	}
	copy(entry.PartitionName[:], utf16Name)

	return binary.Write(w, binary.LittleEndian, &entry)
}

// ReadPartitionEntry reads a single EFI_PARTITION_ENTRY from r.
func ReadPartitionEntry(r io.Reader) (*PartitionEntry, error) {
	var e uefi.EFI_PARTITION_ENTRY
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
		PartitionTypeGUID:   GUID(e.PartitionTypeGUID),
		UniquePartitionGUID: GUID(e.UniquePartitionGUID),
		StartingLBA:         LBA(e.StartingLBA),
		EndingLBA:           LBA(e.EndingLBA),
		Attributes:          e.Attributes,
		PartitionName:       name.String()}, nil
}

func readPartitionEntries(r io.Reader, num, sz, expectedCrc uint32, checkCrc bool) (out []*PartitionEntry, err error) {
	crc := crc32.NewIEEE()
	r2 := io.TeeReader(r, crc)

	b := new(bytes.Buffer)
	for i := uint32(0); i < num; i++ {
		b.Reset()

		if _, err := io.CopyN(b, r2, int64(sz)); err != nil {
			switch {
			case err == io.EOF && i == 0:
				return nil, err
			case err == io.EOF:
				err = io.ErrUnexpectedEOF
			}
			return nil, xerrors.Errorf("cannot read entry %d: %w", i, err)
		}

		e, err := ReadPartitionEntry(b)
		if err != nil {
			return nil, err
		}

		out = append(out, e)
	}

	if checkCrc && crc.Sum32() != expectedCrc {
		return nil, errors.New("CRC check failed")
	}

	return out, nil
}

// ReadPartitionEntries reads the specified number of EFI_PARTITION_ENTRY structures
// of the specified size from the supplied io.Reader. The number and size are typically
// defined by the partition table header.
func ReadPartitionEntries(r io.Reader, num, sz uint32) ([]*PartitionEntry, error) {
	return readPartitionEntries(r, num, sz, 0, false)
}

var emptyPartitionType GUID

type chsAddress [3]uint8

type mbrPartitionEntry struct {
	Flag         uint8
	StartAddress chsAddress
	Type         uint8
	EndAddress   chsAddress
	StartingLBA  uint32
	Length       uint32
}

type mbr struct {
	Code       [446]byte
	Partitions [4]mbrPartitionEntry
	Signature  uint16
}

// PartitionTableRole describes the role of a partition table.
type PartitionTableRole int

const (
	PrimaryPartitionTable PartitionTableRole = iota
	BackupPartitionTable
)

// PartitionTable describes a complete GUID partition table.
type PartitionTable struct {
	Hdr     *PartitionTableHeader
	Entries []*PartitionEntry
}

// ReadPartitionTable reads a complete GUID partition table from the supplied
// io.Reader. The total size and logical block size of the device must be
// supplied - the logical block size is 512 bytes for a file, but must be
// obtained from the kernel for a block device.
//
// This function expects the device to have a valid protective MBR.
//
// If role is PrimaryPartitionTable, this will read the primary partition
// table that is located immediately after the protective MBR. If role is
// BackupPartitionTable, this will read the backup partition table that is
// located at the end of the device.
//
// If checkCrc is true and either CRC check fails, an error will be returned.
// Setting checkCrc to false disables the CRC checks.
func ReadPartitionTable(r io.ReaderAt, totalSz, blockSz int64, role PartitionTableRole, checkCrc bool) (*PartitionTable, error) {
	r2 := io.NewSectionReader(r, 0, totalSz)

	var mbr mbr
	if err := binary.Read(r2, binary.LittleEndian, &mbr); err != nil {
		return nil, ioerr.PassEOF("cannot read MBR: %w", err)
	}
	if mbr.Signature != 0xaa55 {
		return nil, errors.New("invalid MBR signature")
	}

	validPmbr := false
	for _, p := range mbr.Partitions {
		if p.Type == 0xee {
			validPmbr = true
			break
		}
	}
	if !validPmbr {
		return nil, errors.New("no valid PMBR detected")
	}

	var offset int64
	var whence int
	switch role {
	case PrimaryPartitionTable:
		offset = blockSz
		whence = io.SeekStart
	case BackupPartitionTable:
		offset = -blockSz
		whence = io.SeekEnd
	default:
		panic("invalid role")
	}

	if _, err := r2.Seek(offset, whence); err != nil {
		return nil, err
	}

	hdr, err := ReadPartitionTableHeader(r2, checkCrc)
	if err != nil {
		return nil, ioerr.EOFUnexpected("cannot read GPT header: %w", err)
	}

	if _, err := r2.Seek(int64(hdr.PartitionEntryLBA)*blockSz, io.SeekStart); err != nil {
		return nil, err
	}

	entries, err := readPartitionEntries(r2, hdr.NumberOfPartitionEntries, hdr.SizeOfPartitionEntry, hdr.PartitionEntryArrayCRC32, checkCrc)
	if err != nil {
		return nil, ioerr.EOFUnexpected("cannot read GPT entries: %w", err)
	}

	return &PartitionTable{hdr, entries}, nil
}
