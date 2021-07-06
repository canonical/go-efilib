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

// ReadPartitionTableHeader reads a EFI_PARTITION_TABLE_HEADER from the supplied io.Reader.
// It doesn't check that the header is valid.
func ReadPartitionTableHeader(r io.Reader, checkCrc32 bool) (*PartitionTableHeader, error) {
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
	if checkCrc32 && hdr.Hdr.CRC != crc {
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

func readPartitionEntries(r io.Reader, num, sz, expectedCrc uint32, checkCrc bool) (out []*PartitionEntry, err error) {
	crc := crc32.NewIEEE()

	b := new(bytes.Buffer)
	for i := uint32(0); i < num; i++ {
		b.Reset()

		if _, err := io.CopyN(b, r, int64(sz)); err != nil {
			switch {
			case err == io.EOF && i == 0:
				return nil, err
			case err == io.EOF:
				err = io.ErrUnexpectedEOF
			}
			return nil, xerrors.Errorf("cannot read entry %d: %w", i, err)
		}

		crc.Write(b.Bytes())

		var e uefi.EFI_PARTITION_ENTRY
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
			PartitionTypeGUID:   GUID(e.PartitionTypeGUID),
			UniquePartitionGUID: GUID(e.UniquePartitionGUID),
			StartingLBA:         LBA(e.StartingLBA),
			EndingLBA:           LBA(e.EndingLBA),
			Attributes:          e.Attributes,
			PartitionName:       name.String()})
	}

	if checkCrc && crc.Sum32() != expectedCrc {
		return nil, errors.New("CRC check failed")
	}

	return out, nil
}

// ReadPartitionEntries reads EFI_PARTITION_ENTRIES of the specified size from the supplied
// io.Reader
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

type PartitionTableRole int

const (
	PrimaryPartitionTable PartitionTableRole = iota
	BackupPartitionTable
)

func ReadPartitionTable(r io.ReaderAt, totalSz, blockSz int64, role PartitionTableRole, checkCrc32 bool) ([]*PartitionEntry, error) {
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

	hdr, err := ReadPartitionTableHeader(r2, checkCrc32)
	if err != nil {
		return nil, ioerr.EOFUnexpected("cannot read GPT header: %w", err)
	}

	if _, err := r2.Seek(int64(hdr.PartitionEntryLBA)*blockSz, io.SeekStart); err != nil {
		return nil, err
	}

	return readPartitionEntries(r2, hdr.NumberOfPartitionEntries, hdr.SizeOfPartitionEntry, hdr.PartitionEntryArrayCRC32, checkCrc32)
}
