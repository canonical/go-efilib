package efi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"

	"golang.org/x/xerrors"
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

var (
	// CertSHA1Guid corresponds to EFI_CERT_SHA1_GUID
	CertSHA1Guid = MakeGUID(0x826ca512, 0xcf10, 0x4ac9, 0xb187, [...]uint8{0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd})
	// CertSHA256Guid corresponds to EFI_CERT_SHA256_GUID
	CertSHA256Guid = MakeGUID(0xc1c41626, 0x504c, 0x4092, 0xaca9, [...]uint8{0x41, 0xf9, 0x36, 0x93, 0x43, 0x28})
	// CertSHA224Guid corresponds to EFI_CERT_SHA224_GUID
	CertSHA224Guid = MakeGUID(0xb6e5233, 0xa65c, 0x44c9, 0x9407, [...]uint8{0xd9, 0xab, 0x83, 0xbf, 0xc8, 0xbd})
	// CertSHA384Guid corresponds to EFI_CERT_SHA384_GUID
	CertSHA384Guid = MakeGUID(0xff3e5307, 0x9fd0, 0x48c9, 0x85f1, [...]uint8{0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01})
	// CertSHA512Guid corresponds to EFI_CERT_SHA512_GUID
	CertSHA512Guid = MakeGUID(0x093e0fae, 0xa6c4, 0x4f50, 0x9f1b, [...]uint8{0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a})

	// CertRSA2048Guid corresponds to EFI_CERT_RSA2048_GUID
	CertRSA2048Guid = MakeGUID(0x3c5766e8, 0x269c, 0x4e34, 0xaa14, [...]uint8{0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6})
	// CertRSA2048SHA1Guid corresponds to EFI_CERT_RSA2048_SHA1_GUID
	CertRSA2048SHA1Guid = MakeGUID(0x67f8444f, 0x8743, 0x48f1, 0xa328, [...]uint8{0x1e, 0xaa, 0xb8, 0x73, 0x60, 0x80})
	// CertRSA2048SHA256Guid corresponds to EFI_CERT_RSA2048_SHA256_GUID
	CertRSA2048SHA256Guid = MakeGUID(0xe2b36190, 0x879b, 0x4a3d, 0xad8d, [...]uint8{0xf2, 0xe7, 0xbb, 0xa3, 0x27, 0x84})

	// CertX509Guid corresponds to EFI_CERT_X509_GUID
	CertX509Guid = MakeGUID(0xa5c059a1, 0x94e4, 0x4aa7, 0x87b5, [...]uint8{0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72})
	// CertX509SHA256Guid corresponds to EFI_CERT_X509_SHA256_GUID
	CertX509SHA256Guid = MakeGUID(0x3bd2a492, 0x96c0, 0x4079, 0xb420, [...]uint8{0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed})
	// CertX509SHA384Guid corresponds to EFI_CERT_X509_SHA384_GUID
	CertX509SHA384Guid = MakeGUID(0x7076876e, 0x80c2, 0x4ee6, 0xaad2, [...]uint8{0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b})
	// CertX509SHA512Guid corresponds to EFI_CERT_X509_SHA512_GUID
	CertX509SHA512Guid = MakeGUID(0x446dbf63, 0x2502, 0x4cda, 0xbcfa, [...]uint8{0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d})
)

type signatureListHdr struct {
	Type          GUID
	ListSize      uint32
	HeaderSize    uint32
	SignatureSize uint32
}

// SignatureData corresponds to the EFI_SIGNATURE_DATA type.
type SignatureData struct {
	Owner GUID
	Data  []byte
}

// Encode serializes this signature data to w.
func (d *SignatureData) Encode(w io.Writer) error {
	if _, err := w.Write(d.Owner[:]); err != nil {
		return err
	}
	_, err := w.Write(d.Data)
	return err
}

// SignatureList corresponds to the EFI_SIGNATURE_LIST type.
type SignatureList struct {
	Type       GUID
	Header     []byte
	Signatures []*SignatureData
}

// Encode serializes this signature list to w.
func (l *SignatureList) Encode(w io.Writer) error {
	lh := signatureListHdr{Type: l.Type, HeaderSize: uint32(len(l.Header))}

	var signatures bytes.Buffer
	for i, s := range l.Signatures {
		var sig bytes.Buffer
		if err := s.Encode(&sig); err != nil {
			return xerrors.Errorf("cannot encode signature %d: %w", i, err)
		}
		if i == 0 {
			lh.SignatureSize = uint32(sig.Len())
		}
		if uint32(sig.Len()) != lh.SignatureSize {
			// EFI_SIGNATURE_LIST cannot contain EFI_SIGNATURE_DATA entries with different
			// sizes - they must go in their own list.
			return fmt.Errorf("signature %d contains the wrong size", i)
		}
		if _, err := sig.WriteTo(&signatures); err != nil {
			return err
		}
	}

	lh.ListSize = uint32(binary.Size(lh)) + lh.HeaderSize + uint32(signatures.Len())

	if err := binary.Write(w, binary.LittleEndian, lh); err != nil {
		return err
	}
	if _, err := w.Write(l.Header); err != nil {
		return err
	}
	_, err := signatures.WriteTo(w)
	return err
}

// SignatureDatabase corresponds to a list of EFI_SIGNATURE_LIST structures.
type SignatureDatabase []*SignatureList

// Encode serializes this signature database to w.
func (db SignatureDatabase) Encode(w io.Writer) error {
	for i, l := range db {
		if err := l.Encode(w); err != nil {
			return xerrors.Errorf("cannot encode signature list %d: %w", i, err)
		}
	}
	return nil
}

// DecodeSignatureDatabase decodes a list of EFI_SIGNATURE_DATABASE structures from r.
func DecodeSignatureDatabase(r io.Reader) (SignatureDatabase, error) {
	var db SignatureDatabase
	for i := 0; ; i++ {
		var lh signatureListHdr
		if err := binary.Read(r, binary.LittleEndian, &lh); err != nil {
			if err == io.EOF {
				break
			}
			return nil, xerrors.Errorf("cannot read EFI_SIGNATURE_LIST %d: %w", i, err)
		}

		signatureDataSize := lh.ListSize - lh.HeaderSize - uint32(binary.Size(lh))
		if signatureDataSize%lh.SignatureSize != 0 {
			return nil, fmt.Errorf("EFI_SIGNATURE_LIST %d has inconsistent size fields", i)
		}
		if lh.SignatureSize < uint32(binary.Size(GUID{})) {
			return nil, fmt.Errorf("EFI_SIGNATURE_LIST %d has an invalid SignatureSize field", i)
		}
		numOfSignatures := int(signatureDataSize / lh.SignatureSize)

		l := &SignatureList{Type: lh.Type, Header: make([]byte, lh.HeaderSize)}

		if _, err := io.ReadFull(r, l.Header); err != nil {
			return nil, xerrors.Errorf("cannot read EFI_SIGNATURE_LIST.SignatureHeader at index %d: %w", i, err)
		}

		for j := 0; j < numOfSignatures; j++ {
			var d SignatureData
			owner, err := ReadGUID(r)
			if err != nil {
				return nil, xerrors.Errorf("cannot read EFI_SIGNATURE_DATA.SignatureOwner at index %d in EFI_SIGNATURE_LIST %d: %w", j, i, err)
			}
			d.Owner = owner
			d.Data = make([]byte, int(lh.SignatureSize)-binary.Size(owner))
			if _, err := io.ReadFull(r, d.Data); err != nil {
				return nil, xerrors.Errorf("cannot read EFI_SIGNATURE_DATA.SignatureData at index %d in EFI_SIGNATURE_LIST %d: %w", j, i, err)
			}

			l.Signatures = append(l.Signatures, &d)
		}

		db = append(db, l)
	}

	return db, nil
}
