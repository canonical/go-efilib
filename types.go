package efi

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
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

func (l *SignatureList) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "EFI_SIGNATURE_LIST{ SignatureType: %v, SignatureHeader: %x, Signatures: [", l.Type, l.Header)
	for _, d := range l.Signatures {
		fmt.Fprintf(&b, "\n\tEFI_SIGNATURE_DATA{ SignatureOwner: %v, Details: {", d.Owner)
		switch l.Type {
		case CertSHA1Guid, CertSHA256Guid, CertSHA224Guid, CertSHA384Guid, CertSHA512Guid:
			fmt.Fprintf(&b, "\n\t\tHash: %x", d.Data)
		case CertX509Guid:
			cert, err := x509.ParseCertificate(d.Data)
			if err != nil {
				fmt.Fprintf(&b, "%v", err)
			}
			h := crypto.SHA256.New()
			h.Write(cert.RawTBSCertificate)
			fmt.Fprintf(&b, "\n\t\tSubject: %v\n\t\tIssuer: %v\n\t\tSHA256 fingerprint: %x", cert.Subject, cert.Issuer, h.Sum(nil))
		default:
			fmt.Fprintf(&b, "<unrecognized type>")
		}
		fmt.Fprintf(&b, "}}")
	}
	fmt.Fprintf(&b, "]")
	return b.String()
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

func (db SignatureDatabase) String() string {
	var s string
	for _, l := range db {
		s = s + "\n" + l.String() + "\n"
	}
	return s
}

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

const (
	winCertTypePKCSSignedData = 0x0002
	winCertTypePKCS115        = 0x0ef0
	winCertTypeGUID           = 0x0ef1
)

type winCertificate struct {
	Length   uint32
	Revision uint16
	Type     uint16
}

// WinCertificate is an interface type corresponding to implementations of WIN_CERTIFICATE.
type WinCertificate interface {
	Encode(w io.Writer) error // Encode this certificate to the supplied io.Writer
}

// WinCertificatePKCS1_15 corresponds to the WIN_CERTIFICATE_EFI_PKCS1_15 type.
type WinCertificatePKCS1_15 struct {
	HashAlgorithm GUID
	Signature     []byte
}

func (c *WinCertificatePKCS1_15) Encode(w io.Writer) error {
	var buf bytes.Buffer
	if _, err := buf.Write(c.HashAlgorithm[:]); err != nil {
		return err
	}
	if _, err := buf.Write(c.Signature); err != nil {
		return err
	}
	hdr := winCertificate{Revision: 0x0200, Type: winCertTypePKCS115}
	hdr.Length = uint32(binary.Size(hdr) + buf.Len())
	if err := binary.Write(w, binary.LittleEndian, hdr); err != nil {
		return err
	}
	_, err := buf.WriteTo(w)
	return err
}

// WinCertificateGUID corresponds to the WIN_CERTIFICATE_UEFI_GUID type.
type WinCertificateGUID struct {
	Type GUID
	Data []byte
}

func (c *WinCertificateGUID) Encode(w io.Writer) error {
	var buf bytes.Buffer
	if _, err := buf.Write(c.Type[:]); err != nil {
		return err
	}
	if _, err := buf.Write(c.Data); err != nil {
		return err
	}
	hdr := winCertificate{Revision: 0x0200, Type: winCertTypeGUID}
	hdr.Length = uint32(binary.Size(hdr) + buf.Len())
	if err := binary.Write(w, binary.LittleEndian, hdr); err != nil {
		return err
	}
	_, err := buf.WriteTo(w)
	return err
}

// WinCertificateAuthenticode corresponds to an Authenticode signature.
type WinCertificateAuthenticode []byte

func (c WinCertificateAuthenticode) Encode(w io.Writer) error {
	hdr := winCertificate{Revision: 0x0200, Type: winCertTypePKCSSignedData}
	hdr.Length = uint32(binary.Size(hdr) + len(c))
	if err := binary.Write(w, binary.LittleEndian, hdr); err != nil {
		return err
	}
	_, err := w.Write(c)
	return err
}

// DecodeWinCertificate decodes a signature (something that is confusingly represented by types with "certificate" in the name in both
// the UEFI and PE/COFF specifications) from the supplied io.Reader and returns a WinCertificate of the appropriate type. The type
// returned is dependent on the data, and will be one of *WinCertificateAuthenticode, *WinCertificatePKCS1_15 or *WinCertificateGUID.
func DecodeWinCertificate(r io.Reader) (WinCertificate, error) {
	var hdr winCertificate
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return nil, xerrors.Errorf("cannot read WIN_CERTIFICATE header: %w", err)
	}
	if hdr.Revision != 0x0200 {
		return nil, errors.New("unexpected revision")
	}

	switch hdr.Type {
	case winCertTypePKCSSignedData:
		cert := make(WinCertificateAuthenticode, int(hdr.Length)-binary.Size(hdr))
		if _, err := io.ReadFull(r, cert); err != nil {
			return nil, xerrors.Errorf("cannot read Authenticode data: %w", err)
		}
		return cert, nil
	case winCertTypePKCS115:
		cert := &WinCertificatePKCS1_15{}
		h, err := ReadGUID(r)
		if err != nil {
			return nil, xerrors.Errorf("cannot read WIN_CERTIFICATE_EFI_PKCS1_15.HashAlgorithm: %w", err)
		}
		cert.HashAlgorithm = h
		cert.Signature = make([]byte, int(hdr.Length)-binary.Size(hdr)-binary.Size(cert.HashAlgorithm))
		if _, err := io.ReadFull(r, cert.Signature); err != nil {
			return nil, xerrors.Errorf("cannot read WIN_CERTIFICATE_EFI_PKCS1_15.Signature: %w", err)
		}
		return cert, nil
	case winCertTypeGUID:
		cert := &WinCertificateGUID{}
		t, err := ReadGUID(r)
		if err != nil {
			return nil, xerrors.Errorf("cannot read WIN_CERTIFICATE_UEFI_GUID.CertType: %w", err)
		}
		cert.Type = t
		cert.Data = make([]byte, int(hdr.Length)-binary.Size(hdr)-binary.Size(cert.Type))
		if _, err := io.ReadFull(r, cert.Data); err != nil {
			return nil, xerrors.Errorf("cannot read WIN_CERTIFICATE_UEFI_GUID.CertData: %w", err)
		}
		return cert, nil
	default:
		return nil, errors.New("unexpected type")
	}
}

type efiTime struct {
	Year       uint16
	Month      uint8
	Day        uint8
	Hour       uint8
	Minute     uint8
	Second     uint8
	Pad1       uint8
	Nanosecond uint32
	Timezone   int16
	Daylight   uint8
	Pad2       uint8
}

func (t *efiTime) toGoTime() time.Time {
	return time.Date(int(t.Year), time.Month(t.Month), int(t.Day), int(t.Hour), int(t.Minute), int(t.Second), int(t.Nanosecond), time.FixedZone("", -int(t.Timezone)*60))
}

func goTimeToEfiTime(t time.Time) *efiTime {
	_, offset := t.Zone()
	return &efiTime{
		Year:       uint16(t.Year()),
		Month:      uint8(t.Month()),
		Day:        uint8(t.Day()),
		Hour:       uint8(t.Hour()),
		Minute:     uint8(t.Minute()),
		Second:     uint8(t.Second()),
		Nanosecond: uint32(t.Nanosecond()),
		Timezone:   -int16(offset / 60)}
}

// VariableAuthentication correspond to the EFI_VARIABLE_AUTHENTICATION type and is provided as a header when updating a variable with
// the EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS attribute set.
type VariableAuthentication struct {
	MonotonicCount uint64
	AuthInfo       WinCertificateGUID
}

func (a *VariableAuthentication) Encode(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, a.MonotonicCount); err != nil {
		return err
	}
	return a.AuthInfo.Encode(w)
}

// DecodeVariableAuthentication decodes a header for updating a variable with the EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS attribute
// set.
func DecodeVariableAuthentication(r io.Reader) (*VariableAuthentication, error) {
	var monotonicCount uint64
	if err := binary.Read(r, binary.LittleEndian, &monotonicCount); err != nil {
		return nil, err
	}
	cert, err := DecodeWinCertificate(r)
	if err != nil {
		return nil, xerrors.Errorf("cannot decode AuthInfo: %w", err)
	}
	certGuid, ok := cert.(*WinCertificateGUID)
	if !ok {
		return nil, errors.New("AuthInfo has the wrong type")
	}
	return &VariableAuthentication{MonotonicCount: monotonicCount, AuthInfo: *certGuid}, nil
}

// VariableAuthentication2 correspond to the EFI_VARIABLE_AUTHENTICATION_2 type and is provided as a header when updating a variable
// with the EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute set.
type VariableAuthentication2 struct {
	TimeStamp time.Time
	AuthInfo  WinCertificateGUID
}

func (a *VariableAuthentication2) Encode(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, goTimeToEfiTime(a.TimeStamp)); err != nil {
		return err
	}
	return a.AuthInfo.Encode(w)
}

// DecodeTimeBasedVariableAuthentication decodes the header for updating a variable with the
// EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute set.
func DecodeTimeBasedVariableAuthentication(r io.Reader) (*VariableAuthentication2, error) {
	var t efiTime
	if err := binary.Read(r, binary.LittleEndian, &t); err != nil {
		return nil, err
	}
	cert, err := DecodeWinCertificate(r)
	if err != nil {
		return nil, xerrors.Errorf("cannot decode AuthInfo: %w", err)
	}
	certGuid, ok := cert.(*WinCertificateGUID)
	if !ok {
		return nil, errors.New("AuthInfo has the wrong type")
	}
	return &VariableAuthentication2{TimeStamp: t.toGoTime(), AuthInfo: *certGuid}, nil
}

const (
	variableAuthentication3TimestampType = 1
	variableAuthentication3NonceType     = 2
)

type variableAuthentication3 struct {
	Version      uint8
	Type         uint8
	MetadataSize uint32
	Flags        uint32
}

// VariableAuthentication3 represents the header for updating a variable with the EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS
// attribute set.
type VariableAuthentication3 interface{}

// VariableAuthentication3Timestamp corresponds to the header for updating a variable with the
// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS attribute set, and a type of EFI_VARIABLE_AUTHENTICATION_3_TIMESTAMP_TYPE.
type VariableAuthentication3Timestamp struct {
	TimeStamp   time.Time
	NewCert     *WinCertificateGUID
	SigningCert WinCertificateGUID
}

func (a *VariableAuthentication3Timestamp) Encode(w io.Writer) error {
	hdr := variableAuthentication3{
		Version: 1,
		Type:    variableAuthentication3TimestampType}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, goTimeToEfiTime(a.TimeStamp)); err != nil {
		return err
	}
	if a.NewCert != nil {
		hdr.Flags = 1
		if err := a.NewCert.Encode(&buf); err != nil {
			return err
		}
	}
	if err := a.SigningCert.Encode(&buf); err != nil {
		return err
	}

	hdr.MetadataSize = uint32(binary.Size(hdr) + buf.Len())
	if err := binary.Write(w, binary.LittleEndian, hdr); err != nil {
		return err
	}
	_, err := buf.WriteTo(w)
	return err
}

// VariableAuthentication3Nonce corresponds to the header for updating a variable with the
// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS attribute set, and a type of EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE.
type VariableAuthentication3Nonce struct {
	Nonce       []byte
	NewCert     *WinCertificateGUID
	SigningCert WinCertificateGUID
}

func (a *VariableAuthentication3Nonce) Encode(w io.Writer) error {
	hdr := variableAuthentication3{
		Version: 1,
		Type:    variableAuthentication3NonceType}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, uint32(len(a.Nonce))); err != nil {
		return err
	}
	if _, err := buf.Write(a.Nonce); err != nil {
		return err
	}
	if a.NewCert != nil {
		hdr.Flags = 1
		if err := a.NewCert.Encode(&buf); err != nil {
			return err
		}
	}
	if err := a.SigningCert.Encode(&buf); err != nil {
		return err
	}

	hdr.MetadataSize = uint32(binary.Size(hdr) + buf.Len())
	if err := binary.Write(w, binary.LittleEndian, hdr); err != nil {
		return err
	}
	_, err := buf.WriteTo(w)
	return err
}

// DecodeEnhancedVariableAuthentication decodes the header for updating a variable with the
// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS attribute set.
func DecodeEnhancedVariableAuthentication(r io.Reader) (VariableAuthentication3, error) {
	var hdr variableAuthentication3
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}
	if hdr.Version != 1 {
		return nil, errors.New("unexpected version")
	}

	lr := io.LimitReader(r, int64(hdr.MetadataSize)-int64(binary.Size(hdr)))

	switch hdr.Type {
	case variableAuthentication3TimestampType:
		var t efiTime
		if err := binary.Read(lr, binary.LittleEndian, &t); err != nil {
			return nil, err
		}

		var newCert *WinCertificateGUID
		if hdr.Flags&1 > 0 {
			cert, err := DecodeWinCertificate(lr)
			if err != nil {
				return nil, xerrors.Errorf("cannot decode new cert: %w", err)
			}
			var ok bool
			newCert, ok = cert.(*WinCertificateGUID)
			if !ok {
				return nil, errors.New("new cert has the wrong type")
			}
		}

		cert, err := DecodeWinCertificate(lr)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode signing cert: %w", err)
		}
		signingCert, ok := cert.(*WinCertificateGUID)
		if !ok {
			return nil, errors.New("signing cert has the wrong type")
		}

		return &VariableAuthentication3Timestamp{TimeStamp: t.toGoTime(), NewCert: newCert, SigningCert: *signingCert}, nil
	case variableAuthentication3NonceType:
		var nonceSize uint32
		if err := binary.Read(lr, binary.LittleEndian, &nonceSize); err != nil {
			return nil, err
		}
		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(lr, nonce); err != nil {
			return nil, err
		}

		var newCert *WinCertificateGUID
		if hdr.Flags&1 > 0 {
			cert, err := DecodeWinCertificate(lr)
			if err != nil {
				return nil, xerrors.Errorf("cannot decode new cert: %w", err)
			}
			var ok bool
			newCert, ok = cert.(*WinCertificateGUID)
			if !ok {
				return nil, errors.New("new cert has the wrong type")
			}
		}

		cert, err := DecodeWinCertificate(lr)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode signing cert: %w", err)
		}
		signingCert, ok := cert.(*WinCertificateGUID)
		if !ok {
			return nil, errors.New("signing cert has the wrong type")
		}

		return &VariableAuthentication3Nonce{Nonce: nonce, NewCert: newCert, SigningCert: *signingCert}, nil
	default:
		return nil, errors.New("unexpected type")
	}
}

// VariableAuthentication3Descriptor corresponds to the authentication descriptor provided when reading the payload of a variable
// with the EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS attribute set.
type VariableAuthentication3Descriptor interface{}

const (
	VariableAuthentication3DescriptorCertIDSHA256 = 1
)

type VariableAuthentication3DescriptorCertId struct {
	Type uint8
	Id   []byte
}

func decodeVariableAuthentication3DescriptorCertId(r io.Reader) (*VariableAuthentication3DescriptorCertId, error) {
	var h struct {
		Type   uint8
		IdSize uint32
	}
	if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
		return nil, err
	}
	id := make([]byte, int(h.IdSize))
	if _, err := io.ReadFull(r, id); err != nil {
		return nil, err
	}

	return &VariableAuthentication3DescriptorCertId{Type: h.Type, Id: id}, nil
}

// VariableAuthentication3TimestampDescriptor corresponds to the authentication descriptor provided when reading the payload of a
// variable with the EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS attribute set, and a type of
// EFI_VARIABLE_AUTHENTICATION_3_TIMESTAMP_TYPE.
type VariableAuthentication3TimestampDescriptor struct {
	TimeStamp time.Time
	VariableAuthentication3DescriptorCertId
}

// VariableAuthentication3NonceDescriptor corresponds to the authentication descriptor provided when reading the payload of a
// variable with the EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS attribute set, and a type of
// EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE.
type VariableAuthentication3NonceDescriptor struct {
	Nonce []byte
	VariableAuthentication3DescriptorCertId
}

// DecodeEnhancedAuthenticationDescriptor decodes the enhanced authentication descriptor from the supplied io.Reader. The supplied
// reader will typically read from the payload area of a variable with the EFI_VARIABLE_ENHANCED_AUTHENTICATION_ACCESS attribute set,
// returned from a call to OpenVar. Alternatively, for reading variables that you know have this attribute set, use
// ReadEnhancedAuthenticatedVar or OpenEnhancedAuthenticatedVar instead.
func DecodeEnhancedAuthenticationDescriptor(r io.Reader) (VariableAuthentication3Descriptor, error) {
	var hdr variableAuthentication3
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}
	if hdr.Version != 1 {
		return nil, errors.New("unexpected version")
	}

	lr := io.LimitReader(r, int64(hdr.MetadataSize)-int64(binary.Size(hdr)))

	switch hdr.Type {
	case variableAuthentication3TimestampType:
		var t efiTime
		if err := binary.Read(lr, binary.LittleEndian, &t); err != nil {
			return nil, err
		}
		id, err := decodeVariableAuthentication3DescriptorCertId(lr)
		if err != nil {
			return nil, err
		}
		return &VariableAuthentication3TimestampDescriptor{
			TimeStamp:                               t.toGoTime(),
			VariableAuthentication3DescriptorCertId: *id}, nil
	case variableAuthentication3NonceType:
		var nonceSize uint32
		if err := binary.Read(lr, binary.LittleEndian, &nonceSize); err != nil {
			return nil, err
		}
		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(lr, nonce); err != nil {
			return nil, err
		}
		id, err := decodeVariableAuthentication3DescriptorCertId(lr)
		if err != nil {
			return nil, err
		}
		return &VariableAuthentication3NonceDescriptor{
			Nonce:                                   nonce,
			VariableAuthentication3DescriptorCertId: *id}, nil
	default:
		return nil, errors.New("unexpected type")
	}
}
