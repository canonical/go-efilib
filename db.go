package efi

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/xerrors"
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
