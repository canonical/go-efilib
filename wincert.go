// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/xerrors"

	"github.com/canonical/go-efilib/internal/ioerr"
	"github.com/canonical/go-efilib/internal/pkcs7"
	"github.com/canonical/go-efilib/internal/uefi"
)

var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	oidSpcIndirectData   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSpcPeImageDataobj = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
)

type digestInfo struct {
	DigestAlgorithm pkix.AlgorithmIdentifier
	Digest          []byte
}

type spcPeImageData struct {
	Flags asn1.BitString
	File  asn1.RawValue `asn1:"tag:0"`
}

type spcAttributeTypeAndOptionalValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type spcIndirectDataContent struct {
	Data          spcAttributeTypeAndOptionalValue
	MessageDigest digestInfo
}

type authenticodeContent struct {
	digestAlgorithm asn1.ObjectIdentifier
	flags           asn1.BitString
	digest          []byte
}

func unmarshalAuthenticodeContent(data []byte) (*authenticodeContent, error) {
	var content spcIndirectDataContent
	if _, err := asn1.Unmarshal(data, &content); err != nil {
		return nil, err
	}

	if !content.Data.Type.Equal(oidSpcPeImageDataobj) {
		return nil, asn1.StructuralError{Msg: "not a PE image data object"}
	}

	var peData spcPeImageData
	if _, err := asn1.Unmarshal(content.Data.Value.FullBytes, &peData); err != nil {
		return nil, err
	}

	return &authenticodeContent{
		digestAlgorithm: content.MessageDigest.DigestAlgorithm.Algorithm,
		flags:           peData.Flags,
		digest:          content.MessageDigest.Digest}, nil
}

func buildCertChains(chain []*x509.Certificate, root *x509.Certificate, intermediates []*x509.Certificate, depth *int) (chains [][]*x509.Certificate) {
	alreadyInChain := func(cert *x509.Certificate) bool {
		for _, c := range chain {
			if c.Equal(cert) {
				return true
			}
		}
		return false
	}

	if depth == nil {
		depth = new(int)
	}
	*depth++
	if *depth > 100 {
		return nil
	}

	current := chain[len(chain)-1]

	if current.Equal(root) {
		chains = append(chains, append(chain))
	}

	if !alreadyInChain(root) {
		if err := current.CheckSignatureFrom(root); err == nil {
			chains = append(chains, append(chain, root))
		}
	}

	for _, cert := range intermediates {
		if alreadyInChain(cert) {
			continue
		}
		if err := current.CheckSignatureFrom(cert); err != nil {
			continue
		}

		childChains := buildCertChains(append(chain, cert), root, intermediates, depth)
		chains = append(chains, childChains...)
	}

	return chains
}

type WinCertificateType uint16

const (
	// WinCertificateTypeAuthenticode indicates that a WinCertificate
	// is an authenticode signature and is implemented by the
	// *WinCertificateAuthenticode type.
	WinCertificateTypeAuthenticode WinCertificateType = uefi.WIN_CERT_TYPE_PKCS_SIGNED_DATA

	// WinCertificatePKCS1v15 indicates that a WinCertificate is a
	// PKCS#1-v1.5 encoded RSA2048 signature and is implemented by
	// the *WinCertificatePKCS1v15 type.
	WinCertificateTypePKCS1v15 WinCertificateType = uefi.WIN_CERT_TYPE_EFI_PKCS115

	// WinCertificateTypeGUID indicates that a WinCertificate is a
	// signature of a type indicated by a separate GUID and is implemented
	// by a type that implements the WinCertificateGUID interface.
	WinCertificateTypeGUID WinCertificateType = uefi.WIN_CERT_TYPE_EFI_GUID
)

// WinCertificate is an interface type corresponding to implementations of WIN_CERTIFICATE.
type WinCertificate interface {
	Type() WinCertificateType // Type of this certificate
}

// WinCertificatePKCS1v15 corresponds to the WIN_CERTIFICATE_EFI_PKCS1_15 type
// and represents a RSA2048 signature with PKCS#1 v1.5 padding.
type WinCertificatePKCS1v15 struct {
	HashAlgorithm crypto.Hash
	Signature     [256]byte
}

func (c *WinCertificatePKCS1v15) Type() WinCertificateType {
	return WinCertificateTypePKCS1v15
}

// WinCertificateGUID corresponds to implementations of WIN_CERTIFICATE_UEFI_GUID.
type WinCertificateGUID interface {
	WinCertificate
	GUIDType() GUID
}

func newWinCertificateGUID(cert *uefi.WIN_CERTIFICATE_UEFI_GUID) (WinCertificateGUID, error) {
	switch cert.CertType {
	case uefi.EFI_CERT_TYPE_RSA2048_SHA256_GUID:
		if len(cert.CertData) != binary.Size(WinCertificateGUIDPKCS1v15{}) {
			return nil, errors.New("invalid length for WIN_CERTIFICATE_UEFI_GUID with EFI_CERT_TYPE_RSA2048_SHA256_GUID type")
		}
		c := new(WinCertificateGUIDPKCS1v15)
		binary.Read(bytes.NewReader(cert.CertData), binary.LittleEndian, &c)
		return c, nil
	case uefi.EFI_CERT_TYPE_PKCS7_GUID:
		p7, err := pkcs7.UnmarshalPKCS7(cert.CertData)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode payload for WIN_CERTIFICATE_UEFI_GUID with EFI_CERT_TYPE_PKCS7_GUID type: %w", err)
		}
		return &WinCertificatePKCS7{p7: p7}, nil
	default:
		return &WinCertificateGUIDUnknown{unknownGUIDType: GUID(cert.CertType), Data: cert.CertData}, nil
	}
}

// WinCertificateGUIDUnknown corresponds to a WIN_CERTIFICATE_UEFI_GUID with
// an unknown type.
type WinCertificateGUIDUnknown struct {
	unknownGUIDType GUID
	Data            []byte
}

func (c *WinCertificateGUIDUnknown) Type() WinCertificateType {
	return WinCertificateTypeGUID
}

func (c *WinCertificateGUIDUnknown) GUIDType() GUID {
	return c.unknownGUIDType
}

// WinCertificateGUIDPKCS1v15 corresponds to a WIN_CERTIFICATE_UEFI_GUID with
// the EFI_CERT_TYPE_RSA2048_SHA256_GUID type, and represents a RSA2048 SHA256
// signature with PKCS#1 v1.5 padding
type WinCertificateGUIDPKCS1v15 struct {
	PublicKey [256]byte
	Signature [256]byte
}

func (c *WinCertificateGUIDPKCS1v15) Type() WinCertificateType {
	return WinCertificateTypeGUID
}

func (c *WinCertificateGUIDPKCS1v15) GUIDType() GUID {
	return CertTypeRSA2048SHA256Guid
}

// WinCertificatePKCS7 corresponds to a WIN_CERTIFICATE_UEFI_GUID with
// the EFI_CERT_TYPE_PKCS7_GUID type, and represents a detached PKCS7
// signature.
type WinCertificatePKCS7 struct {
	p7 *pkcs7.PKCS7
}

func (c *WinCertificatePKCS7) Type() WinCertificateType {
	return WinCertificateTypeGUID
}

func (c *WinCertificatePKCS7) GUIDType() GUID {
	return CertTypePKCS7Guid
}

// GetSigners returns the signing certificates.
func (c *WinCertificatePKCS7) GetSigners() []*x509.Certificate {
	return c.p7.GetSigners()
}

// CanBeVerifiedBy determines if the specified CA certificate can be used to verify
// this signature. This checks that the specified CA certificate is a signer of
// one or more certificate chains that terminate in the signer certificates -
// it does not check whether the signature will actually be verified successfully.
func (c *WinCertificatePKCS7) CanBeVerifiedBy(cert *x509.Certificate) bool {
	for _, s := range c.GetSigners() {
		chains := buildCertChains([]*x509.Certificate{s}, cert, c.p7.Certificates, nil)
		if len(chains) == 0 {
			return false
		}
	}

	return true
}

// WinCertificateAuthenticode corresponds to a WIN_CERTIFICATE_EFI_PKCS and
// represents an Authenticode signature.
type WinCertificateAuthenticode struct {
	p7           *pkcs7.PKCS7
	authenticode *authenticodeContent
}

func (c *WinCertificateAuthenticode) Type() WinCertificateType {
	return WinCertificateTypeAuthenticode
}

// GetSigner returns the signing certificate.
func (c *WinCertificateAuthenticode) GetSigner() *x509.Certificate {
	return c.p7.GetSigners()[0]
}

// CanBeVerifiedBy determines if the specified CA certificate can be used to verify
// this signature. This checks that the specified CA certificate is a signer of
// one or more certificate chains that terminate in the signer certificates -
// it does not check whether the signature will actually be verified successfully.
func (c *WinCertificateAuthenticode) CanBeVerifiedBy(cert *x509.Certificate) bool {
	chains := buildCertChains([]*x509.Certificate{c.GetSigner()}, cert, c.p7.Certificates, nil)
	if len(chains) == 0 {
		return false
	}
	return true
}

func (c *WinCertificateAuthenticode) DigestAlgorithm() crypto.Hash {
	switch {
	case c.authenticode.digestAlgorithm.Equal(oidSHA256):
		return crypto.SHA256
	default:
		return crypto.Hash(0)
	}
}

// Digest returns the PE image digest of the image associated with this
// signature.
func (c *WinCertificateAuthenticode) Digest() []byte {
	return c.authenticode.digest
}

func digestAlgorithmIdToCryptoHash(id GUID) (crypto.Hash, error) {
	switch id {
	case HashAlgorithmSHA1Guid:
		return crypto.SHA1, nil
	case HashAlgorithmSHA256Guid:
		return crypto.SHA256, nil
	case HashAlgorithmSHA224Guid:
		return crypto.SHA224, nil
	case HashAlgorithmSHA384Guid:
		return crypto.SHA384, nil
	case HashAlgorithmSHA512Guid:
		return crypto.SHA512, nil
	default:
		return crypto.Hash(0), errors.New("unrecognized digest")
	}
}

// ReadWinCertificate decodes a signature (something that is confusingly
// represented by types with "certificate" in the name in both the UEFI
// and PE/COFF specifications) from the supplied reader and returns a
// WinCertificate of the appropriate type. The type returned is dependent
// on the data, and will be one of *[WinCertificateAuthenticode],
// *[WinCertificatePKCS1v15], *[WinCertificatePKCS7] or
// *[WinCertificateGUIDPKCS1v15].
func ReadWinCertificate(r io.Reader) (WinCertificate, error) {
	var hdr uefi.WIN_CERTIFICATE
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}
	if hdr.Revision != 0x0200 {
		return nil, errors.New("unexpected revision")
	}

	switch hdr.CertificateType {
	case uefi.WIN_CERT_TYPE_PKCS_SIGNED_DATA:
		cert := uefi.WIN_CERTIFICATE_EFI_PKCS{Hdr: hdr}
		cert.CertData = make([]byte, int(cert.Hdr.Length)-binary.Size(cert.Hdr))
		if _, err := io.ReadFull(r, cert.CertData); err != nil {
			return nil, ioerr.EOFIsUnexpected("cannot read WIN_CERTIFICATE_EFI_PKCS: %w", err)
		}

		p7, err := pkcs7.UnmarshalAuthenticode(cert.CertData)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode WIN_CERTIFICATE_EFI_PKCS payload: %w", err)
		}
		if len(p7.GetSigners()) != 1 {
			return nil, errors.New("WIN_CERTIFICATE_EFI_PKCS has invalid number of signers")
		}

		if !p7.ContentType().Equal(oidSpcIndirectData) {
			return nil, errors.New("WIN_CERTIFICATE_EFI_PKCS has invalid content type")
		}
		auth, err := unmarshalAuthenticodeContent(p7.Content())
		if err != nil {
			return nil, xerrors.Errorf("cannot decode authenticode content for WIN_CERTIFICATE_EFI_PKCS: %w", err)
		}
		return &WinCertificateAuthenticode{p7: p7, authenticode: auth}, nil
	case uefi.WIN_CERT_TYPE_EFI_PKCS115:
		if hdr.Length != uint32(binary.Size(uefi.WIN_CERTIFICATE_EFI_PKCS1_15{})) {
			return nil, fmt.Errorf("invalid length for WIN_CERTIFICATE_EFI_PKCS1_15: %d", hdr.Length)
		}

		cert := uefi.WIN_CERTIFICATE_EFI_PKCS1_15{Hdr: hdr}
		if _, err := io.ReadFull(r, cert.HashAlgorithm[:]); err != nil {
			return nil, ioerr.EOFIsUnexpected("cannot read WIN_CERTIFICATE_EFI_PKCS1_15: %w", err)
		}
		if _, err := io.ReadFull(r, cert.Signature[:]); err != nil {
			return nil, ioerr.EOFIsUnexpected("cannot read WIN_CERTIFICATE_EFI_PKCS1_15: %w", err)
		}

		digest, err := digestAlgorithmIdToCryptoHash(GUID(cert.HashAlgorithm))
		if err != nil {
			return nil, xerrors.Errorf("cannot determine digest algorithm for WIN_CERTIFICATE_EFI_PKCS1_15: %w", err)
		}

		return &WinCertificatePKCS1v15{HashAlgorithm: digest, Signature: cert.Signature}, nil
	case uefi.WIN_CERT_TYPE_EFI_GUID:
		cert := uefi.WIN_CERTIFICATE_UEFI_GUID{Hdr: hdr}
		cert.CertData = make([]byte, int(cert.Hdr.Length)-binary.Size(cert.Hdr)-binary.Size(cert.CertType))
		if _, err := io.ReadFull(r, cert.CertType[:]); err != nil {
			return nil, ioerr.EOFIsUnexpected("cannot read WIN_CERTIFICATE_UEFI_GUID: %w", err)
		}
		if _, err := io.ReadFull(r, cert.CertData); err != nil {
			return nil, ioerr.EOFIsUnexpected("cannot read WIN_CERTIFICATE_UEFI_GUID: %w", err)
		}
		return newWinCertificateGUID(&cert)
	default:
		return nil, errors.New("unexpected type")
	}
}
