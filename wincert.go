// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/xerrors"
)

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
