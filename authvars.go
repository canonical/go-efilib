// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/xerrors"
)

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
