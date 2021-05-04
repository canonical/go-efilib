// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package uefi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-efilib/internal/ioerr"

	"golang.org/x/xerrors"
)

const ESLHeaderSize = 28

type EFI_SIGNATURE_DATA struct {
	SignatureOwner EFI_GUID
	SignatureData  []byte
}

func (d *EFI_SIGNATURE_DATA) Encode(w io.Writer) error {
	if _, err := w.Write(d.SignatureOwner[:]); err != nil {
		return xerrors.Errorf("cannot write SignatureOwner: %w", err)
	}
	if _, err := w.Write(d.SignatureData); err != nil {
		return xerrors.Errorf("cannot write SignatureData: %w", err)
	}
	return nil
}

type EFI_SIGNATURE_LIST struct {
	SignatureType       EFI_GUID
	SignatureListSize   uint32
	SignatureHeaderSize uint32
	SignatureSize       uint32

	SignatureHeader []byte
	Signatures      []EFI_SIGNATURE_DATA
}

func (l *EFI_SIGNATURE_LIST) Encode(w io.Writer) error {
	if _, err := w.Write(l.SignatureType[:]); err != nil {
		return xerrors.Errorf("cannot write SignatureType: %w", err)
	}
	if err := binary.Write(w, binary.LittleEndian, l.SignatureListSize); err != nil {
		return xerrors.Errorf("cannot write SignatureListSize: %w", err)
	}
	if err := binary.Write(w, binary.LittleEndian, l.SignatureHeaderSize); err != nil {
		return xerrors.Errorf("cannot write SignatureHeaderSize: %w", err)
	}
	if err := binary.Write(w, binary.LittleEndian, l.SignatureSize); err != nil {
		return xerrors.Errorf("cannot write SignatureSize: %w", err)
	}

	if _, err := w.Write(l.SignatureHeader); err != nil {
		return xerrors.Errorf("cannot write SignatureHeader: %w", err)
	}

	for i, s := range l.Signatures {
		if err := s.Encode(w); err != nil {
			return xerrors.Errorf("cannot write signature %d: %w", i, err)
		}
	}

	return nil
}

func Read_EFI_SIGNATURE_LIST(r io.Reader) (out *EFI_SIGNATURE_LIST, err error) {
	out = &EFI_SIGNATURE_LIST{}
	if err := binary.Read(r, binary.LittleEndian, &out.SignatureType); err != nil {
		return nil, ioerr.PassEOF("cannot read SignatureType", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &out.SignatureListSize); err != nil {
		return nil, ioerr.EOFUnexpected("cannot read SignatureListSize", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &out.SignatureHeaderSize); err != nil {
		return nil, ioerr.EOFUnexpected("cannot read SignatureHeaderSize", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &out.SignatureSize); err != nil {
		return nil, ioerr.EOFUnexpected("cannot read SignatureSize", err)
	}

	out.SignatureHeader = make([]byte, out.SignatureHeaderSize)
	if _, err := io.ReadFull(r, out.SignatureHeader); err != nil {
		return nil, ioerr.EOFUnexpected("cannot read SignatureHeader", err)
	}

	signaturesSize := out.SignatureListSize - out.SignatureHeaderSize - ESLHeaderSize
	if signaturesSize%out.SignatureSize != 0 {
		return nil, errors.New("inconsistent size fields")
	}
	if out.SignatureSize < uint32(binary.Size(EFI_GUID{})) {
		return nil, errors.New("invalid SignatureSize")
	}
	numOfSignatures := int(signaturesSize / out.SignatureSize)

	for i := 0; i < numOfSignatures; i++ {
		var s EFI_SIGNATURE_DATA
		if _, err := io.ReadFull(r, s.SignatureOwner[:]); err != nil {
			return nil, ioerr.EOFUnexpected(fmt.Sprintf("cannot read SignatureOwner for %d", i), err)
		}

		s.SignatureData = make([]byte, int(out.SignatureSize)-binary.Size(s.SignatureOwner))
		if _, err := io.ReadFull(r, s.SignatureData); err != nil {
			return nil, ioerr.EOFUnexpected(fmt.Sprintf("cannot read SignatureData for %d", i), err)
		}

		out.Signatures = append(out.Signatures, s)
	}

	return out, nil
}
