// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package uefi

import (
	"encoding/binary"
	"io"
	"io/ioutil"

	"golang.org/x/xerrors"

	"github.com/canonical/go-efilib/internal/ioerr"
)

type EFI_LOAD_OPTION struct {
	Attributes         uint32
	FilePathListLength uint16
	Description        []uint16
	FilePathList       []byte
	OptionalData       []byte
}

func (o *EFI_LOAD_OPTION) WriteTo(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, o.Attributes); err != nil {
		return xerrors.Errorf("cannot write Attributes: %w", err)
	}
	if err := binary.Write(w, binary.LittleEndian, o.FilePathListLength); err != nil {
		return xerrors.Errorf("cannot write FilePathListLength: %w", err)
	}
	if err := binary.Write(w, binary.LittleEndian, o.Description); err != nil {
		return xerrors.Errorf("cannot write Description: %w", err)
	}
	if _, err := w.Write(o.FilePathList); err != nil {
		return xerrors.Errorf("cannot write FilePathList: %w", err)
	}
	if _, err := w.Write(o.OptionalData); err != nil {
		return xerrors.Errorf("cannot write OptionalData: %w", err)
	}
	return nil
}

func Read_EFI_LOAD_OPTION(r io.Reader) (out *EFI_LOAD_OPTION, err error) {
	out = &EFI_LOAD_OPTION{}
	if err := binary.Read(r, binary.LittleEndian, &out.Attributes); err != nil {
		return nil, ioerr.PassEOF("cannot read Attributes: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &out.FilePathListLength); err != nil {
		return nil, ioerr.EOFUnexpected("cannot read FilePathListLength: %w", err)
	}
	for i := 0; ; i++ {
		var c uint16
		if err := binary.Read(r, binary.LittleEndian, &c); err != nil {
			return nil, ioerr.EOFUnexpected("cannot read character %i from Description: %w", err)
		}
		out.Description = append(out.Description, c)
		if c == 0 {
			break
		}
	}

	out.FilePathList = make([]byte, out.FilePathListLength)
	if _, err := io.ReadFull(r, out.FilePathList); err != nil {
		return nil, ioerr.EOFUnexpected("cannot read FilePathList: %w", err)
	}

	optionalData, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, xerrors.Errorf("cannot read OptionalData: %w", err)
	}
	out.OptionalData = optionalData

	return out, nil
}
