// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"

	"golang.org/x/xerrors"

	"github.com/canonical/go-efilib/internal/uefi"
)

// LoadOption corresponds to the EFI_LOAD_OPTION type.
type LoadOption struct {
	Attributes   uint32
	Description  string
	FilePath     DevicePath
	OptionalData []byte
}

func (o *LoadOption) String() string {
	return fmt.Sprintf("EFI_LOAD_OPTION{ Attributes: %d, Description: \"%s\", FilePath: %s, OptionalData: %x }",
		o.Attributes, o.Description, o.FilePath, o.OptionalData)
}

func (o *LoadOption) Write(w io.Writer) error {
	opt := uefi.EFI_LOAD_OPTION{
		Attributes:   o.Attributes,
		Description:  ConvertUTF8ToUTF16(o.Description + "\x00"),
		OptionalData: o.OptionalData}

	dp := new(bytes.Buffer)
	if err := o.FilePath.Write(dp); err != nil {
		return err
	}
	if dp.Len() > math.MaxUint16 {
		return errors.New("FilePath too long")
	}
	opt.FilePathList = dp.Bytes()
	opt.FilePathListLength = uint16(dp.Len())

	return opt.Write(w)
}

// ReadLoadOption reads a LoadOption from the supplied io.Reader.
// This function will consume all of the bytes available.
func ReadLoadOption(r io.Reader) (out *LoadOption, err error) {
	opt, err := uefi.Read_EFI_LOAD_OPTION(r)
	if err != nil {
		return nil, err
	}

	out = &LoadOption{
		Attributes:   opt.Attributes,
		Description:  ConvertUTF16ToUTF8(opt.Description),
		OptionalData: opt.OptionalData}

	dp, err := ReadDevicePath(bytes.NewReader(opt.FilePathList))
	if err != nil {
		return nil, xerrors.Errorf("cannot read device path: %w", err)
	}
	out.FilePath = dp

	return out, nil
}
