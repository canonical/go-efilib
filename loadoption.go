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
	"unicode/utf16"

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

func (o *LoadOption) WriteTo(w io.Writer) error {
	opt := uefi.EFI_LOAD_OPTION{
		Attributes:   o.Attributes,
		OptionalData: o.OptionalData}

	description := bytes.NewReader([]byte(o.Description + "\x00"))
	var unicodeDescription []rune
	for {
		c, _, err := description.ReadRune()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		unicodeDescription = append(unicodeDescription, c)
	}
	opt.Description = utf16.Encode(unicodeDescription)

	dp := new(bytes.Buffer)
	if err := o.FilePath.WriteTo(dp); err != nil {
		return err
	}
	if dp.Len() > math.MaxUint16 {
		return errors.New("FilePath too long")
	}
	opt.FilePathList = dp.Bytes()
	opt.FilePathListLength = uint16(dp.Len())

	return opt.WriteTo(w)
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
		OptionalData: opt.OptionalData}

	var description bytes.Buffer
	for _, c := range utf16.Decode(opt.Description) {
		if c == 0 {
			break
		}
		description.WriteRune(c)
	}
	out.Description = description.String()

	dp, err := ReadDevicePath(bytes.NewReader(opt.FilePathList))
	if err != nil {
		return nil, xerrors.Errorf("cannot read device path: %w", err)
	}
	out.FilePath = dp

	return out, nil
}
