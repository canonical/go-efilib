// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package ioerr

import (
	"io"

	"golang.org/x/xerrors"
)

func EOFUnexpected(msg string, err error) error {
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return xerrors.Errorf("%s: %w", msg, err)
}

func PassEOF(msg string, err error) error {
	if err == io.EOF {
		return err
	}
	return xerrors.Errorf("%s: %w", msg, err)
}
