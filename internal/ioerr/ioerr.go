// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package ioerr

import (
	"io"

	"golang.org/x/xerrors"
)

// EOFUnexpected is a wrapper around xerrors.Errorf that will convert
// io.EOF errors into io.ErrUnexpectedEOF, which is useful when using
// binary.Read to decode parts of a structure that aren't at the start
// and when a io.EOF error is not expected. This only works on raw
// io.EOF errors - ie, it won't work on errors that have been wrapped.
func EOFUnexpected(format string, args ...interface{}) error {
	args2 := make([]interface{}, len(args))
	copy(args2, args)
	for i, a := range args2 {
		if e, isErr := a.(error); isErr && e == io.EOF {
			args2[i] = io.ErrUnexpectedEOF
		}
	}

	return xerrors.Errorf(format, args2...)
}

// PassEOF is a wrapper around xerrors.Errorf that will return a raw
// io.EOF if this is the error.
func PassEOF(format string, args ...interface{}) error {
	err := xerrors.Errorf(format, args...)
	if xerrors.Is(err, io.EOF) {
		return io.EOF
	}
	return err
}
