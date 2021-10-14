// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type (
	EfivarfsVarsBackend = efivarfsVarsBackend
	VarFile             = varFile
)

var Defer = errors.New("")

func MockOpenVarFile(fn func(string, int, os.FileMode) (VarFile, error)) (restore func()) {
	orig := openVarFile

	openVarFile = func(path string, flags int, perm os.FileMode) (VarFile, error) {
		f, err := fn(path, flags, perm)
		if err == Defer {
			return orig(path, flags, perm)
		}
		return f, err
	}

	return func() {
		openVarFile = orig
	}
}

func MockUnixStatfs(fn func(string, *unix.Statfs_t) error) (restore func()) {
	orig := unixStatfs
	unixStatfs = fn
	return func() {
		unixStatfs = orig
	}
}
