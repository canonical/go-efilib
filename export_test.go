// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type VarFile = varFile

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

func MockUnlinkVarFile(fn func(string) error) (restore func()) {
	orig := unlinkVarFile

	unlinkVarFile = func(path string) error {
		err := fn(path)
		if err == Defer {
			return orig(path)
		}
		return err
	}

	return func() {
		unlinkVarFile = orig
	}
}

func MockVarsStatfs(fn func(string, *unix.Statfs_t) error) (restore func()) {
	orig := varsStatfs
	varsStatfs = fn
	return func() {
		varsStatfs = orig
	}
}
