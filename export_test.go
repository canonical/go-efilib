// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"os"

	"golang.org/x/sys/unix"
)

type VarReadWriteCloser = varReadWriteCloser

func MockOpenVarFile(fn func(string, int, os.FileMode) (VarReadWriteCloser, error)) (restore func()) {
	orig := openVarFile
	openVarFile = fn
	return func() {
		openVarFile = orig
	}
}

func MockVarsStatfs(fn func(string, *unix.Statfs_t) error) (restore func()) {
	orig := varsStatfs
	varsStatfs = fn
	return func() {
		varsStatfs = orig
	}
}
