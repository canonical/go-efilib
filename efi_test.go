// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

func DecodeHexString(c *C, s string) []byte {
	x, err := hex.DecodeString(s)
	c.Assert(err, IsNil)
	return x
}

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

func MockVarsBackend(backend VarsBackend) (restore func()) {
	orig := vars
	vars = backend
	return func() {
		vars = orig
	}
}

func ReadFile(c *C, path string) []byte {
	data, err := ioutil.ReadFile(path)
	c.Assert(err, IsNil)
	return data
}
