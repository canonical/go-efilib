// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type TarFileMixin struct{}

func (m *TarFileMixin) UnpackTar(c *C, path string) string {
	dir := c.MkDir()

	cmd := exec.Command("tar", "-xaf", path, "-C", dir)
	c.Assert(cmd.Run(), IsNil)

	return dir
}

func MockDevicePathNodeHandlers(handlers map[interfaceType][]registeredDpHandler) (restore func()) {
	orig := devicePathNodeHandlers
	devicePathNodeHandlers = handlers
	return func() {
		devicePathNodeHandlers = orig
	}
}

func MockMountsPath(path string) (restore func()) {
	orig := mountsPath
	mountsPath = path
	return func() {
		mountsPath = orig
	}
}

func MockOsOpen(fn func(string) (*os.File, error)) (restore func()) {
	orig := osOpen
	osOpen = fn
	return func() {
		osOpen = orig
	}
}

func MockOsStat(fn func(string) (os.FileInfo, error)) (restore func()) {
	orig := osStat
	osStat = fn
	return func() {
		osStat = orig
	}
}

func MockSysfsPath(path string) (restore func()) {
	orig := sysfsPath
	sysfsPath = path
	return func() {
		sysfsPath = orig
	}
}

func MockUnixStat(fn func(string, *unix.Stat_t) error) (restore func()) {
	orig := unixStat
	unixStat = fn
	return func() {
		unixStat = orig
	}
}
