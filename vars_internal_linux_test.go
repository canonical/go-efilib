// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

type varsLinuxSuite struct{}

var _ = Suite(&varsLinuxSuite{})

func (s *varsLinuxSuite) TestProbeEfivarfs(c *C) {
	restore := MockUnixStatfs(func(path string, st *unix.Statfs_t) error {
		if path != "/sys/firmware/efi/efivars" {
			return syscall.ENOENT
		}

		if err := unix.Statfs("testdata", st); err != nil {
			return err
		}
		*(*uint)(unsafe.Pointer(&st.Type)) = uint(unix.EFIVARFS_MAGIC)
		return nil
	})
	defer restore()

	c.Check(probeEfivarfs(), Equals, true)
}

func (s *varsLinuxSuite) TestProbeEfivarfsNOENT(c *C) {
	restore := MockUnixStatfs(func(path string, st *unix.Statfs_t) error {
		return syscall.ENOENT
	})
	defer restore()

	c.Check(probeEfivarfs(), Equals, false)
}

func (s *varsLinuxSuite) TestProbeEfivarfsBadFS(c *C) {
	restore := MockUnixStatfs(func(path string, st *unix.Statfs_t) error {
		unix.Statfs("testdata", st)
		st.Type = unix.SYSFS_MAGIC
		return nil
	})
	defer restore()

	c.Check(probeEfivarfs(), Equals, false)
}
