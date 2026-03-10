// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"reflect"
	"syscall"

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
		// XXX: The type of Statfs_t.Type differs widely across architectures
		// but the constant unix.EFIVARFS_MAGIC is always a uint so we cannot
		// just assign and call it a day.
		val := reflect.ValueOf(&st.Type).Elem()
		if val.CanInt() {
			val.SetInt(int64(unix.EFIVARFS_MAGIC))
		} else {
			val.SetUint(uint64(unix.EFIVARFS_MAGIC))
		}

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
		val := reflect.ValueOf(&st.Type).Elem()
		if val.CanInt() {
			val.SetInt(int64(unix.SYSFS_MAGIC))
		} else {
			val.SetUint(uint64(unix.SYSFS_MAGIC))
		}
		return nil
	})
	defer restore()

	c.Check(probeEfivarfs(), Equals, false)
}
