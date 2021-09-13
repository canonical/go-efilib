// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux_test

import (
	"os"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
	. "github.com/canonical/go-efilib/linux"
)

type filepathSuite struct {
	FilepathMockMixin
}

func (s *filepathSuite) mockOsOpen(m map[string]string) (restore func()) {
	return MockOsOpen(func(path string) (*os.File, error) {
		if p, ok := m[path]; ok {
			path = p
		}
		return os.Open(path)
	})
}

var _ = Suite(&filepathSuite{})

func (s *filepathSuite) TestNewFileDevicePathShortFormFile(c *C) {
	restoreMounts := MockMountsPath("testdata/mounts")
	defer restoreMounts()

	restoreOsStat := s.MockOsStat()
	defer restoreOsStat()

	restoreSysfs := MockSysfsPath("testdata/sys")
	defer restoreSysfs()

	restoreUnixStat := s.MockUnixStat(
		[]MockMountPoint{{Dev: "/dev/nvme0n1p1", Root: "/boot/efi"}},
		map[string]uint64{
			"/dev/nvme0n1":   unix.Mkdev(259, 0),
			"/dev/nvme0n1p1": unix.Mkdev(259, 1)},
		[]string{"/boot/efi/EFI/ubuntu/shimx64.efi"})
	defer restoreUnixStat()

	path, err := NewFileDevicePath("/boot/efi/EFI/ubuntu/shimx64.efi", ShortFormPathFile)
	c.Check(err, IsNil)
	c.Check(path, DeepEquals, efi.DevicePath{efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")})
}

func (s *filepathSuite) TestNewFileDevicePathShortFormHD(c *C) {
	restoreMounts := MockMountsPath("testdata/mounts")
	defer restoreMounts()

	restoreOsOpen := s.mockOsOpen(map[string]string{"/dev/nvme0n1": "testdata/disk.img"})
	defer restoreOsOpen()

	restoreOsStat := s.MockOsStat()
	defer restoreOsStat()

	restoreSysfs := MockSysfsPath("testdata/sys")
	defer restoreSysfs()

	restoreUnixStat := s.MockUnixStat(
		[]MockMountPoint{{Dev: "/dev/nvme0n1p1", Root: "/boot/efi"}},
		map[string]uint64{
			"/dev/nvme0n1":   unix.Mkdev(259, 0),
			"/dev/nvme0n1p1": unix.Mkdev(259, 1)},
		[]string{"/boot/efi/EFI/ubuntu/shimx64.efi"})
	defer restoreUnixStat()

	path, err := NewFileDevicePath("/boot/efi/EFI/ubuntu/shimx64.efi", ShortFormPathHD)
	c.Check(err, IsNil)
	c.Check(path, DeepEquals, efi.DevicePath{
		&efi.HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  34,
			PartitionSize:   64,
			Signature:       efi.MakeGUID(0xc7a2907e, 0xd8c9, 0x4a41, 0x8b99, [...]uint8{0x3e, 0xf3, 0x24, 0x5f, 0xaf, 0x2a}),
			MBRType:         efi.GPT},
		efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")})
}
