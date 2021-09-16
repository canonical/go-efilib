// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux_test

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
	. "github.com/canonical/go-efilib/linux"
)

type filepathSuite struct {
	FilepathMockMixin
	TarFileMixin
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
	restoreMounts := MockMountsPath("testdata/mounts-nvme")
	defer restoreMounts()

	restoreOsStat := s.MockOsStat()
	defer restoreOsStat()

	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
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
	restoreMounts := MockMountsPath("testdata/mounts-nvme")
	defer restoreMounts()

	restoreOsOpen := s.mockOsOpen(map[string]string{"/dev/nvme0n1": "testdata/disk.img"})
	defer restoreOsOpen()

	restoreOsStat := s.MockOsStat()
	defer restoreOsStat()

	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
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

func (s *filepathSuite) TestNewFileDevicePathShortFormHDUnpartitioned(c *C) {
	restoreMounts := MockMountsPath("testdata/mounts-nvme")
	defer restoreMounts()

	restoreOsStat := s.MockOsStat()
	defer restoreOsStat()

	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	restoreUnixStat := s.MockUnixStat(
		[]MockMountPoint{{Dev: "/dev/loop1", Root: "/snap/core/11606"}},
		map[string]uint64{
			"/dev/loop1": unix.Mkdev(7, 1)},
		[]string{"/snap/core/11606/bin/ls"})
	defer restoreUnixStat()

	_, err := NewFileDevicePath("/snap/core/11606/bin/ls", ShortFormPathHD)
	c.Check(err, Equals, ErrNoDevicePath)
}

func (s *filepathSuite) TestNewFileDevicePathFullNVME(c *C) {
	restoreMounts := MockMountsPath("testdata/mounts-nvme")
	defer restoreMounts()

	restoreOsOpen := s.mockOsOpen(map[string]string{"/dev/nvme0n1": "testdata/disk.img"})
	defer restoreOsOpen()

	restoreOsStat := s.MockOsStat()
	defer restoreOsStat()

	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	restoreUnixStat := s.MockUnixStat(
		[]MockMountPoint{{Dev: "/dev/nvme0n1p1", Root: "/boot/efi"}},
		map[string]uint64{
			"/dev/nvme0n1":   unix.Mkdev(259, 0),
			"/dev/nvme0n1p1": unix.Mkdev(259, 1)},
		[]string{"/boot/efi/EFI/ubuntu/shimx64.efi"})
	defer restoreUnixStat()

	path, err := NewFileDevicePath("/boot/efi/EFI/ubuntu/shimx64.efi", FullPath)
	c.Check(err, IsNil)
	c.Check(path, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 0, Device: 0x1d},
		&efi.PCIDevicePathNode{Function: 0, Device: 0x0},
		&efi.NVMENamespaceDevicePathNode{NamespaceID: 1},
		&efi.HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  34,
			PartitionSize:   64,
			Signature:       efi.MakeGUID(0xc7a2907e, 0xd8c9, 0x4a41, 0x8b99, [...]uint8{0x3e, 0xf3, 0x24, 0x5f, 0xaf, 0x2a}),
			MBRType:         efi.GPT},
		efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")})
}

func (s *filepathSuite) TestNewFileDevicePathFullSATA(c *C) {
	restoreMounts := MockMountsPath("testdata/mounts-sata")
	defer restoreMounts()

	restoreOsOpen := s.mockOsOpen(map[string]string{"/dev/sda": "testdata/disk.img"})
	defer restoreOsOpen()

	restoreOsStat := s.MockOsStat()
	defer restoreOsStat()

	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	restoreUnixStat := s.MockUnixStat(
		[]MockMountPoint{{Dev: "/dev/sda1", Root: "/boot/efi"}},
		map[string]uint64{
			"/dev/sda":  unix.Mkdev(8, 0),
			"/dev/sda1": unix.Mkdev(8, 1)},
		[]string{"/boot/efi/EFI/ubuntu/shimx64.efi"})
	defer restoreUnixStat()

	path, err := NewFileDevicePath("/boot/efi/EFI/ubuntu/shimx64.efi", FullPath)
	c.Check(err, IsNil)
	c.Check(path, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{HID: 0x0a0341d0},
		&efi.PCIDevicePathNode{Function: 2, Device: 0x1f},
		&efi.SATADevicePathNode{
			HBAPortNumber:            0,
			PortMultiplierPortNumber: 0xffff},
		&efi.HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  34,
			PartitionSize:   64,
			Signature:       efi.MakeGUID(0xc7a2907e, 0xd8c9, 0x4a41, 0x8b99, [...]uint8{0x3e, 0xf3, 0x24, 0x5f, 0xaf, 0x2a}),
			MBRType:         efi.GPT},
		efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")})
}

func (s *filepathSuite) TestNewFileDevicePathFullNoDevicePath(c *C) {
	restoreMounts := MockMountsPath("testdata/mounts-nvme")
	defer restoreMounts()

	restoreOsStat := s.MockOsStat()
	defer restoreOsStat()

	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	restoreUnixStat := s.MockUnixStat(
		[]MockMountPoint{{Dev: "/dev/loop1", Root: "/snap/core/11606"}},
		map[string]uint64{
			"/dev/loop1": unix.Mkdev(7, 1)},
		[]string{"/snap/core/11606/bin/ls"})
	defer restoreUnixStat()

	_, err := NewFileDevicePath("/snap/core/11606/bin/ls", FullPath)
	c.Check(err, Equals, ErrNoDevicePath)
}
