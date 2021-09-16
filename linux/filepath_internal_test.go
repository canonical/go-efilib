// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
)

type FilepathMockMixin struct{}

type mockDeviceInfo struct {
	mode os.FileMode
}

func (i *mockDeviceInfo) Name() string       { return "" }
func (i *mockDeviceInfo) Size() int64        { return 0 }
func (i *mockDeviceInfo) Mode() os.FileMode  { return i.mode }
func (i *mockDeviceInfo) ModTime() time.Time { return time.Time{} }
func (i *mockDeviceInfo) IsDir() bool        { return false }
func (i *mockDeviceInfo) Sys() interface{}   { return nil }

func (s *FilepathMockMixin) MockOsStat() (restore func()) {
	return MockOsStat(func(path string) (os.FileInfo, error) {
		if !filepath.IsAbs(path) {
			return nil, &os.PathError{Op: "stat", Path: path, Err: syscall.ENOENT}
		}
		if !strings.HasPrefix(path, "/dev") {
			return &mockDeviceInfo{0600}, nil
		}
		return &mockDeviceInfo{os.ModeDevice | 0600}, nil
	})
}

type MockMountPoint struct {
	Dev  string
	Root string
}

func (s *FilepathMockMixin) MockUnixStat(mounts []MockMountPoint, devs map[string]uint64, paths []string) (restore func()) {
	return MockUnixStat(func(path string, st *unix.Stat_t) error {
		path = filepath.Clean(path)

		if devNum, ok := devs[path]; ok {
			st.Rdev = devNum
			return nil
		}

		if strings.HasPrefix(path, "/dev") {
			return nil
		}

		var found bool
		for _, p := range paths {
			if p == path {
				found = true
				break
			}
		}
		if !found {
			return syscall.ENOENT
		}

		var chosen *MockMountPoint
		for _, mount := range mounts {
			if strings.HasPrefix(path, mount.Root) && (chosen == nil || len(mount.Root) > len(chosen.Root)) {
				chosen = &mount
			}
		}
		if chosen != nil {
			if devNum, ok := devs[chosen.Dev]; ok {
				st.Dev = devNum
			}
		}

		return nil
	})
}

type filepathSuite struct {
	FilepathMockMixin
	TarFileMixin
}

var _ = Suite(&filepathSuite{})

func (s *filepathSuite) TestScanBlockDeviceMounts(c *C) {
	restoreMounts := MockMountsPath("testdata/mounts-nvme")
	defer restoreMounts()
	restoreStat := s.MockOsStat()
	defer restoreStat()

	mounts, err := scanBlockDeviceMounts()
	c.Check(err, IsNil)
	c.Check(mounts, DeepEquals, []mountPoint{
		{"/dev/mapper/vgubuntu-root", "/"},
		{"/dev/nvme0n1p2", "/boot"},
		{"/dev/nvme0n1p1", "/boot/efi"},
		{"/dev/loop1", "/snap/core/11606"},
		{"/dev/loop2", "/snap/gnome-3-34-1804/72"},
		{"/dev/loop3", "/snap/gtk-common-themes/1515"},
		{"/dev/loop4", "/snap/snap-store/547"}})
}

func (s *filepathSuite) TestGetFileMockMountPoint(c *C) {
	restoreMounts := MockMountsPath("testdata/mounts-nvme")
	defer restoreMounts()

	restoreOsStat := s.MockOsStat()
	defer restoreOsStat()

	restoreUnixStat := s.MockUnixStat(
		[]MockMountPoint{{Dev: "/dev/nvme0n1p1", Root: "/boot/efi"}},
		map[string]uint64{"/dev/nvme0n1p1": unix.Mkdev(259, 1)},
		[]string{"/boot/efi/EFI/ubuntu/shimx64.efi"})
	defer restoreUnixStat()

	mount, err := getFileMountPoint("/boot/efi/EFI/ubuntu/shimx64.efi")
	c.Check(err, IsNil)
	c.Check(mount, DeepEquals, &mountPoint{"/dev/nvme0n1p1", "/boot/efi"})
}

func (s *filepathSuite) TestNewFilePath(c *C) {
	restoreMounts := MockMountsPath("testdata/mounts-nvme")
	defer restoreMounts()

	restoreOsStat := s.MockOsStat()
	defer restoreOsStat()

	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	restoreUnixStat := s.MockUnixStat(
		[]MockMountPoint{{Dev: "/dev/nvme0n1p1", Root: "/boot/efi"}},
		map[string]uint64{"/dev/nvme0n1p1": unix.Mkdev(259, 1)},
		[]string{"/boot/efi/EFI/ubuntu/shimx64.efi"})
	defer restoreUnixStat()

	path, err := newFilePath("/boot/efi/EFI/ubuntu/shimx64.efi")
	c.Check(err, IsNil)
	c.Check(path, DeepEquals, &filePath{
		dev: dev{
			node: "/dev/nvme0n1",
			part: 1},
		path: "EFI/ubuntu/shimx64.efi"})
}

func (s *filepathSuite) TestNewFilePathNotPartitioned(c *C) {
	restoreMounts := MockMountsPath("testdata/mounts-nvme")
	defer restoreMounts()

	restoreOsStat := s.MockOsStat()
	defer restoreOsStat()

	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	restoreUnixStat := s.MockUnixStat(
		[]MockMountPoint{{Dev: "/dev/loop1", Root: "/snap/core/11606"}},
		map[string]uint64{"/dev/loop1": unix.Mkdev(7, 1)},
		[]string{"/snap/core/11606/bin/ls"})
	defer restoreUnixStat()

	path, err := newFilePath("/snap/core/11606/bin/ls")
	c.Check(err, IsNil)
	c.Check(path, DeepEquals, &filePath{
		dev: dev{
			node: "/dev/loop1",
			part: 0},
		path: "bin/ls"})
}

func (s *filepathSuite) TestDevSysfsPath(c *C) {
	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	restoreUnixStat := s.MockUnixStat(nil, map[string]uint64{"/dev/nvme0n1": unix.Mkdev(259, 0)}, nil)
	defer restoreUnixStat()

	dev := &dev{node: "/dev/nvme0n1", part: 1}
	sysfsPath, err := dev.sysfsPath()
	c.Check(err, IsNil)
	c.Check(sysfsPath, Matches, `.*\/sys\/devices\/pci0000:00\/0000:00:1d\.0\/0000:3d:00\.0\/nvme\/nvme0\/nvme0n1$`)
}

func (s *filepathSuite) TestNewDevicePathBuilder(c *C) {
	restoreSysfs := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restoreSysfs()

	restoreUnixStat := s.MockUnixStat(nil, map[string]uint64{"/dev/nvme0n1": unix.Mkdev(259, 0)}, nil)
	defer restoreUnixStat()

	dev := &dev{node: "/dev/nvme0n1", part: 1}
	builder, err := newDevicePathBuilder(dev)
	c.Check(err, IsNil)
	c.Check(builder, DeepEquals, &devicePathBuilderImpl{
		dev:       dev,
		remaining: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}})
}

func (s *filepathSuite) TestDevicePathBuilderNumRemaining(c *C) {
	builder := &devicePathBuilderImpl{remaining: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}
	c.Check(builder.numRemaining(), Equals, 6)

	builder.remaining = []string{"0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}
	c.Check(builder.numRemaining(), Equals, 4)
}

func (s *filepathSuite) TestDevicePathBuilderNext(c *C) {
	builder := &devicePathBuilderImpl{remaining: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}
	c.Check(builder.next(1), Equals, "pci0000:00")
	c.Check(builder.next(2), Equals, "pci0000:00/0000:00:1d.0")
	c.Check(builder.next(-1), Equals, "pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0/nvme0n1")
}

func (s *filepathSuite) TestDevicePathBuilderAbsPath(c *C) {
	builder := &devicePathBuilderImpl{}
	c.Check(builder.absPath("pci0000:00"), Equals, "/sys/devices/pci0000:00")
	c.Check(builder.absPath("pci0000:00/0000:00:1d.0"), Equals, "/sys/devices/pci0000:00/0000:00:1d.0")

	builder.processed = []string{"pci0000:00"}
	c.Check(builder.absPath("0000:00:1d.0"), Equals, "/sys/devices/pci0000:00/0000:00:1d.0")
}

func (s *filepathSuite) TestDevicePathBuilderAdvance(c *C) {
	builder := &devicePathBuilderImpl{remaining: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}

	builder.advance(1)
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00"})
	c.Check(builder.remaining, DeepEquals, []string{"0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"})

	builder.advance(2)
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0"})
	c.Check(builder.remaining, DeepEquals, []string{"nvme", "nvme0", "nvme0n1"})
}

func (s *filepathSuite) TestDevicePathBuilderDone(c *C) {
	builder := &devicePathBuilderImpl{remaining: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}
	c.Check(builder.done(), Equals, false)

	builder.remaining = []string{}
	c.Check(builder.done(), Equals, true)
}

func (s *filepathSuite) TestDevicePathBuilderProcessNextComponent(c *C) {
	builder := &devicePathBuilderImpl{
		dev:       &dev{node: "/dev/nvme0n1", part: 1},
		remaining: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}

	hid, _ := efi.NewEISAID("PNP", 0x0a03)

	var skipped int
	skipHandler := func(_ devicePathBuilder, _ *dev) error {
		skipped += 1
		return errSkipDevicePathNodeHandler
	}
	realHandler := func(builder devicePathBuilder, dev *dev) error {
		dev.interfaceType = interfaceTypePCI
		dev.devPath = append(dev.devPath, &efi.ACPIDevicePathNode{HID: hid})
		dev.devPathIsFull = true
		builder.advance(1)
		return nil
	}
	restore := MockDevicePathNodeHandlers(map[interfaceType][]registeredDpHandler{
		interfaceTypeUnknown: []registeredDpHandler{
			{name: "skip1", fn: skipHandler},
			{name: "skip2", fn: skipHandler},
			{name: "acpi", fn: realHandler}},
		interfaceTypePCI: []registeredDpHandler{
			{name: "pci", fn: skipHandler}}})
	defer restore()

	c.Check(builder.processNextComponent(), IsNil)
	c.Check(skipped, Equals, 2)
	c.Check(builder.dev.interfaceType, Equals, interfaceType(interfaceTypePCI))
	c.Check(builder.dev.devPath, DeepEquals, efi.DevicePath{&efi.ACPIDevicePathNode{HID: hid}})
	c.Check(builder.dev.devPathIsFull, Equals, true)
	c.Check(builder.remaining, DeepEquals, []string{"0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"})
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00"})
}

func (s *filepathSuite) TestDevicePathBuilderProcessNextComponentUnhandled(c *C) {
	hid, _ := efi.NewEISAID("PNP", 0x0a03)

	builder := &devicePathBuilderImpl{
		dev: &dev{
			node: "/dev/nvme0n1", part: 1,
			interfaceType: interfaceTypePCI,
			devPath:       efi.DevicePath{&efi.ACPIDevicePathNode{HID: hid}},
			devPathIsFull: true},
		processed: []string{"pci0000:00"},
		remaining: []string{"0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}

	var skipped int
	skipHandler := func(builder devicePathBuilder, _ *dev) error {
		skipped += 1
		builder.advance(2)
		return errSkipDevicePathNodeHandler
	}
	restore := MockDevicePathNodeHandlers(map[interfaceType][]registeredDpHandler{
		interfaceTypeUnknown: []registeredDpHandler{
			{name: "acpi-skip", fn: skipHandler}},
		interfaceTypePCI: []registeredDpHandler{
			{name: "skip1", fn: skipHandler},
			{name: "skip2", fn: skipHandler}}})
	defer restore()

	c.Check(builder.processNextComponent(), IsNil)
	c.Check(skipped, Equals, 2)
	c.Check(builder.dev.interfaceType, Equals, interfaceType(interfaceTypeUnknown))
	c.Check(builder.dev.devPath, IsNil)
	c.Check(builder.dev.devPathIsFull, Equals, false)
	c.Check(builder.remaining, DeepEquals, []string{"0000:3d:00.0", "nvme", "nvme0", "nvme0n1"})
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00", "0000:00:1d.0"})
}
