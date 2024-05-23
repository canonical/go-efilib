// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	efi "github.com/canonical/go-efilib"
	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

type FilepathMockMixin struct{}

func (s *FilepathMockMixin) MockFilepathEvalSymlinks(m map[string]string) (restore func()) {
	orig := filepathEvalSymlinks
	filepathEvalSymlinks = func(path string) (string, error) {
		p, ok := m[path]
		switch {
		case ok && p == "":
			return "", &os.PathError{Op: "lstat", Path: filepath.Dir(path), Err: syscall.EEXIST}
		case ok:
			return p, nil
		default:
			return path, nil
		}
	}

	return func() {
		filepathEvalSymlinks = orig
	}
}

func (s *FilepathMockMixin) MockUnixStat(m map[string]unix.Stat_t) (restore func()) {
	orig := unixStat
	unixStat = func(path string, st *unix.Stat_t) error {
		if s, ok := m[path]; ok {
			*st = s
			return nil
		}
		return orig(path, st)
	}

	return func() {
		unixStat = orig
	}
}

type filepathSuite struct {
	FilepathMockMixin
	TarFileMixin
}

var _ = Suite(&filepathSuite{})

func (s *filepathSuite) TestScanBlockDeviceMounts(c *C) {
	restore := MockMountsPath("testdata/mounts-nvme")
	defer restore()

	mounts, err := scanBlockDeviceMounts()
	c.Check(err, IsNil)
	c.Check(mounts, DeepEquals, []*mountPoint{
		{dev: unix.Mkdev(253, 1), root: "/", mountDir: "/", mountSource: "/dev/mapper/vgubuntu-root"},
		{dev: unix.Mkdev(259, 2), root: "/", mountDir: "/boot", mountSource: "/dev/nvme0n1p2"},
		{dev: unix.Mkdev(259, 1), root: "/", mountDir: "/boot/efi", mountSource: "/dev/nvme0n1p1"},
		{dev: unix.Mkdev(7, 1), root: "/", mountDir: "/snap/core/11993", mountSource: "/dev/loop1"},
		{dev: unix.Mkdev(7, 2), root: "/", mountDir: "/snap/gnome-3-38-2004/87", mountSource: "/dev/loop2"},
		{dev: unix.Mkdev(7, 3), root: "/", mountDir: "/snap/snap-store/558", mountSource: "/dev/loop3"},
		{dev: unix.Mkdev(7, 4), root: "/", mountDir: "/snap/gtk-common-themes/1519", mountSource: "/dev/loop4"},
		{dev: unix.Mkdev(259, 1), root: "/EFI", mountDir: "/efi", mountSource: "/dev/nvme0n1p1"}})
}

func (s *filepathSuite) TestGetFileMountPoint(c *C) {
	restore := s.MockFilepathEvalSymlinks(map[string]string{})
	defer restore()
	restore = MockMountsPath("testdata/mounts-nvme")
	defer restore()
	restore = s.MockUnixStat(map[string]unix.Stat_t{
		"/boot/efi/EFI/ubuntu/shimx64.efi": unix.Stat_t{Dev: unix.Mkdev(259, 1)},
	})
	defer restore()

	mount, err := getFileMountPoint("/boot/efi/EFI/ubuntu/shimx64.efi")
	c.Check(err, IsNil)
	c.Check(mount, DeepEquals, &mountPoint{dev: unix.Mkdev(259, 1), root: "/", mountDir: "/boot/efi", mountSource: "/dev/nvme0n1p1"})
}

func (s *filepathSuite) TestGetFileMountPointBindMount(c *C) {
	restore := s.MockFilepathEvalSymlinks(map[string]string{})
	defer restore()
	restore = MockMountsPath("testdata/mounts-nvme")
	defer restore()
	restore = s.MockUnixStat(map[string]unix.Stat_t{
		"/efi/ubuntu/shimx64.efi": unix.Stat_t{Dev: unix.Mkdev(259, 1)},
	})
	defer restore()

	mount, err := getFileMountPoint("/efi/ubuntu/shimx64.efi")
	c.Check(err, IsNil)
	c.Check(mount, DeepEquals, &mountPoint{dev: unix.Mkdev(259, 1), root: "/EFI", mountDir: "/efi", mountSource: "/dev/nvme0n1p1"})
}

func (s *filepathSuite) TestNewFilePath(c *C) {
	restore := s.MockFilepathEvalSymlinks(map[string]string{})
	defer restore()
	restore = MockMountsPath("testdata/mounts-nvme")
	defer restore()
	restore = s.MockUnixStat(map[string]unix.Stat_t{
		"/boot/efi/EFI/ubuntu/shimx64.efi": unix.Stat_t{Dev: unix.Mkdev(259, 1)},
	})
	defer restore()

	sysfs := filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys")
	restore = MockSysfsPath(sysfs)
	defer restore()

	path, err := newFilePath("/boot/efi/EFI/ubuntu/shimx64.efi")
	c.Check(err, IsNil)
	c.Check(path, DeepEquals, &filePath{
		dev: dev{
			sysfsPath: filepath.Join(sysfs, "devices/pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0/nvme0n1"),
			devPath:   "/dev/nvme0n1",
			part:      1},
		path: "/EFI/ubuntu/shimx64.efi"})
}

func (s *filepathSuite) TestNewFilePathBindMount(c *C) {
	restore := s.MockFilepathEvalSymlinks(map[string]string{})
	defer restore()
	restore = MockMountsPath("testdata/mounts-nvme")
	defer restore()
	restore = s.MockUnixStat(map[string]unix.Stat_t{
		"/efi/ubuntu/shimx64.efi": unix.Stat_t{Dev: unix.Mkdev(259, 1)},
	})
	defer restore()

	sysfs := filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys")
	restore = MockSysfsPath(sysfs)
	defer restore()

	path, err := newFilePath("/efi/ubuntu/shimx64.efi")
	c.Check(err, IsNil)
	c.Check(path, DeepEquals, &filePath{
		dev: dev{
			sysfsPath: filepath.Join(sysfs, "devices/pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0/nvme0n1"),
			devPath:   "/dev/nvme0n1",
			part:      1},
		path: "/EFI/ubuntu/shimx64.efi"})
}

func (s *filepathSuite) TestNewFilePathSymlink(c *C) {
	restore := s.MockFilepathEvalSymlinks(map[string]string{"/foo/bar/shimx64.efi": "/efi/ubuntu/shimx64.efi"})
	defer restore()
	restore = MockMountsPath("testdata/mounts-nvme")
	defer restore()
	restore = s.MockUnixStat(map[string]unix.Stat_t{
		"/efi/ubuntu/shimx64.efi": unix.Stat_t{Dev: unix.Mkdev(259, 1)},
	})
	defer restore()

	sysfs := filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys")
	restore = MockSysfsPath(sysfs)
	defer restore()

	path, err := newFilePath("/foo/bar/shimx64.efi")
	c.Check(err, IsNil)
	c.Check(path, DeepEquals, &filePath{
		dev: dev{
			sysfsPath: filepath.Join(sysfs, "devices/pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0/nvme0n1"),
			devPath:   "/dev/nvme0n1",
			part:      1},
		path: "/EFI/ubuntu/shimx64.efi"})
}

func (s *filepathSuite) TestNewFilePathNotPartitioned(c *C) {
	restore := s.MockFilepathEvalSymlinks(map[string]string{})
	defer restore()
	restore = MockMountsPath("testdata/mounts-nvme")
	defer restore()
	restore = s.MockUnixStat(map[string]unix.Stat_t{
		"/snap/core/11993/bin/ls": unix.Stat_t{Dev: unix.Mkdev(7, 1)},
	})
	defer restore()

	sysfs := filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys")
	restore = MockSysfsPath(sysfs)
	defer restore()

	path, err := newFilePath("/snap/core/11993/bin/ls")
	c.Check(err, IsNil)
	c.Check(path, DeepEquals, &filePath{
		dev: dev{
			sysfsPath: filepath.Join(sysfs, "devices/virtual/block/loop1"),
			devPath:   "/dev/loop1",
			part:      0},
		path: "/bin/ls"})
}

func (s *filepathSuite) TestNewDevicePathBuilder(c *C) {
	sysfs := filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys")
	restore := MockSysfsPath(sysfs)
	defer restore()

	dev := &dev{sysfsPath: filepath.Join(sysfs, "devices/pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0/nvme0n1")}
	builder, err := newDevicePathBuilder(dev)
	c.Check(err, IsNil)
	c.Check(builder, DeepEquals, &devicePathBuilder{
		devicePathBuilderState: devicePathBuilderState{
			remaining: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}})
}

func (s *filepathSuite) TestDevicePathBuilderStateSysfsComponentsRemaining(c *C) {
	state := &devicePathBuilderState{remaining: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}
	c.Check(state.SysfsComponentsRemaining(), Equals, 6)

	state.remaining = []string{"0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}
	c.Check(state.SysfsComponentsRemaining(), Equals, 4)
}

func (s *filepathSuite) TestDevicePathBuilderStatePeekUnhandledSysfsComponents(c *C) {
	state := &devicePathBuilderState{remaining: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}
	c.Check(state.PeekUnhandledSysfsComponents(1), Equals, "pci0000:00")
	c.Check(state.PeekUnhandledSysfsComponents(2), Equals, "pci0000:00/0000:00:1d.0")
	c.Check(state.PeekUnhandledSysfsComponents(-1), Equals, "pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0/nvme0n1")
}

func (s *filepathSuite) TestDevicePathBuilderStateSysfsPath(c *C) {
	state := &devicePathBuilderState{processed: []string{"pci0000:00"}}
	c.Check(state.SysfsPath(), Equals, "/sys/devices/pci0000:00")
	state.processed = append(state.processed, "0000:00:1d.0")
	c.Check(state.SysfsPath(), Equals, "/sys/devices/pci0000:00/0000:00:1d.0")
}

func (s *filepathSuite) TestDevicePathBuilderStateAdvanceSysfsPath(c *C) {
	state := &devicePathBuilderState{remaining: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}

	state.AdvanceSysfsPath(1)
	c.Check(state.processed, DeepEquals, []string{"pci0000:00"})
	c.Check(state.remaining, DeepEquals, []string{"0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"})

	state.AdvanceSysfsPath(2)
	c.Check(state.processed, DeepEquals, []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0"})
	c.Check(state.remaining, DeepEquals, []string{"nvme", "nvme0", "nvme0n1"})
}

func (s *filepathSuite) TestDevicePathBuilderDone(c *C) {
	builder := &devicePathBuilder{
		devicePathBuilderState: devicePathBuilderState{remaining: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}}
	c.Check(builder.done(), Equals, false)

	builder.remaining = []string{}
	c.Check(builder.done(), Equals, true)
}

func (s *filepathSuite) TestDevicePathBuilderProcessNextComponent(c *C) {
	builder := &devicePathBuilder{
		devicePathBuilderState: devicePathBuilderState{
			remaining: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}}

	hid, _ := efi.NewEISAID("PNP", 0x0a03)

	var skipped int
	skipHandler := func(state *devicePathBuilderState) error {
		skipped += 1
		state.AdvanceSysfsPath(2)
		return errSkipDevicePathNodeHandler
	}
	realHandler := func(state *devicePathBuilderState) error {
		state.Interface = interfaceTypePCI
		state.Path = append(state.Path, &efi.ACPIDevicePathNode{HID: hid})
		state.AdvanceSysfsPath(1)
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

	c.Check(builder.ProcessNextComponent(), IsNil)
	c.Check(skipped, Equals, 2)
	c.Check(builder.Interface, Equals, interfaceTypePCI)
	c.Check(builder.Path, DeepEquals, efi.DevicePath{&efi.ACPIDevicePathNode{HID: hid}})
	c.Check(builder.remaining, DeepEquals, []string{"0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"})
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00"})
}

func (s *filepathSuite) TestDevicePathBuilderProcessNextComponentUnhandled(c *C) {
	hid, _ := efi.NewEISAID("PNP", 0x0a03)

	builder := &devicePathBuilder{
		devicePathBuilderState: devicePathBuilderState{
			Interface: interfaceTypePCI,
			Path:      efi.DevicePath{&efi.ACPIDevicePathNode{HID: hid}},
			processed: []string{"pci0000:00"},
			remaining: []string{"0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}}

	var skipped int
	skipHandler := func(_ *devicePathBuilderState) error {
		skipped += 1
		return errSkipDevicePathNodeHandler
	}
	restore := MockDevicePathNodeHandlers(map[interfaceType][]registeredDpHandler{
		interfaceTypeUnknown: []registeredDpHandler{
			{name: "acpi-skip", fn: skipHandler}},
		interfaceTypePCI: []registeredDpHandler{
			{name: "skip1", fn: skipHandler},
			{name: "skip2", fn: skipHandler}}})
	defer restore()

	c.Check(func() { builder.ProcessNextComponent() }, PanicMatches, "all handlers skipped handling interface type 1")
	c.Check(skipped, Equals, 2)
}

func (s *filepathSuite) TestDevicePathBuilderProcessNextComponentUnhandledRoot(c *C) {
	builder := &devicePathBuilder{
		devicePathBuilderState: devicePathBuilderState{
			Interface: interfaceTypeUnknown,
			remaining: []string{"pci0000:00", "0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}}

	var skipped int
	skipHandler := func(state *devicePathBuilderState) error {
		skipped += 1
		state.Interface = interfaceTypePCI
		return errSkipDevicePathNodeHandler
	}
	restore := MockDevicePathNodeHandlers(map[interfaceType][]registeredDpHandler{
		interfaceTypeUnknown: []registeredDpHandler{
			{name: "acpi-skip", fn: skipHandler}},
		interfaceTypePCI: []registeredDpHandler{
			{name: "skip1", fn: skipHandler},
			{name: "skip2", fn: skipHandler}}})
	defer restore()

	c.Check(builder.ProcessNextComponent(), ErrorMatches, "unsupported device: unhandled root node")
	c.Check(skipped, Equals, 1)
	c.Check(builder.Interface, Equals, interfaceTypeUnknown)
}

func (s *filepathSuite) TestDevicePathBuilderProcessNextComponentError(c *C) {
	hid, _ := efi.NewEISAID("PNP", 0x0a03)

	builder := &devicePathBuilder{
		devicePathBuilderState: devicePathBuilderState{
			Interface: interfaceTypePCI,
			Path:      efi.DevicePath{&efi.ACPIDevicePathNode{HID: hid}},
			processed: []string{"pci0000:00"},
			remaining: []string{"0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"}}}

	handler := func(state *devicePathBuilderState) error {
		state.AdvanceSysfsPath(1)
		return errors.New("error")
	}
	restore := MockDevicePathNodeHandlers(map[interfaceType][]registeredDpHandler{
		interfaceTypePCI: []registeredDpHandler{
			{name: "pci", fn: handler}}})
	defer restore()

	c.Check(builder.ProcessNextComponent(), ErrorMatches, "\\[handler pci\\]: error")
	c.Check(builder.remaining, DeepEquals, []string{"0000:00:1d.0", "0000:3d:00.0", "nvme", "nvme0", "nvme0n1"})
	c.Check(builder.processed, DeepEquals, []string{"pci0000:00"})
}
