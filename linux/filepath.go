// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"

	"github.com/canonical/go-efilib"
)

// FileDevicePathMode specifies the mode for NewFileDevicePath
type FileDevicePathMode int

const (
	// FullPath indicates that only a full device path should be created.
	FullPath FileDevicePathMode = iota

	// ShortFormPathHD indicates that a short-form device path beginning
	// with a HD() node should be created.
	ShortFormPathHD

	// ShortFormPathFile indicates that a short-form device path consisting
	// of only the file path relative to the device should be created.
	ShortFormPathFile
)

// ErrDeviceUnpartitioned is returned from NewFileDevicePath if it is called
// with mode set to ShortFormPathHD but the file is not stored inside a partitioned
// device.
var ErrDeviceUnpartitioned = errors.New("device is not partitioned")

type interfaceType int

const (
	interfaceTypeUnknown = iota
	interfaceTypePCI
	interfaceTypeUSB
	interfaceTypeSCSI
	interfaceTypeIDE
	interfaceTypeSATA
	interfaceTypeNVME
)

var errSkipDevicePathNodeHandler = errors.New("")

type devicePathNodeHandler func(devicePathBuilder, *dev) error

type registeredDpHandler struct {
	name string
	fn   devicePathNodeHandler
}

var devicePathNodeHandlers = make(map[interfaceType][]registeredDpHandler)

func registerDevicePathNodeHandler(name string, fn devicePathNodeHandler, interfaces []interfaceType) {
	if len(interfaces) == 0 {
		interfaces = []interfaceType{interfaceTypeUnknown}
	}
	for _, i := range interfaces {
		devicePathNodeHandlers[i] = append(devicePathNodeHandlers[i], registeredDpHandler{name, fn})
	}
}

type devicePathBuilder interface {
	// numRemaining returns the number of remaining sysfs components
	// to process.
	numRemaining() int

	// next returns the next n sysfs components to process. -1 returns
	// all remaining components.
	next(n int) string

	// absPath turns the supplied sysfs path components into an
	// absolute path.
	absPath(path string) string

	// advance marks the specified number of sysfs components
	// as handled and advances to the next ones.
	advance(n int)
}

type devicePathBuilderImpl struct {
	dev *dev

	processed []string
	remaining []string
}

func (b *devicePathBuilderImpl) numRemaining() int {
	return len(b.remaining)
}

func (b *devicePathBuilderImpl) next(n int) string {
	if n < 0 {
		return filepath.Join(b.remaining...)
	}
	return filepath.Join(b.remaining[:n]...)
}

func (b *devicePathBuilderImpl) absPath(path string) string {
	return filepath.Join(sysfsPath, "devices", filepath.Join(b.processed...), path)
}

func (b *devicePathBuilderImpl) advance(n int) {
	b.processed = append(b.processed, b.remaining[:n]...)
	b.remaining = b.remaining[n:]
}

func (b *devicePathBuilderImpl) done() bool {
	return len(b.remaining) == 0
}

func (b *devicePathBuilderImpl) processNextComponent() error {
	for _, handler := range devicePathNodeHandlers[b.dev.interfaceType] {
		p := len(b.processed)
		r := b.remaining

		err := handler.fn(b, b.dev)
		if err == errSkipDevicePathNodeHandler {
			b.processed = b.processed[:p]
			b.remaining = r
			continue
		}
		if err != nil {
			return xerrors.Errorf("cannot execute handler %s: %w", handler.name, err)
		}
		return nil
	}

	b.dev.interfaceType = interfaceTypeUnknown
	b.dev.devPath = nil
	b.dev.devPathIsFull = false
	b.advance(1)
	return nil
}

func newDevicePathBuilder(dev *dev) (*devicePathBuilderImpl, error) {
	path, err := dev.sysfsPath()
	if err != nil {
		return nil, xerrors.Errorf("cannot determine sysfs device path: %w", err)
	}

	path, err = filepath.Rel(filepath.Join(sysfsPath, "devices"), path)
	if err != nil {
		return nil, err
	}

	return &devicePathBuilderImpl{
		dev:       dev,
		remaining: strings.Split(path, string(os.PathSeparator))}, nil
}

type mountPoint struct {
	dev  string
	root string
}

func scanBlockDeviceMounts() (mounts []mountPoint, err error) {
	f, err := os.Open(mountsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 6 {
			continue
		}
		dev := fields[0]
		root := fields[1]
		if !filepath.IsAbs(dev) {
			continue
		}

		info, err := osStat(dev)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeDevice == 0 {
			continue
		}
		mounts = append(mounts, mountPoint{dev, root})
	}
	if scanner.Err() != nil {
		return nil, xerrors.Errorf("cannot parse mount info: %w", err)
	}

	return mounts, nil
}

func getFileMountPoint(path string) (*mountPoint, error) {
	var fileSt unix.Stat_t
	if err := unixStat(path, &fileSt); err != nil {
		return nil, xerrors.Errorf("cannot obtain file information: %w", err)
	}

	mounts, err := scanBlockDeviceMounts()
	if err != nil {
		return nil, xerrors.Errorf("cannot obtain list of block device mounts: %w", err)
	}

	for _, mount := range mounts {
		var devSt unix.Stat_t
		if err := unixStat(mount.dev, &devSt); err != nil {
			return nil, xerrors.Errorf("cannot obtain information for block device %s: %w", mount.dev, err)
		}
		if devSt.Rdev == fileSt.Dev {
			return &mount, nil
		}
	}

	return nil, errors.New("not found")
}

type dev struct {
	node string
	part int

	interfaceType interfaceType

	devPath       efi.DevicePath
	devPathIsFull bool
}

func (d *dev) sysfsPath() (string, error) {
	var st unix.Stat_t
	if err := unixStat(d.node, &st); err != nil {
		return "", xerrors.Errorf("cannot obtain information for block device: %w", err)
	}

	return filepath.EvalSymlinks(filepath.Join(sysfsPath, "dev/block", fmt.Sprintf("%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev))))
}

type filePath struct {
	dev
	path string
}

func newFilePath(path string) (*filePath, error) {
	mount, err := getFileMountPoint(path)
	if err != nil {
		return nil, xerrors.Errorf("cannot obtain mount information for path: %w", err)
	}

	rel, err := filepath.Rel(mount.root, path)
	if err != nil {
		return nil, err
	}
	out := &filePath{path: rel}

	var st unix.Stat_t
	if err := unixStat(mount.dev, &st); err != nil {
		return nil, xerrors.Errorf("cannot obtain information for block device %s: %w", mount.dev, err)
	}

	childDev, err := filepath.EvalSymlinks(filepath.Join(sysfsPath, "dev/block", fmt.Sprintf("%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev))))
	if err != nil {
		return nil, err
	}

	parentDev := filepath.Dir(childDev)
	parentSubsystem, err := filepath.EvalSymlinks(filepath.Join(parentDev, "subsystem"))
	switch {
	case os.IsNotExist(err):
		// No subsystem link, could be the block/ directory
	case err != nil:
		return nil, err
	}

	if parentSubsystem != filepath.Join(sysfsPath, "class", "block") {
		// Parent device is not a block device
		out.dev.node = filepath.Join("/dev", filepath.Base(childDev))
	} else {
		// Parent device is a block device, so this is a partitioned
		// device.
		out.dev.node = filepath.Join("/dev", filepath.Base(parentDev))
		b, err := ioutil.ReadFile(filepath.Join(childDev, "partition"))
		if err != nil {
			return nil, xerrors.Errorf("cannot obtain partition number for %s: %w", mount.dev, err)
		}
		part, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, xerrors.Errorf("cannot determine partition number for %s: %w", mount.dev, err)
		}
		out.dev.part = part
	}

	return out, nil
}

// NewFileDevicePath creates an EFI device path from the supplied filepath usin the
// specified mode.
func NewFileDevicePath(path string, mode FileDevicePathMode) (out efi.DevicePath, err error) {
	fp, err := newFilePath(path)
	if err != nil {
		return nil, err
	}

	if mode == ShortFormPathHD && fp.part == 0 {
		return nil, errors.New("cannot specify ShortFormPathHD for a file on an unpartitioned device")
	}

	builder, err := newDevicePathBuilder(&fp.dev)
	if err != nil {
		return nil, err
	}

	if mode == FullPath {
		for !builder.done() {
			if err := builder.processNextComponent(); err != nil {
				return nil, xerrors.Errorf("cannot process %s: %w", builder.next(-1), err)
			}
		}

		if !fp.dev.devPathIsFull {
			return nil, errors.New("cannot construct full path")
		}
	}

	out = fp.dev.devPath

	if mode != ShortFormPathFile && fp.part > 0 {
		node, err := NewHardDriveDevicePathNodeFromDevice(fp.node, fp.part)
		if err != nil {
			return nil, xerrors.Errorf("cannot construct hard drive device path node: %w", err)
		}
		out = append(out, node)
	}

	out = append(out, efi.NewFilePathDevicePathNode(fp.path))
	return out, err
}
