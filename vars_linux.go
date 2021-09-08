// Copyright 2020-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"golang.org/x/sys/unix"
)

func efivarfsPath() string {
	return "/sys/firmware/efi/efivars"
}

type varFile interface {
	io.ReadWriteCloser
	Readdir(n int) ([]os.FileInfo, error)
	GetInodeFlags() (uint32, error)
	SetInodeFlags(flags uint32) error
}

func makeVarFileMutable(f varFile) (restore func() error, err error) {
	const immutableFlag = 0x00000010

	flags, err := f.GetInodeFlags()
	if err != nil {
		return nil, err
	}

	if flags&immutableFlag == 0 {
		// Nothing to do
		return func() error { return nil }, nil
	}

	if err := f.SetInodeFlags(flags &^ immutableFlag); err != nil {
		return nil, err
	}

	return func() error {
		return f.SetInodeFlags(flags)
	}, nil
}

type realVarFile struct {
	*os.File
}

func (f *realVarFile) GetInodeFlags() (uint32, error) {
	flags, err := unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return 0, &os.PathError{Op: "ioctl", Path: f.Name(), Err: err}
	}
	return flags, nil
}

func (f *realVarFile) SetInodeFlags(flags uint32) error {
	if err := unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(flags)); err != nil {
		return &os.PathError{Op: "ioctl", Path: f.Name(), Err: err}
	}
	return nil
}

func realOpenVarFile(path string, flags int, perm os.FileMode) (varFile, error) {
	f, err := os.OpenFile(path, flags, perm)
	if err != nil {
		return nil, err
	}
	return &realVarFile{f}, nil
}

var (
	guidLength = len("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")

	openVarFile = realOpenVarFile
	varsStatfs  = unix.Statfs
)

func probeEfivarfs() bool {
	var st unix.Statfs_t
	if err := varsStatfs(efivarfsPath(), &st); err != nil {
		return false
	}
	if st.Type != EFIVARFS_MAGIC {
		return false
	}
	return true
}

func maybeRetry(n int, fn func() (bool, error)) error {
	for i := 1; ; i++ {
		retry, err := fn()
		switch {
		case i > n:
			return err
		case !retry:
			return err
		case err == nil:
			return nil
		}
	}
}

func writeEfivarfsFile(path string, attrs VariableAttributes, data []byte) (retry bool, err error) {
	flags := os.O_WRONLY | os.O_CREATE
	if attrs&AttributeAppendWrite != 0 {
		flags |= os.O_APPEND
	}

	r, err := openVarFile(path, os.O_RDONLY, 0)
	switch {
	case os.IsNotExist(err):
	case os.IsPermission(err):
		return false, ErrVarPermission
	case err != nil:
		return false, err
	default:
		defer r.Close()

		restoreImmutable, err := makeVarFileMutable(r)
		switch {
		case os.IsPermission(err):
			return false, ErrVarPermission
		case err != nil:
			return false, err
		}
		defer restoreImmutable()
	}

	w, err := openVarFile(path, flags, 0644)
	switch {
	case os.IsPermission(err):
		pe, ok := err.(*os.PathError)
		if !ok {
			return false, err
		}
		if pe.Err == syscall.EACCES {
			// open will fail with EACCES if we lack the privileges
			// to write to the file or the parent directory in the
			// case where we need to create a new file. Don't retry
			// in this case.
			return false, ErrVarPermission
		}

		// open will fail with EPERM if the file exists but we can't
		// write to it because it is immutable. This might happen as a
		// result of a race with another process that might have been
		// writing to the variable or may have deleted and recreated
		// it, making the underlying inode immutable again. Retry in
		// this case.
		return true, ErrVarPermission
	case err != nil:
		return false, err
	}
	defer w.Close()

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, attrs)
	buf.Write(data)

	_, err = buf.WriteTo(w)
	return false, err
}

type efivarfsVarsBackend struct{}

func (v efivarfsVarsBackend) Get(name string, guid GUID) (VariableAttributes, []byte, error) {
	path := filepath.Join(efivarfsPath(), fmt.Sprintf("%s-%s", name, guid))
	f, err := openVarFile(path, os.O_RDONLY, 0)
	switch {
	case os.IsNotExist(err):
		return 0, nil, ErrVarNotExist
	case os.IsPermission(err):
		return 0, nil, ErrVarPermission
	case err != nil:
		return 0, nil, err
	}
	defer f.Close()

	var attrs VariableAttributes
	if err := binary.Read(f, binary.LittleEndian, &attrs); err != nil {
		if err == io.EOF {
			return 0, nil, ErrVarNotExist
		}
		return 0, nil, err
	}

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return 0, nil, err
	}
	return attrs, data, nil
}

func (v efivarfsVarsBackend) Set(name string, guid GUID, attrs VariableAttributes, data []byte) error {
	path := filepath.Join(efivarfsPath(), fmt.Sprintf("%s-%s", name, guid))
	return maybeRetry(4, func() (bool, error) { return writeEfivarfsFile(path, attrs, data) })
}

func (v efivarfsVarsBackend) List() ([]VarEntry, error) {
	f, err := openVarFile(efivarfsPath(), os.O_RDONLY, 0)
	switch {
	case os.IsNotExist(err):
		return nil, ErrVarsUnavailable
	case os.IsPermission(err):
		return nil, ErrVarPermission
	case err != nil:
		return nil, err
	}
	defer f.Close()

	dirents, err := f.Readdir(-1)
	if err != nil {
		return nil, err
	}

	var entries []VarEntry

	for _, dirent := range dirents {
		if !dirent.Mode().IsRegular() {
			// Skip non-regular files
			continue
		}
		if len(dirent.Name()) < guidLength+1 {
			// Skip files with a basename that isn't long enough
			// to contain a GUID and a hyphen
			continue
		}
		if dirent.Name()[len(dirent.Name())-guidLength-1] != '-' {
			// Skip files where the basename doesn't contain a
			// hyphen between the name and GUID
			continue
		}
		if dirent.Size() == 0 {
			// Skip files with zero size. These are variables that
			// have been deleted by writing an empty payload
			continue
		}

		name := dirent.Name()[:len(dirent.Name())-guidLength-1]
		guid, err := DecodeGUIDString(dirent.Name()[len(name)+1:])
		if err != nil {
			continue
		}

		entries = append(entries, VarEntry{Name: name, GUID: guid})
	}

	sort.Slice(entries, func(i, j int) bool {
		return fmt.Sprintf("%s-%v", entries[i].Name, entries[i].GUID) < fmt.Sprintf("%s-%v", entries[j].Name, entries[j].GUID)
	})
	return entries, nil
}

func init() {
	if !probeEfivarfs() {
		return
	}
	vars = efivarfsVarsBackend{}
}
