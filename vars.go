// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/canonical/go-efilib/internal/ioerr"
)

type VariableAttributes uint32

const (
	AttributeNonVolatile                       VariableAttributes = 1 << 0
	AttributeBootserviceAccess                 VariableAttributes = 1 << 1
	AttributeRuntimeAccess                     VariableAttributes = 1 << 2
	AttributeHardwareErrorRecord               VariableAttributes = 1 << 3
	AttributeAuthenticatedWriteAccess          VariableAttributes = 1 << 4
	AttributeTimeBasedAuthenticatedWriteAccess VariableAttributes = 1 << 5
	AttributeAppendWrite                       VariableAttributes = 1 << 6
	AttributeEnhancedAuthenticatedAccess       VariableAttributes = 1 << 7
)

var (
	ErrVarsUnavailable  = errors.New("no efivarfs mounted in the expected location")
	ErrVariableNotFound = errors.New("a variable with the supplied name could not be found")
)

type varFile interface {
	io.ReadWriteCloser
	MakeImmutable() (restore func() error, err error)
}

type realVarFile struct {
	*os.File
}

func (f *realVarFile) MakeImmutable() (restore func() error, err error) {
	const immutableFlag = 0x00000010

	flags, err := unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return nil, err
	}

	if flags&immutableFlag == 0 {
		// Nothing to do
		return func() error { return nil }, nil
	}

	if err := unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(flags&^immutableFlag)); err != nil {
		return nil, err
	}

	return func() error {
		return unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(flags))
	}, nil
}

func realOpenVarFile(path string, flags int, perm os.FileMode) (varFile, error) {
	f, err := os.OpenFile(path, flags, perm)
	if err != nil {
		return nil, err
	}
	return &realVarFile{f}, nil
}

var (
	openVarFile   = realOpenVarFile
	readVarDir    = os.ReadDir
	unlinkVarFile = os.Remove
	varsStatfs    = unix.Statfs
)

func varsPath() string {
	return "/sys/firmware/efi/efivars"
}

func checkAvailable() error {
	var st unix.Statfs_t
	if err := varsStatfs(varsPath(), &st); err != nil {
		if os.IsNotExist(err) {
			return ErrVarsUnavailable
		}
		return err
	}
	if st.Type != unix.EFIVARFS_MAGIC {
		return ErrVarsUnavailable
	}
	return nil
}

// OpenVar opens the EFI variable with the specified name and GUID for reading using
// efivarfs. On success, it returns the variable's attributes, and a io.ReadCloser
// for reading the variable value.
func OpenVar(name string, guid GUID) (io.ReadCloser, VariableAttributes, error) {
	if err := checkAvailable(); err != nil {
		return nil, 0, err
	}

	path := filepath.Join(varsPath(), fmt.Sprintf("%s-%s", name, guid))
	f, err := openVarFile(path, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrVariableNotFound
		}
		return nil, 0, err
	}

	var attrs VariableAttributes
	if err := binary.Read(f, binary.LittleEndian, &attrs); err != nil {
		f.Close()
		switch err {
		case io.EOF:
			return nil, 0, ErrVariableNotFound
		case io.ErrUnexpectedEOF:
			return nil, 0, errors.New("invalid variable format: too short")
		}
		return nil, 0, err
	}

	return f, attrs, nil
}

// ReadVar returns the value and attributes of the EFI variable with the specified
// name and GUID using efivarfs.
func ReadVar(name string, guid GUID) ([]byte, VariableAttributes, error) {
	f, attrs, err := OpenVar(name, guid)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	val, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, 0, err
	}

	return val, attrs, nil
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

func writeVarFile(path string, attrs VariableAttributes, data []byte) (retry bool, err error) {
	flags := os.O_WRONLY | os.O_CREATE
	if attrs&AttributeAppendWrite != 0 {
		flags |= os.O_APPEND
	}

	r, err := openVarFile(path, os.O_RDONLY, 0)
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return false, err
	default:
		defer r.Close()

		restoreImmutable, err := r.MakeImmutable()
		if err != nil {
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
			return false, err
		}

		// open will fail with EPERM if the file exists but we can't
		// write to it because it is immutable. This might happen as a
		// result of a race with another process that might have been
		// writing to the variable or may have deleted and recreated
		// it, making the underlying inode immutable again. Retry in
		// this case.
		return true, err
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

// WriteVar writes the supplied data value with the specified attributes to the
// EFI variable with the specified name and GUID using efivarfs.
//
// If the variable already exists, the specified attributes must match the existing
// attributes with the exception of AttributeAppendWrite.
//
// If the variable does not exist, it will be created.
//
// If the variable already exists and the corresponding file in efivarfs is
// immutable, this function will temporarily remove the immutable flag.
func WriteVar(name string, guid GUID, attrs VariableAttributes, data []byte) error {
	if err := checkAvailable(); err != nil {
		return err
	}

	path := filepath.Join(varsPath(), fmt.Sprintf("%s-%s", name, guid))
	return maybeRetry(4, func() (bool, error) { return writeVarFile(path, attrs, data) })
}

func deleteVarFile(path string) (retry bool, err error) {
	r, err := openVarFile(path, os.O_RDONLY, 0)
	switch {
	case os.IsNotExist(err):
		return false, ErrVariableNotFound
	case err != nil:
		return false, err
	}
	defer r.Close()

	_, err = r.MakeImmutable()
	if err != nil {
		return false, err
	}

	if err := unlinkVarFile(path); err != nil {
		if os.IsPermission(err) {
			pe, ok := err.(*os.PathError)
			if !ok {
				return false, err
			}
			if pe.Err == syscall.EACCES {
				// unlink will fail with EACCES if we lack the privileges
				// to write to the parent directory. Don't retry in this
				// case.
				return false, err
			}

			// unlink will fail with EPERM if the file is immutable.
			// This might happen due to a race with another process
			// which might have been writing to the variable or may
			// have deleted and recreated it and has since made the
			// underlying inode immutable again. Have another go in
			// this case.
			return true, err
		}
		return false, err
	}

	return false, nil
}

// DeleteVar deletes the variable with the specified GUID and name using
// efivarfs.
func DeleteVar(name string, guid GUID) error {
	if err := checkAvailable(); err != nil {
		return err
	}

	path := filepath.Join(varsPath(), fmt.Sprintf("%s-%s", name, guid))
	return maybeRetry(4, func() (bool, error) { return deleteVarFile(path) })
}

type VarEntry struct {
	Name string
	GUID GUID
}

var guidLength = len("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")

// ListVars returns a list of variables that can be accessed via efivarfs.
func ListVars() ([]VarEntry, error) {
	if err := checkAvailable(); err != nil {
		return nil, err
	}

	dirents, err := readVarDir(varsPath())
	if err != nil {
		return nil, err
	}

	var entries []VarEntry

	for _, dirent := range dirents {
		if !dirent.Type().IsRegular() {
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

		name := dirent.Name()[:len(dirent.Name())-guidLength-1]
		guid, err := DecodeGUIDString(dirent.Name()[len(name)+1:])
		if err != nil {
			continue
		}

		entries = append(entries, VarEntry{Name: name, GUID: guid})
	}

	return entries, nil
}

func OpenEnhancedAuthenticatedVar(name string, guid GUID) (io.ReadCloser, VariableAuthentication3Descriptor, VariableAttributes, error) {
	r, attrs, err := OpenVar(name, guid)
	if err != nil {
		return nil, nil, 0, err
	}
	defer r.Close()
	if attrs&AttributeEnhancedAuthenticatedAccess == 0 {
		return nil, nil, 0, errors.New("variable does not have the EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS attribute set")
	}

	auth, err := ReadEnhancedAuthenticationDescriptor(r)
	if err != nil {
		return nil, nil, 0, ioerr.EOFIsUnexpected("cannot decode authentication descriptor: %w", err)
	}

	return r, auth, attrs, nil
}

// ReadEnhancedAuthenticatedVar returns the value, attributes and authentication descriptor of the EFI variable with the specified
// name and GUID. This will return an error if the variable doesn't have the EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS attribute
// set.
func ReadEnhancedAuthenticatedVar(name string, guid GUID) ([]byte, VariableAuthentication3Descriptor, VariableAttributes, error) {
	r, auth, attrs, err := OpenEnhancedAuthenticatedVar(name, guid)
	if err != nil {
		return nil, nil, 0, err
	}
	defer r.Close()

	val, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, nil, 0, err
	}

	return val, auth, attrs, nil
}
