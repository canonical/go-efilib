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

type varReadWriteCloser interface {
	io.ReadWriteCloser
	MakeImmutable() (restore func() error, err error)
}

type realVarReadWriteCloser struct {
	*os.File
}

func (rwc *realVarReadWriteCloser) MakeImmutable() (restore func() error, err error) {
	const immutableFlag = 0x00000010

	flags, err := unix.IoctlGetUint32(int(rwc.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return nil, err
	}

	if flags&immutableFlag == 0 {
		// Nothing to do
		return func() error { return nil }, nil
	}

	if err := unix.IoctlSetPointerInt(int(rwc.Fd()), unix.FS_IOC_SETFLAGS, int(flags&^immutableFlag)); err != nil {
		return nil, err
	}

	return func() error {
		return unix.IoctlSetPointerInt(int(rwc.Fd()), unix.FS_IOC_SETFLAGS, int(flags))
	}, nil
}

func realOpenVarFile(path string, flags int, perm os.FileMode) (varReadWriteCloser, error) {
	f, err := os.OpenFile(path, flags, perm)
	if err != nil {
		return nil, err
	}
	return &realVarReadWriteCloser{f}, nil
}

var (
	openVarFile = realOpenVarFile
	varsStatfs  = unix.Statfs
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

// OpenVar opens the EFI variable with the specified name and GUID for reading. On success, it returns the variable's attributes,
// and a io.ReadCloser for reading the variable value.
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

// ReadVar returns the value and attributes of the EFI variable with the specified name and GUID.
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

// WriteVar writes the supplied data value with the specified attributes to the EFI variable with the specified name and GUID.
func WriteVar(name string, guid GUID, attrs VariableAttributes, data []byte) error {
	if err := checkAvailable(); err != nil {
		return err
	}

	flags := os.O_WRONLY
	if attrs&AttributeAppendWrite != 0 {
		flags |= os.O_APPEND
	}

	path := filepath.Join(varsPath(), fmt.Sprintf("%s-%s", name, guid))
	r, err := openVarFile(path, os.O_RDONLY, 0)
	switch {
	case os.IsNotExist(err):
		flags |= (os.O_CREATE | os.O_EXCL)
	case err != nil:
		return err
	default:
		defer r.Close()

		restoreImmutable, err := r.MakeImmutable()
		if err != nil {
			return err
		}
		defer restoreImmutable()
	}

	// XXX: This is racy - another process could come along and delete
	// and recreate the variable. If that happens, this open might still
	// fail with EPERM.
	w, err := openVarFile(path, flags, 0644)
	if err != nil {
		return err
	}
	defer w.Close()

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, attrs); err != nil {
		return err
	}
	if _, err := buf.Write(data); err != nil {
		return err
	}

	_, err = buf.WriteTo(w)
	return err
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
