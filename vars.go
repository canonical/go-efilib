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
	"golang.org/x/xerrors"
)

var (
	varsRoot = "/"
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

func varsPath() string {
	return filepath.Join(varsRoot, "sys/firmware/efi/efivars")
}

func isAvailable() (bool, error) {
	var st unix.Statfs_t
	if err := unixStatfs(varsPath(), &st); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if st.Type != unix.EFIVARFS_MAGIC {
		return false, nil
	}
	return true, nil
}

// OpenVar opens the EFI variable with the specified name and GUID for reading. On success, it returns the variable's attributes,
// and a io.ReadCloser for reading the variable value.
func OpenVar(name string, guid GUID) (io.ReadCloser, VariableAttributes, error) {
	if available, err := isAvailable(); err != nil {
		return nil, 0, err
	} else if !available {
		return nil, 0, ErrVarsUnavailable
	}

	path := filepath.Join(varsPath(), fmt.Sprintf("%s-%s", name, guid))
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrVariableNotFound
		}
		return nil, 0, err
	}

	var attrs VariableAttributes
	if err := binary.Read(f, binary.LittleEndian, &attrs); err != nil {
		f.Close()
		if err == io.EOF {
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
	if available, err := isAvailable(); err != nil {
		return err
	} else if !available {
		return ErrVarsUnavailable
	}

	path := filepath.Join(varsPath(), fmt.Sprintf("%s-%s", name, guid))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, attrs); err != nil {
		return err
	}
	if _, err := buf.Write(data); err != nil {
		return err
	}

	_, err = buf.WriteTo(f)
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
		return nil, nil, 0, xerrors.Errorf("cannot decode authentication descriptor: %w", err)
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
