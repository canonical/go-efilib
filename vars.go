// Copyright 2020-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"bytes"
	"errors"
	"io/ioutil"

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
	ErrVarsUnavailable = errors.New("no variable backend is available")
	ErrVarNotExist     = errors.New("variable does not exist")
	ErrVarPermission   = errors.New("permission denied")
)

type VarEntry struct {
	Name string
	GUID GUID
}

type varsBackend interface {
	Get(name string, guid GUID) (VariableAttributes, []byte, error)
	Set(name string, guid GUID, attrs VariableAttributes, data []byte) error
	List() ([]VarEntry, error)
}

type nullVarsBackend struct{}

func (v nullVarsBackend) Get(name string, guid GUID) (VariableAttributes, []byte, error) {
	return 0, nil, ErrVarsUnavailable
}

func (v nullVarsBackend) Set(name string, guid GUID, attrs VariableAttributes, data []byte) error {
	return ErrVarsUnavailable
}

func (v nullVarsBackend) List() ([]VarEntry, error) {
	return nil, ErrVarsUnavailable
}

var vars varsBackend = nullVarsBackend{}

// ReadVar returns the value and attributes of the EFI variable with the specified
// name and GUID.
func ReadVar(name string, guid GUID) ([]byte, VariableAttributes, error) {
	attrs, data, err := vars.Get(name, guid)
	return data, attrs, err
}

// WriteVar writes the supplied data value with the specified attributes to the
// EFI variable with the specified name and GUID.
//
// If the variable already exists, the specified attributes must match the existing
// attributes with the exception of AttributeAppendWrite.
//
// If the variable does not exist, it will be created.
func WriteVar(name string, guid GUID, attrs VariableAttributes, data []byte) error {
	return vars.Set(name, guid, attrs, data)
}

// ListVars returns a list of variables that can be accessed.
func ListVars() ([]VarEntry, error) {
	return vars.List()
}

// ReadEnhancedAuthenticatedVar returns the value, attributes and authentication
// descriptor of the EFI variable with the specified name and GUID. This will
// return an error if the variable doesn't have the EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS
// attribute set.
func ReadEnhancedAuthenticatedVar(name string, guid GUID) ([]byte, VariableAuthentication3Descriptor, VariableAttributes, error) {
	data, attrs, err := ReadVar(name, guid)
	if err != nil {
		return nil, nil, 0, err
	}
	if attrs&AttributeEnhancedAuthenticatedAccess == 0 {
		return nil, nil, 0, errors.New("variable does not have the EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS attribute set")
	}

	r := bytes.NewReader(data)
	auth, err := ReadEnhancedAuthenticationDescriptor(r)
	if err != nil {
		return nil, nil, 0, ioerr.EOFIsUnexpected("cannot decode authentication descriptor: %w", err)
	}

	data, _ = ioutil.ReadAll(r)
	return data, auth, attrs, nil
}
