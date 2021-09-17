// Copyright 2020-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"errors"
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

type VarDescriptor struct {
	Name string
	GUID GUID
}

type varsBackend interface {
	Get(name string, guid GUID) (VariableAttributes, []byte, error)
	Set(name string, guid GUID, attrs VariableAttributes, data []byte) error
	List() ([]VarDescriptor, error)
}

type nullVarsBackend struct{}

func (v nullVarsBackend) Get(name string, guid GUID) (VariableAttributes, []byte, error) {
	return 0, nil, ErrVarsUnavailable
}

func (v nullVarsBackend) Set(name string, guid GUID, attrs VariableAttributes, data []byte) error {
	return ErrVarsUnavailable
}

func (v nullVarsBackend) List() ([]VarDescriptor, error) {
	return nil, ErrVarsUnavailable
}

var vars varsBackend = nullVarsBackend{}

// ReadVariable returns the value and attributes of the EFI variable with the specified
// name and GUID.
func ReadVariable(name string, guid GUID) ([]byte, VariableAttributes, error) {
	attrs, data, err := vars.Get(name, guid)
	return data, attrs, err
}

// WriteVariable writes the supplied data value with the specified attributes to the
// EFI variable with the specified name and GUID.
//
// If the variable already exists, the specified attributes must match the existing
// attributes with the exception of AttributeAppendWrite.
//
// If the variable does not exist, it will be created.
func WriteVariable(name string, guid GUID, attrs VariableAttributes, data []byte) error {
	return vars.Set(name, guid, attrs, data)
}

// ListVariables returns a list of variables that can be accessed.
func ListVariables() ([]VarDescriptor, error) {
	return vars.List()
}
