// Copyright 2020-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"context"
	"errors"

	"github.com/canonical/go-efilib/internal/uefi"
)

type VariableAttributes uint32

const (
	AttributeNonVolatile                       VariableAttributes = uefi.EFI_VARIABLE_NON_VOLATILE
	AttributeBootserviceAccess                 VariableAttributes = uefi.EFI_VARIABLE_BOOTSERVICE_ACCESS
	AttributeRuntimeAccess                     VariableAttributes = uefi.EFI_VARIABLE_RUNTIME_ACCESS
	AttributeHardwareErrorRecord               VariableAttributes = uefi.EFI_VARIABLE_HARDWARE_ERROR_RECORD
	AttributeAuthenticatedWriteAccess          VariableAttributes = uefi.EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
	AttributeTimeBasedAuthenticatedWriteAccess VariableAttributes = uefi.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
	AttributeAppendWrite                       VariableAttributes = uefi.EFI_VARIABLE_APPEND_WRITE
	AttributeEnhancedAuthenticatedAccess       VariableAttributes = uefi.EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS
)

var (
	ErrVarsUnavailable = errors.New("no variable backend is available")
	ErrVarNotExist     = errors.New("variable does not exist")
	ErrVarPermission   = errors.New("permission denied")
)

// VariableDescriptor represents the identity of a variable.
type VariableDescriptor struct {
	Name string
	GUID GUID
}

// VarsBackendKey is used to identify the [VarsBackend] on a [context.Context].
type VarsBackendKey struct{}

// VarsBackend is used by the [ReadVariable], [WriteVariable] and [ListVariables]
// functions, and indirectly by other functions in this package to abstract access
// to a specific backend. A default backend is initialized at process initialization
// and is available via [DefaultVarContext].
type VarsBackend interface {
	Get(name string, guid GUID) (VariableAttributes, []byte, error)
	Set(name string, guid GUID, attrs VariableAttributes, data []byte) error
	List() ([]VariableDescriptor, error)
}

func getVarsBackend(ctx context.Context) VarsBackend {
	value := ctx.Value(VarsBackendKey{})
	if value == nil {
		return nullVarsBackend{}
	}
	return value.(VarsBackend)
}

type nullVarsBackend struct{}

func (v nullVarsBackend) Get(name string, guid GUID) (VariableAttributes, []byte, error) {
	return 0, nil, ErrVarsUnavailable
}

func (v nullVarsBackend) Set(name string, guid GUID, attrs VariableAttributes, data []byte) error {
	return ErrVarsUnavailable
}

func (v nullVarsBackend) List() ([]VariableDescriptor, error) {
	return nil, ErrVarsUnavailable
}

var nullContext = context.WithValue(context.Background(), VarsBackendKey{}, nullVarsBackend{})

// ReadVariable returns the value and attributes of the EFI variable with the specified
// name and GUID. In general, [DefaultVarContext] should be supplied to this.
func ReadVariable(ctx context.Context, name string, guid GUID) ([]byte, VariableAttributes, error) {
	attrs, data, err := getVarsBackend(ctx).Get(name, guid)
	return data, attrs, err
}

// WriteVariable writes the supplied data value with the specified attributes to the
// EFI variable with the specified name and GUID. In general, [DefaultVarContext] should
// be supplied to this.
//
// If the variable already exists, the specified attributes must match the existing
// attributes with the exception of AttributeAppendWrite.
//
// If the variable does not exist, it will be created.
func WriteVariable(ctx context.Context, name string, guid GUID, attrs VariableAttributes, data []byte) error {
	return getVarsBackend(ctx).Set(name, guid, attrs, data)
}

// ListVariables returns a list of variables that can be accessed. In general,
// [DefaultVarContext] should be supplied to this.
func ListVariables(ctx context.Context) ([]VariableDescriptor, error) {
	return getVarsBackend(ctx).List()
}

// DefaultVarContext should be passed to functions that interact with EFI
// variables in order to use the default system backend for accessing
// EFI variables.
var DefaultVarContext = newDefaultVarContext()
