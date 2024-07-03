// Copyright 2020-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"context"
	"errors"
	"fmt"
	"reflect"

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

type varsBackendKey struct{}

// VarsBackend is used by the [ReadVariable], [WriteVariable] and [ListVariables]
// functions, and indirectly by other functions in this package to abstract access
// to a specific backend. A default backend is initialized at process initialization
// and is available via [DefaultVarContext].
type VarsBackend interface {
	Get(name string, guid GUID) (VariableAttributes, []byte, error)
	Set(name string, guid GUID, attrs VariableAttributes, data []byte) error
	List() ([]VariableDescriptor, error)
}

// VarsBackend2 is like [VarsBackend] only it takes a context that the backend can use
// for deadlines or cancellation - this is paricularly applicable on systems where there
// may be multiple writers and writes have to be serialized by the operating system to
// some degree.
type VarsBackend2 interface {
	Get(ctx context.Context, name string, guid GUID) (VariableAttributes, []byte, error)
	Set(ctx context.Context, name string, guid GUID, attrs VariableAttributes, data []byte) error
	List(ctx context.Context) ([]VariableDescriptor, error)
}

// varsBackend2ToVarsBackendShim makes a VarsBackend2 look like a VarsBackend.
// It should only exist for the lifetime of a function call with the associated
// context.
type varsBackend2ToVarsBackendShim struct {
	Context context.Context
	Backend VarsBackend2
}

func (v *varsBackend2ToVarsBackendShim) Get(name string, guid GUID) (VariableAttributes, []byte, error) {
	return v.Backend.Get(v.Context, name, guid)
}

func (v *varsBackend2ToVarsBackendShim) Set(name string, guid GUID, attrs VariableAttributes, data []byte) error {
	return v.Backend.Set(v.Context, name, guid, attrs, data)
}

func (v *varsBackend2ToVarsBackendShim) List() ([]VariableDescriptor, error) {
	return v.Backend.List(v.Context)
}

func varsBackend2ToVarsBackend(ctx context.Context, backend VarsBackend2) VarsBackend {
	return &varsBackend2ToVarsBackendShim{
		Context: ctx,
		Backend: backend,
	}
}

func getVarsBackend(ctx context.Context) VarsBackend {
	switch v := ctx.Value(varsBackendKey{}).(type) {
	case VarsBackend2:
		return varsBackend2ToVarsBackend(ctx, v)
	case VarsBackend:
		return v
	case nil:
		return nullVarsBackend{}
	default:
		val := ctx.Value(varsBackendKey{})
		panic(fmt.Sprintf("invalid variable backend type %q: %#v", reflect.TypeOf(val), val))
	}
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

func withVarsBackend(ctx context.Context, backend VarsBackend) context.Context {
	return context.WithValue(ctx, varsBackendKey{}, backend)
}

func withVarsBackend2(ctx context.Context, backend VarsBackend2) context.Context {
	return context.WithValue(ctx, varsBackendKey{}, backend)
}

func newDefaultVarContext() context.Context {
	return addDefaultVarsBackend(context.Background())
}

// DefaultVarContext should generally be passed to functions that interact with
// EFI variables in order to use the default system backend for accessing EFI
// variables. It is based on a background context.
var DefaultVarContext = newDefaultVarContext()

// WithDefaultVarsBackend adds the default system backend for accesssing EFI
// variables to an existing context.
func WithDefaultVarsBackend(ctx context.Context) context.Context {
	return addDefaultVarsBackend(ctx)
}
