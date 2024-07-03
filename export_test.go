// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

type (
	NullVarsBackend         = nullVarsBackend
	VariableDescriptorSlice = variableDescriptorSlice
	VarsBackendKey          = varsBackendKey
	VarsBackendWrapper      = varsBackendWrapper
)

var (
	GetVarsBackend   = getVarsBackend
	WithVarsBackend  = withVarsBackend
	WithVarsBackend2 = withVarsBackend2
)
