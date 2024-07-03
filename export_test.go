// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

type (
	NullVarsBackend               = nullVarsBackend
	VariableDescriptorSlice       = variableDescriptorSlice
	VarsBackendKey                = varsBackendKey
	VarsBackend2ToVarsBackendShim = varsBackend2ToVarsBackendShim
)

var (
	GetVarsBackend            = getVarsBackend
	VarsBackend2ToVarsBackend = varsBackend2ToVarsBackend
	WithVarsBackend           = withVarsBackend
	WithVarsBackend2          = withVarsBackend2
)
