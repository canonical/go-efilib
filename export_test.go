// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

type (
	NullVarsBackend = nullVarsBackend
	VarsBackend     = varsBackend
)

func MockVarsBackend(backend VarsBackend) (restore func()) {
	orig := vars
	vars = backend
	return func() {
		vars = orig
	}
}
