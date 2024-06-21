// Copyright 2020-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.
//go:build !linux

package efi

import "context"

func newDefaultVarContext() context.Context {
	return nullContext
}
