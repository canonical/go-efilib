// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"golang.org/x/sys/unix"
)

var unixStatfs = unix.Statfs
