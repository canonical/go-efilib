// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"os"

	"golang.org/x/sys/unix"
)

var (
	mountsPath = "/proc/self/mounts"
	sysfsPath  = "/sys"

	osOpen   = os.Open
	osStat   = os.Stat
	unixStat = unix.Stat
)
