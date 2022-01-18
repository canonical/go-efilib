// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"os"
)

func MockDevicePathNodeHandlers(handlers map[interfaceType][]registeredDpHandler) (restore func()) {
	orig := devicePathNodeHandlers
	devicePathNodeHandlers = handlers
	return func() {
		devicePathNodeHandlers = orig
	}
}

func MockMountsPath(path string) (restore func()) {
	orig := mountsPath
	mountsPath = path
	return func() {
		mountsPath = orig
	}
}

func MockOsOpen(fn func(string) (*os.File, error)) (restore func()) {
	orig := osOpen
	osOpen = fn
	return func() {
		osOpen = orig
	}
}

func MockSysfsPath(path string) (restore func()) {
	orig := sysfsPath
	sysfsPath = path
	return func() {
		sysfsPath = orig
	}
}
