// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"regexp"
)

var virtioRE = regexp.MustCompile(`^virtio[[:digit:]]`)

func handleVirtioDevicePathNode(state *devicePathBuilderState) error {
	if !virtioRE.MatchString(state.PeekUnhandledSysfsComponents(1)) {
		return errSkipDevicePathNodeHandler
	}

	state.AdvanceSysfsPath(1)
	return nil
}
