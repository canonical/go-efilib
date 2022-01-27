// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/canonical/go-efilib"

	"golang.org/x/xerrors"
)

var scsiRE = regexp.MustCompile(`^host[[:digit:]]+\/target[[:digit:]]+\:[[:digit:]]+\:[[:digit:]]+\/[[:digit:]]+\:([[:digit:]]+)\:([[:digit:]])+\:([[:digit:]])+\/block\/s[dr][[:alpha:]]$`)

func handleSCSIDevicePathNode(builder devicePathBuilder) error {
	if builder.numRemaining() < 5 {
		return errors.New("invalid path: not enough components")
	}

	m := scsiRE.FindStringSubmatch(builder.next(5))
	if len(m) == 0 {
		return fmt.Errorf("invalid path components: %s", builder.next(5))
	}

	builder.advance(5)

	if m[1] != "0" {
		return errors.New("invalid channel")
	}

	target, err := strconv.ParseUint(m[2], 10, 16)
	if err != nil {
		return xerrors.Errorf("invalid target: %w", err)
	}
	lun, err := strconv.ParseUint(m[3], 10, 16)
	if err != nil {
		return xerrors.Errorf("invalid LUN: %w", err)
	}

	builder.append(&efi.SCSIDevicePathNode{
		PUN: uint16(target),
		LUN: uint16(lun)})
	return nil
}

func init() {
	registerDevicePathNodeHandler("scsi", handleSCSIDevicePathNode, 0, interfaceTypeSCSI)
}
