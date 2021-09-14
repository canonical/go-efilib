// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/xerrors"

	"github.com/canonical/go-efilib"
)

var ataRE = regexp.MustCompile(`^ata([[:digit:]]+)\/host[[:digit:]]+\/target[[:digit:]]+\:[[:digit:]]+\:[[:digit:]]+\/[[:digit:]]+\:[[:digit:]]+\:[[:digit:]]+\:[[:digit:]]+\/block\/s[dr][[:alpha:]]$`)

var ataDevRE = regexp.MustCompile(`^dev[[:digit:]]+\.([[:digit:]]+)\.?([[:digit:]]*)`)

func handleATADevicePathNode(builder devicePathBuilder, dev *dev) error {
	if builder.numRemaining() < 6 {
		return errors.New("invalid path: not enough components")
	}

	m := ataRE.FindStringSubmatch(builder.next(6))
	if len(m) == 0 {
		return fmt.Errorf("invalid path components: %s", builder.next(6))
	}
	printId, _ := strconv.Atoi(m[1])

	node := new(efi.SATADevicePathNode)

	portBytes, err := ioutil.ReadFile(filepath.Join(builder.absPath(builder.next(1)), "ata_port", builder.next(1), "port_no"))
	if err != nil {
		return xerrors.Errorf("cannot obtain port ID: %w", err)
	}

	port, err := strconv.ParseUint(strings.TrimSpace(string(portBytes)), 10, 16)
	if err != nil {
		return xerrors.Errorf("invalid port ID: %w", err)
	}
	// The kernel provides a one-indexed number and the firmware is zero-indexed.
	node.HBAPortNumber = uint16(port) - 1

	paths, err := filepath.Glob(filepath.Join(builder.absPath(builder.next(1)), fmt.Sprintf("link[0-9]*/dev%d.[0-9]*", printId)))
	switch {
	case err != nil:
		return err
	case len(paths) == 0:
		paths, err = filepath.Glob(filepath.Join(builder.absPath(builder.next(1)), fmt.Sprintf("link[0-9]*/dev%d.[0-9]*.0", printId)))
		if err != nil {
			return err
		}
	}

	if len(paths) != 1 {
		return errors.New("cannot determine PMP")
	}

	m = ataDevRE.FindStringSubmatch(filepath.Base(paths[0]))
	switch {
	case len(m) == 0:
		return errors.New("cannot determine PMP: invalid format")
	case m[2] == "":
		if m[1] != "0" {
			return errors.New("invalid LUN")
		}
		node.PortMultiplierPortNumber = 0xffff
	default:
		if m[2] != "0" {
			return errors.New("invalid LUN")
		}
		pmp, err := strconv.ParseUint(m[1], 10, 16)
		if err != nil {
			return xerrors.Errorf("invalid PMP: %w", err)
		}
		if pmp > 0x7fff {
			return errors.New("invalid LUN")
		}
		node.PortMultiplierPortNumber = uint16(pmp)
	}

	builder.advance(6)
	dev.devPath = append(dev.devPath, node)
	return nil
}

func init() {
	registerDevicePathNodeHandler("ata", handleATADevicePathNode, []interfaceType{interfaceTypeSATA})
}
