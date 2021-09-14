// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strconv"

	"golang.org/x/xerrors"

	"github.com/canonical/go-efilib"
)

var classRE = regexp.MustCompile(`^0x([[:xdigit:]]+)$`)

// pciRE matches "nnnn:bb:dd:f" where "nnnn" is the domain, "bb" is the bus number,
// "dd" is the device number and "f" is the function.
var pciRE = regexp.MustCompile(`^[[:xdigit:]]{4}:[[:xdigit:]]{2}:([[:xdigit:]]{2})\.([[:digit:]]{1})$`)

func handlePCIDevicePathNode(builder devicePathBuilder, dev *dev) error {
	component := builder.next(1)

	m := pciRE.FindStringSubmatch(component)
	if len(m) == 0 {
		return fmt.Errorf("invalid component: %s", component)
	}

	devNum, _ := strconv.ParseUint(m[1], 16, 8)
	fun, _ := strconv.ParseUint(m[2], 10, 8)

	classBytes, err := ioutil.ReadFile(filepath.Join(builder.absPath(component), "class"))
	if err != nil {
		return xerrors.Errorf("cannot read device class: %w", err)
	}

	var class []byte
	if n, err := fmt.Sscanf(string(classBytes), "0x%x", &class); err != nil || n != 1 {
		return errors.New("cannot decode device class")
	}

	builder.advance(1)

	switch {
	case bytes.HasPrefix(class, []byte{0x00}):
		dev.interfaceType = interfaceTypeSCSI
	case bytes.HasPrefix(class, []byte{0x01, 0x01}):
		dev.interfaceType = interfaceTypeIDE
	case bytes.HasPrefix(class, []byte{0x01, 0x06}):
		dev.interfaceType = interfaceTypeSATA
	case bytes.HasPrefix(class, []byte{0x01, 0x08}):
		dev.interfaceType = interfaceTypeNVME
	case bytes.HasPrefix(class, []byte{0x06, 0x04}):
		dev.interfaceType = interfaceTypePCI
	default:
		dev.interfaceType = interfaceTypeUnknown
	}

	dev.devPath = append(dev.devPath, &efi.PCIDevicePathNode{
		Function: uint8(fun),
		Device:   uint8(devNum)})
	return nil
}

func init() {
	registerDevicePathNodeHandler("pci", handlePCIDevicePathNode, []interfaceType{interfaceTypePCI})
}
