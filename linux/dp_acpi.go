// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/xerrors"

	"github.com/canonical/go-efilib"
)

// acpiIdRE matches a ACPI or PNP ID, capturing the vendor and product.
var acpiIdRE = regexp.MustCompile(`^([[:upper:][:digit:]]{3,4})([[:xdigit:]]{4})$`)

// acpiModaliasRE matches a modalias for an ACPI node, capturing the CID.
var acpiModaliasRE = regexp.MustCompile(`^acpi:[[:alnum:]]+:([[:alnum:]]*)`)

func maybeUseSimpleACPIDevicePathNode(node *efi.ACPIExtendedDevicePathNode) efi.DevicePathNode {
	if node.HIDStr != "" || node.UIDStr != "" || node.CIDStr != "" {
		return node
	}
	if node.CID != 0 && node.CID != node.HID {
		return node
	}
	return &efi.ACPIDevicePathNode{HID: node.HID, UID: node.UID}
}

func decodeACPIOrPNPId(str string) (string, uint16, error) {
	switch len(str) {
	case 7, 8:
		m := acpiIdRE.FindStringSubmatch(str)
		if len(m) == 0 {
			return "", 0, errors.New("invalid ID")
		}
		vendor := m[1]
		product, _ := hex.DecodeString(m[2])
		return vendor, binary.BigEndian.Uint16(product), nil
	default:
		return "", 0, errors.New("invalid length")
	}
}

func newEISAIDOrString(vendor string, product uint16) (efi.EISAID, string, error) {
	switch len(vendor) {
	case 3:
		id, err := efi.NewEISAID(vendor, product)
		if err != nil {
			return 0, "", err
		}
		return id, "", nil
	case 4:
		return 0, fmt.Sprintf("%s%04x", vendor, product), nil
	default:
		return 0, "", errors.New("invalid vendor length")
	}
}

func newACPIExtendedDevicePathNode(path string) (*efi.ACPIExtendedDevicePathNode, error) {
	node := new(efi.ACPIExtendedDevicePathNode)

	hidBytes, err := ioutil.ReadFile(filepath.Join(path, "firmware_node", "hid"))
	if err != nil {
		return nil, err
	}

	hidVendor, hidProduct, err := decodeACPIOrPNPId(strings.TrimSpace(string(hidBytes)))
	if err != nil {
		return nil, xerrors.Errorf("cannot decode hid: %w", err)
	}
	hid, hidStr, err := newEISAIDOrString(hidVendor, hidProduct)
	if err != nil {
		return nil, xerrors.Errorf("cannot make hid: %w", err)
	}
	node.HID = hid
	node.HIDStr = hidStr

	modalias, err := ioutil.ReadFile(filepath.Join(path, "firmware_node", "modalias"))
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return nil, err
	default:
		m := acpiModaliasRE.FindSubmatch(modalias)
		if len(m) == 0 {
			return nil, errors.New("invalid modalias")
		}
		if len(m[1]) > 0 {
			cidVendor, cidProduct, err := decodeACPIOrPNPId(string(m[1]))
			if err != nil {
				return nil, xerrors.Errorf("cannot decode cid: %w", err)
			}
			cid, cidStr, err := newEISAIDOrString(cidVendor, cidProduct)
			if err != nil {
				return nil, xerrors.Errorf("cannot make cid: %w", err)
			}
			node.CID = cid
			node.CIDStr = cidStr
		}
	}

	uidBytes, err := ioutil.ReadFile(filepath.Join(path, "firmware_node", "uid"))
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return nil, err
	default:
		uidStr := strings.TrimSpace(string(uidBytes))
		uid, err := strconv.ParseUint(uidStr, 10, 32)
		if err != nil {
			node.UIDStr = uidStr
		} else {
			node.UID = uint32(uid)
		}
	}

	return node, nil
}
