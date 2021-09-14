// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
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

// ataRE matches an ATA path including the components from the SCSI subsystem,
// capturing the ATA print ID, SCSI channel, SCSI target and SCSI LUN.
//
// The kernel creates one ata%d device per port (see
// drivers/ata/libata-core.c:ata_host_register). Each ATA device is represented
// in the SCSI layer by setting the SCSI channel to the port multiplier port
// number, the SCSI target to the device number (0 for SATA, 0 or 1 for PATA),
// and the SCSI LUN as the LUN (see drivers/ata/libata-scsi.c:ata_scsi_scan_host).
var ataRE = regexp.MustCompile(`^ata([[:digit:]]+)\/host[[:digit:]]+\/target[[:digit:]]+\:[[:digit:]]+\:[[:digit:]]+\/[[:digit:]]+\:([[:digit:]]+)\:([[:digit:]])+\:([[:digit:]])+\/block\/s[dr][[:alpha:]]$`)

var ataDevRE = regexp.MustCompile(`^dev[[:digit:]]+\.([[:digit:]]+)\.?([[:digit:]]*)`)

func handleATADevicePathNode(builder devicePathBuilder, dev *dev) error {
	if builder.numRemaining() < 6 {
		return errors.New("invalid path: not enough components")
	}

	m := ataRE.FindStringSubmatch(builder.next(6))
	if len(m) == 0 {
		return fmt.Errorf("invalid path components: %s", builder.next(6))
	}

	// Obtain the ATA port number local to this ATA controller.
	portBytes, err := ioutil.ReadFile(filepath.Join(builder.absPath(builder.next(1)), "ata_port", builder.next(1), "port_no"))
	if err != nil {
		return xerrors.Errorf("cannot obtain port ID: %w", err)
	}

	lun, err := strconv.ParseUint(m[4], 10, 16)
	if err != nil {
		return xerrors.Errorf("invalid LUN: %w", err)
	}

	var node efi.DevicePathNode

	switch dev.interfaceType {
	case interfaceTypeIDE:
		controller, err := strconv.Atoi(strings.TrimSpace(string(portBytes)))
		if err != nil {
			return xerrors.Errorf("invalid controller: %w", err)
		}
		// PATA has a maximum of 2 ports.
		if controller < 1 || controller > 2 {
			return fmt.Errorf("invalid controller: %d", controller)
		}
		// The channel is always 0 for PATA devices (no port multiplier).
		if m[2] != "0" {
			return errors.New("invalid channel")
		}
		// The target corresponds to the PATA device.
		drive, err := strconv.ParseUint(m[3], 10, 1)
		if err != nil {
			return xerrors.Errorf("invalid drive: %w", err)
		}

		node = &efi.ATAPIDevicePathNode{
			Controller: efi.ATAPIControllerRole(controller - 1),
			Drive:      efi.ATAPIDriveRole(drive),
			LUN:        uint16(lun)}
	case interfaceTypeSATA:
		port, err := strconv.ParseUint(strings.TrimSpace(string(portBytes)), 10, 16)
		if err != nil {
			return xerrors.Errorf("invalid port ID: %w", err)
		}

		printId, _ := strconv.Atoi(m[1])

		// The channel indicates the port multiplier port number for SATA devices.
		pmp, err := strconv.ParseUint(m[2], 10, 15)
		if err != nil {
			return xerrors.Errorf("invalid PMP: %w", err)
		}
		// SATA ports only have a single device, so the target should be zero.
		if m[3] != "0" {
			return errors.New("invalid target")
		}

		// We need to determine if the device is connected via a port
		// multiplier because we have to set the PMP address to 0xffff
		// if it isn't. Unfortunately, it is zero indexed so checking
		// that it is zero isn't sufficient.
		//
		// The kernel will expose a single host link%d device if there
		// is no port multiplier, or one of more PMP link%d.%d devices
		// if there is a port multiplier attached (see
		// drivers/ata/libata-pmp.c:sata_pmp_init_links and
		// drivers/ata/libata-transport.c:ata_tlink_add).
		_, err = os.Stat(filepath.Join(builder.next(1), fmt.Sprintf("link%d.%d", printId, pmp)))
		switch {
		case os.IsNotExist(err):
			// No port multiplier is connected.
			pmp = 0xffff
		case err != nil:
			return err
		default:
			// A port multiplier is connected.
		}

		node = &efi.SATADevicePathNode{
			// The kernel provides a one-indexed number and the firmware is zero-indexed.
			HBAPortNumber:            uint16(port) - 1,
			PortMultiplierPortNumber: uint16(pmp),
			LUN:                      uint16(lun)}
	default:
		return errors.New("invalid interface type")
	}

	builder.advance(6)
	dev.devPath = append(dev.devPath, node)
	return nil
}

func init() {
	registerDevicePathNodeHandler("ata", handleATADevicePathNode, []interfaceType{interfaceTypeIDE, interfaceTypeSATA})
}
