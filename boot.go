// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/canonical/go-efilib/internal/uefi"
)

// LoadOptionClass describes a class of load option
type LoadOptionClass string

const (
	// LoadOptionClassDriver corresponds to drivers that are processed before
	// normal boot options and before the initial ready to boot signal.
	LoadOptionClassDriver LoadOptionClass = "Driver"

	// LadOptionClassSysPrep corresponds to system preparation applications that
	// are processed before normal boot options and before the initial
	// ready to boot signal.
	LoadOptionClassSysPrep LoadOptionClass = "SysPrep"

	// LoadOptionClassBoot corresponds to normal boot applicationds.
	LoadOptionClassBoot LoadOptionClass = "Boot"

	// LoadOptionClassPlatformRecovery corresponds to platform supplied recovery
	// applications.
	LoadOptionClassPlatformRecovery LoadOptionClass = "PlatformRecovery"
)

// OSIndications provides a way for the firmware to advertise features to the OS
// and a way to request the firmware perform a specific action on the next boot,
// although this latter case is not supported by this package.
type OSIndications uint64

const (
	OSIndicationBootToFWUI                   = uefi.EFI_OS_INDICATIONS_BOOT_TO_FW_UI
	OSIndicationTimestampRevocation          = uefi.EFI_OS_INDICATIONS_TIMESTAMP_REVOCATION
	OSIndicationFileCapsuleDeliverySupported = uefi.EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED
	OSIndicationFMPCapsuleSupported          = uefi.EFI_OS_INDICATIONS_FMP_CAPSULE_SUPPORTED
	OSIndicationCapsuleResultVarSupported    = uefi.EFI_OS_INDICATIONS_CAPSULE_RESULT_VAR_SUPPORTED
	OSIndicationStartOSRecovery              = uefi.EFI_OS_INDICATIONS_START_OS_RECOVERY
	OSIndicationStartPlatformRecovery        = uefi.EFI_OS_INDICATIONS_START_PLATFORM_RECOVERY
	OSIndicationJSONConfigDataRefresh        = uefi.EFI_OS_INDICATIONS_JSON_CONFIG_DATA_REFRESH
)

// BootOptionSupport provides a way for the firmware to indicate certain boot
// options that are supported.
type BootOptionSupport uint32

const (
	BootOptionSupportKey     = uefi.EFI_BOOT_OPTION_SUPPORT_KEY
	BootOptionSupportApp     = uefi.EFI_BOOT_OPTION_SUPPORT_APP
	BootOptionSupportSysPrep = uefi.EFI_BOOT_OPTION_SUPPORT_SYSPREP
	BootOptionSupportCount   = uefi.EFI_BOOT_OPTION_SUPPORT_COUNT
)

// KeyCount returns the supported number of key presses (up to 3).
func (s BootOptionSupport) KeyCount() uint8 {
	return uint8((s & BootOptionSupportCount) >> 8)
}

// ReadOSIndicationsSupportedVariable returns the value of the OSIndicationsSupported
// variable in the global namespace.
func ReadOSIndicationsSupportedVariable() (OSIndications, error) {
	data, _, err := ReadVariable("OsIndicationsSupported", GlobalVariable)
	if err != nil {
		return 0, err
	}
	if len(data) != 8 {
		return 0, fmt.Errorf("variable contents has an unexpected size (%d bytes)", len(data))
	}
	return OSIndications(binary.LittleEndian.Uint64(data)), nil
}

// ReadBootOptionSupportVariable returns the value of the BootOptionSupport
// variable in the global namespace.
func ReadBootOptionSupportVariable() (BootOptionSupport, error) {
	data, _, err := ReadVariable("BootOptionSupport", GlobalVariable)
	if err != nil {
		return 0, err
	}
	if len(data) != 4 {
		return 0, fmt.Errorf("variable contents has an unexpected size (%d bytes)", len(data))
	}
	return BootOptionSupport(binary.LittleEndian.Uint32(data)), nil
}

// ReadLoadOrderVariable returns the load option order for the specified class,
// which must be one of LoadOptionClassDriver, LoadOptionClassSysPrep, or
// LoadOptionClassBoot.
func ReadLoadOrderVariable(class LoadOptionClass) ([]uint16, error) {
	switch class {
	case LoadOptionClassDriver, LoadOptionClassSysPrep, LoadOptionClassBoot:
		// ok
	default:
		return nil, fmt.Errorf("invalid class %q: function only suitable for Driver, SysPrep or Boot", class)
	}

	data, _, err := ReadVariable(string(class)+"Order", GlobalVariable)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	if r.Size()&0x1 > 0 {
		return nil, fmt.Errorf("%sOrder variable contents has odd size (%d bytes)", class, r.Size())
	}

	out := make([]uint16, r.Size()>>1)
	if err := binary.Read(r, binary.LittleEndian, &out); err != nil {
		return nil, err
	}

	return out, nil
}

// ReadLoadOptionVariable returns the LoadOption for the specified class and option number.
// The variable is read from the global namespace.
func ReadLoadOptionVariable(class LoadOptionClass, n uint16) (*LoadOption, error) {
	switch class {
	case LoadOptionClassDriver, LoadOptionClassSysPrep, LoadOptionClassBoot, LoadOptionClassPlatformRecovery:
		// ok
	default:
		return nil, fmt.Errorf("invalid class %q: only suitable for Driver, SysPrep, Boot, or PlatformRecovery", class)
	}

	data, _, err := ReadVariable(fmt.Sprintf("%s%04x", class, n), GlobalVariable)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)

	option, err := ReadLoadOption(r)
	if err != nil {
		return nil, fmt.Errorf("cannot decode LoadOption: %w", err)
	}

	return option, nil
}

// ReadBootNextVariable returns the option number of the boot entry to try next.
func ReadBootNextVariable() (uint16, error) {
	data, _, err := ReadVariable("BootNext", GlobalVariable)
	if err != nil {
		return 0, err
	}

	if len(data) != 2 {
		return 0, fmt.Errorf("BootNext variable contents has the wrong size (%d bytes)", len(data))
	}

	return binary.LittleEndian.Uint16(data), nil
}

// ReadBootNextLoadOptionVariable returns the LoadOption for the boot entry to try next.
func ReadBootNextLoadOptionVariable() (*LoadOption, error) {
	n, err := ReadBootNextVariable()
	if err != nil {
		return nil, err
	}

	return ReadLoadOptionVariable(LoadOptionClassBoot, n)
}

// ReadBootCurrentVariable returns the option number used for the current boot.
func ReadBootCurrentVariable() (uint16, error) {
	data, _, err := ReadVariable("BootCurrent", GlobalVariable)
	if err != nil {
		return 0, err
	}

	if len(data) != 2 {
		return 0, fmt.Errorf("BootCurrent variable contents has the wrong size (%d bytes)", len(data))
	}

	return binary.LittleEndian.Uint16(data), nil
}

// ReadOrderedLoadOptionVariables returns an ordered list of LoadOptions for the specified
// class. The variables are all read from the global namespace. This will skip entries
// for which there isn't a corresponding variable.
func ReadOrderedLoadOptionVariables(class LoadOptionClass) ([]*LoadOption, error) {
	var optNumbers []uint16
	switch class {
	case LoadOptionClassDriver, LoadOptionClassSysPrep, LoadOptionClassBoot:
		var err error
		optNumbers, err = ReadLoadOrderVariable(class)
		if err != nil {
			return nil, fmt.Errorf("cannot obtain order: %w", err)
		}
	case LoadOptionClassPlatformRecovery:
		vars, err := ListVariables()
		if err != nil {
			return nil, fmt.Errorf("cannot list variables: %w", err)
		}
		for _, desc := range vars {
			fmt.Println(desc)
			if desc.GUID != GlobalVariable {
				continue
			}
			if !strings.HasPrefix(desc.Name, string(LoadOptionClassPlatformRecovery)) {
				continue
			}
			if len(desc.Name) != len(LoadOptionClassPlatformRecovery)+4 {
				continue
			}

			var x uint16
			if n, err := fmt.Sscanf(desc.Name, "PlatformRecovery%x", &x); err != nil || n != 1 {
				continue
			}

			optNumbers = append(optNumbers, x)
		}

		sort.Slice(optNumbers, func(i, j int) bool { return optNumbers[i] < optNumbers[j] })
	}

	var opts []*LoadOption
	for _, n := range optNumbers {
		opt, err := ReadLoadOptionVariable(class, n)
		switch {
		case errors.Is(err, ErrVarNotExist):
			// skip and ignore missing number
		case err != nil:
			// handle all other errors
			return nil, fmt.Errorf("cannot read load option %d: %w", n, err)
		default:
			opts = append(opts, opt)
		}
	}

	return opts, nil
}
