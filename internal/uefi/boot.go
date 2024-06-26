// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package uefi

const (
	EFI_OS_INDICATIONS_BOOT_TO_FW_UI                   = 0x0000000000000001
	EFI_OS_INDICATIONS_TIMESTAMP_REVOCATION            = 0x0000000000000002
	EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED = 0x0000000000000004
	EFI_OS_INDICATIONS_FMP_CAPSULE_SUPPORTED           = 0x0000000000000008
	EFI_OS_INDICATIONS_CAPSULE_RESULT_VAR_SUPPORTED    = 0x0000000000000010
	EFI_OS_INDICATIONS_START_OS_RECOVERY               = 0x0000000000000020
	EFI_OS_INDICATIONS_START_PLATFORM_RECOVERY         = 0x0000000000000040
	EFI_OS_INDICATIONS_JSON_CONFIG_DATA_REFRESH        = 0x0000000000000080

	EFI_BOOT_OPTION_SUPPORT_KEY     = 0x00000001
	EFI_BOOT_OPTION_SUPPORT_APP     = 0x00000002
	EFI_BOOT_OPTION_SUPPORT_SYSPREP = 0x00000010
	EFI_BOOT_OPTION_SUPPORT_COUNT   = 0x00000300
)
