// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package uefi

type EFI_GUID [16]byte

type EFI_LBA uint64

type EFI_TABLE_HEADER struct {
	Signature  uint64
	Revision   uint32
	HeaderSize uint32
	CRC        uint32
	Reserved   uint32
}
