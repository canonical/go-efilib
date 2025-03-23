// Copyright 2025 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"errors"
	"fmt"
)

// NetworkInterfaceType describes the type of network hardware.
type NetworkInterfaceType uint8

const (
	NetworkInterfaceTypeReserved NetworkInterfaceType = 0
	NetworkInterfaceTypeEthernet NetworkInterfaceType = 1
)

// MACAddressType describes the type of a MAC address.
type MACAddressType int

const (
	MACAddressTypeUnknown MACAddressType = iota // an unknown address type
	MACAddressTypeEUI48                         // EUI-48 address type
	MACAddressTypeEUI64                         // EUI-64 address type
)

// MACAddress is an abstraction for a MAC address.
type MACAddress interface {
	fmt.Stringer

	// Bytes32 returns the address as a 32-byte left-aligned, zero padded array,
	// which is how MAC addresses are represented in UEFI.
	Bytes32() [32]uint8

	Type() MACAddressType // Type address type
}

// EUI64 represents a EUI-64 (64-bit Extended Unique Identifier).
type EUI64 [8]uint8

// String implements [fmt.Stringer].
func (id EUI64) String() string {
	return fmt.Sprintf("%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x",
		id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7])
}

// Bytes implements [MACAddress.Bytes32].
func (id EUI64) Bytes32() [32]uint8 {
	var out [32]uint8
	copy(out[:], id[:])
	return out
}

// Type implements [MACAddress.Type].
func (EUI64) Type() MACAddressType {
	return MACAddressTypeEUI64
}

func (id EUI64) AsEUI48() (EUI48, error) {
	if id[3] != 0xFF || id[4] != 0xFE {
		return EUI48{}, errors.New("EUI64 doesn't represent a EUI48 address")
	}

	var out EUI48
	copy(out[0:], id[:3])
	copy(out[3:], id[5:])
	return out, nil
}

// EUI48 represents a EUI-48 (48-bit Extended Unique Identifier).
type EUI48 [6]uint8

// String implements [fmt.Stringer].
func (id EUI48) String() string {
	return fmt.Sprintf("%02x-%02x-%02x-%02x-%02x-%02x",
		id[0], id[1], id[2], id[3], id[4], id[5])
}

// Bytes32 implements [MACAddress.Bytes32].
func (id EUI48) Bytes32() [32]byte {
	var out [32]uint8
	copy(out[:], id[:])
	return out
}

// Type implements [MACAddress.Type].
func (EUI48) Type() MACAddressType {
	return MACAddressTypeEUI64
}

func (id EUI48) AsEUI64() EUI64 {
	var out EUI64
	copy(out[0:], id[:3])
	out[3] = 0xFF
	out[4] = 0xFE
	copy(out[5:], id[3:])
	return out
}

type unknownMACAddress [32]uint8

func (address unknownMACAddress) String() string {
	return fmt.Sprintf("%x", [32]byte(address))
}

func (address unknownMACAddress) Bytes32() [32]uint8 {
	var out [32]uint8
	copy(out[:], address[:])
	return out
}

func (unknownMACAddress) Type() MACAddressType {
	return MACAddressTypeUnknown
}
