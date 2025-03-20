// Copyright 2025 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import "fmt"

// EUI64 represents a EUI-64 (64-bit Extended Unique Identifier).
type EUI64 [8]uint8

// String implements [fmt.Stringer].
func (id EUI64) String() string {
	return fmt.Sprintf("%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x",
		id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7])
}
