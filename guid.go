// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"encoding/binary"
	"fmt"
	"io"
)

// GUID corresponds to the EFI_GUID type.
type GUID [16]byte

func (guid GUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(guid[0:4]),
		binary.LittleEndian.Uint16(guid[4:6]),
		binary.LittleEndian.Uint16(guid[6:8]),
		binary.BigEndian.Uint16(guid[8:10]),
		guid[10:16])
}

// MakeGUID makes a new GUID from the supplied arguments.
func MakeGUID(a uint32, b, c, d uint16, e [6]uint8) (out GUID) {
	binary.LittleEndian.PutUint32(out[0:4], a)
	binary.LittleEndian.PutUint16(out[4:6], b)
	binary.LittleEndian.PutUint16(out[6:8], c)
	binary.BigEndian.PutUint16(out[8:10], d)
	copy(out[10:], e[:])
	return
}

// ReadGUID reads a EFI_GUID from the supplied io.Reader.
func ReadGUID(r io.Reader) (out GUID, err error) {
	_, err = io.ReadFull(r, out[:])
	return
}
