// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.
//go:generate go run ./generate guids.csv generated_guids.go
//go:generate gofmt -w generated_guids.go

// Package guids provides a way to map well known firmware volume
// file GUIDs to readable names.
package guids

import efi "github.com/canonical/go-efilib"

// FileNameString returns the semi-readable name for the supplied
// GUID if it corresponds to a well known name used for files in
// firmware volumes (see [efi.MediaFvFileDevicePathNode]). If it is
// not known by this package, then ("", false) will be returned.
func FileNameString(guid efi.GUID) (name string, wellKnown bool) {
	name, wellKnown = guidToNameMap[guid]
	return name, wellKnown
}
