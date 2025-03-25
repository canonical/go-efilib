// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.
//go:generate go run ./generate map guids guidToNameMap guids.csv guidmap_generated.go
//go:generate gofmt -w guidmap_generated.go
//go:generate go run ./generate list guids_test allGuids guids.csv guidlist_generated_test.go
//go:generate gofmt -w guidlist_generated_test.go

// Package guids provides a way to map well known firmware volume and
// file GUIDs to readable names.
package guids

import (
	"bytes"
	"sort"

	efi "github.com/canonical/go-efilib"
)

// FileOrVolumeNameString returns the semi-readable name for the supplied
// GUID if it corresponds to a well known name used for files or
// firmware volumes (see [efi.MediaFvDevicePathNode] and
// [efi.MediaFvFileDevicePathNode]). If it is not known by this package,
// then ("", false) will be returned.
//
// Deprecated: use [IndustryStandardString].
func FileOrVolumeNameString(guid efi.GUID) (name string, wellKnown bool) {
	return IndustryStandardString(guid)
}

// IndustryStandardString returns the semi-readable name for the supplied
// GUID if it corresponds to a well known industry standard name. If it is
// not known by this package, then ("", false) will be returned.
func IndustryStandardString(guid efi.GUID) (name string, wellKnown bool) {
	name, wellKnown = guidToNameMap[guid]
	return name, wellKnown
}

// ListAllKnown returns a list of all well-known GUIDs that are used
// to identify the names of firmware volumes and their files (see
// [efi.MediaFvDevicePathNode] and [efi.MediaFvFileDevicePathNode]).
func ListAllKnown() []efi.GUID {
	var out []efi.GUID
	for guid := range guidToNameMap {
		out = append(out, guid)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
}

func init() {
	efi.RegisterFWFileNameLookup(IndustryStandardString)
	efi.RegisterFWVolNameLookup(IndustryStandardString)
}
