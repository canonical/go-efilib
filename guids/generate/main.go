package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"sort"

	efi "github.com/canonical/go-efilib"
)

func run() error {
	if len(os.Args) != 6 {
		return fmt.Errorf("usage: %s [map|list] <pkgname> <varname> <src> <out>", os.Args[0])
	}

	action := os.Args[1]
	if action != "map" && action != "list" {
		return fmt.Errorf("usage: %s [map|list] <pkgname> <varname> <src> <out>", os.Args[0])
	}
	pkgname := os.Args[2]
	varname := os.Args[3]
	src := os.Args[4]
	out := os.Args[5]

	r, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("cannot open source csv file: %w", err)
	}
	defer r.Close()

	var orderedGuids []efi.GUID
	guidMap := make(map[efi.GUID]string)

	csvReader := csv.NewReader(r)
	records, err := csvReader.ReadAll()
	if err != nil {
		return fmt.Errorf("cannot decode csv: %w", err)
	}
	for i, record := range records {
		guid, err := efi.DecodeGUIDString(record[0])
		if err != nil {
			return fmt.Errorf("cannot decode GUID at record %d: %w", i, err)
		}
		guidMap[guid] = record[1]
		orderedGuids = append(orderedGuids, guid)
	}
	sort.Slice(orderedGuids, func(i, j int) bool { return bytes.Compare(orderedGuids[i][:], orderedGuids[j][:]) < 0 })

	w, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("cannot create output file: %w", err)
	}
	defer w.Close()

	if _, err := fmt.Fprintf(w, `// NOTE: This file is generated automatically and any manual changes to it will be overwritten
//
// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package %s

import (
	"github.com/canonical/go-efilib"
)
`, pkgname); err != nil {
		return fmt.Errorf("cannot write header: %w", err)
	}

	switch action {
	case "map":
		if _, err := fmt.Fprintf(w, "var %s map[efi.GUID]string\n", varname); err != nil {
			return fmt.Errorf("cannot write var declaration: %w", err)
		}
	case "list":
		if _, err := fmt.Fprintf(w, "var %s []efi.GUID\n", varname); err != nil {
			return fmt.Errorf("cannot write var declaration: %w", err)
		}
	}

	if _, err := fmt.Fprintf(w, `
func init() {
`); err != nil {
		return fmt.Errorf("cannot write init function prologue: %w", err)
	}

	switch action {
	case "map":
		if _, err := fmt.Fprintf(w, "	%s = map[efi.GUID]string{\n", varname); err != nil {
			return fmt.Errorf("cannot write map initializer: %w", err)
		}
	case "list":
		if _, err := fmt.Fprintf(w, "	%s = []efi.GUID{\n", varname); err != nil {
			return fmt.Errorf("cannot write list initializer: %w", err)
		}
	}

	for _, guid := range orderedGuids {
		name := guidMap[guid]
		switch action {
		case "map":
			if _, err := fmt.Fprintf(w, "		efi.GUID{%#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x}: %q,\n", guid[0], guid[1], guid[2], guid[3], guid[4], guid[5], guid[6], guid[7], guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15], name); err != nil {
				return fmt.Errorf("cannot output map entry for %q: %w", name, err)
			}
		case "list":
			if _, err := fmt.Fprintf(w, "		efi.GUID{%#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x, %#02x},\n", guid[0], guid[1], guid[2], guid[3], guid[4], guid[5], guid[6], guid[7], guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]); err != nil {
				return fmt.Errorf("cannot output list entry for %q: %w", name, err)
			}
		}
	}

	if _, err := fmt.Fprintf(w, `	}
}
`); err != nil {
		return fmt.Errorf("cannot write init function epilogoue: %w", err)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
