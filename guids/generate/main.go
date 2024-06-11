package main

import (
	"encoding/csv"
	"fmt"
	"os"

	efi "github.com/canonical/go-efilib"
)

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: %s <src> <out>", os.Args[0])
	}

	src := os.Args[1]
	out := os.Args[2]
	_ = out

	r, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("cannot open source csv file: %w", err)
	}
	defer r.Close()

	guids := make(map[efi.GUID]string)

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
		guids[guid] = record[1]
	}

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

package guids

import (
	"github.com/canonical/go-efilib"
)

var guidToNameMap map[efi.GUID]string

func init() {
	guidToNameMap = map[efi.GUID]string{
`); err != nil {
		return fmt.Errorf("cannot write init function prologue: %w", err)
	}

	for k, v := range guids {
		if _, err := fmt.Fprintf(w, "		efi.GUID{%#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x}:%q,\n", k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15], v); err != nil {
			return fmt.Errorf("cannot output string for %v: %w", k, err)
		}
	}

	if _, err := fmt.Fprintf(w, "	}\n}"); err != nil {
		return fmt.Errorf("cannot write init function epilogue: %w", err)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
