// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/canonical/go-efilib"
	"github.com/canonical/go-efilib/linux"
	"github.com/jessevdk/go-flags"
)

type mode linux.FilePathToDevicePathMode

func (m mode) MarshalFlag() (string, error) {
	switch linux.FilePathToDevicePathMode(m) {
	case linux.FullPath:
		return "full", nil
	case linux.ShortFormPathHD:
		return "hd", nil
	case linux.ShortFormPathFile:
		return "file", nil
	default:
		return "", fmt.Errorf("invalid value: %v", m)
	}
}

func (m *mode) UnmarshalFlag(value string) error {
	switch value {
	case "full":
		*m = mode(linux.FullPath)
	case "hd":
		*m = mode(linux.ShortFormPathHD)
	case "file":
		*m = mode(linux.ShortFormPathFile)
	default:
		return fmt.Errorf("invalid value: %v", value)
	}
	return nil
}

type options struct {
	Hexdump bool   `long:"hexdump" description:"Display a hexdump of the device path"`
	Mode    mode   `long:"mode" short:"m" description:"Specify the mode" default:"full" choice:"full" choice:"hd" choice:"file"`
	Output  string `long:"output" short:"o" description:"Write the binary device path to the specified file"`
	Verbose bool   `long:"verbose" short:"v" description:"Print more verbose version of device path"`

	Positional struct {
		Filename string `positional-arg-name:"filename"`
	} `positional-args:"true"`
}

var opts options

func run() error {
	if _, err := flags.Parse(&opts); err != nil {
		return err
	}

	path, err := linux.FilePathToDevicePath(opts.Positional.Filename, linux.FilePathToDevicePathMode(opts.Mode))
	if err != nil {
		return err
	}

	if opts.Output == "-" {
		if err := path.Write(os.Stdout); err != nil {
			return fmt.Errorf("cannot serialize path to stdout: %v", err)
		}
		return nil
	}

	var flags efi.DevicePathToStringFlags
	if !opts.Verbose {
		flags |= efi.DevicePathDisplayOnly
	}
	fmt.Printf("%s\n", path.ToString(flags))

	if opts.Hexdump {
		b, err := path.Bytes()
		if err != nil {
			return fmt.Errorf("cannot serialize path: %v", err)
		}

		fmt.Println()
		fmt.Println(hex.Dump(b))
	}

	if opts.Output != "" {
		b, err := path.Bytes()
		if err != nil {
			return fmt.Errorf("cannot serialize path: %v", err)
		}

		if err := ioutil.WriteFile(opts.Output, b, 0644); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		switch e := err.(type) {
		case *flags.Error:
			// flags already prints this
			if e.Type != flags.ErrHelp {
				os.Exit(1)
			}
		default:
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
