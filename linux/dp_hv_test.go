// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-efilib"
)

type hvSuite struct {
	TarFileMixin
}

var _ = Suite(&hvSuite{})

func (s *hvSuite) TestHandleHVDevicePathNode(c *C) {
	restore := MockSysfsPath(filepath.Join(s.UnpackTar(c, "testdata/sys.tar"), "sys"))
	defer restore()

	builder := &devicePathBuilderImpl{
		iface: interfaceTypeVMBus,
		devPath: efi.DevicePath{
			&efi.ACPIExtendedDevicePathNode{HIDStr: "VMBus"}},
		processed: []string{"LNXSYSTM:00", "LNXSYBUS:00", "ACPI0004:00", "VMBUS:00"},
		remaining: []string{"f8b3781b-1e82-4818-a1c3-63d806ec15bb", "host6", "target6:0:0", "6:0:0:0", "block", "sdf"}}
	c.Check(handleHVDevicePathNode(builder), IsNil)
	c.Check(builder.processed, DeepEquals, []string{"LNXSYSTM:00", "LNXSYBUS:00", "ACPI0004:00", "VMBUS:00", "f8b3781b-1e82-4818-a1c3-63d806ec15bb"})
	c.Check(builder.remaining, DeepEquals, []string{"host6", "target6:0:0", "6:0:0:0", "block", "sdf"})
	c.Check(builder.iface, Equals, interfaceTypeSCSI)
	c.Check(builder.devPath, DeepEquals, efi.DevicePath{
		&efi.ACPIExtendedDevicePathNode{HIDStr: "VMBus"},
		&efi.VendorDevicePathNode{
			Type: efi.HardwareDevicePath,
			GUID: efi.MakeGUID(0x9b17e5a2, 0x0891, 0x42dd, 0xb653, [...]uint8{0x80, 0xb5, 0xc2, 0x28, 0x09, 0xba}),
			Data: DecodeHexString(c, "d96361baa104294db60572e2ffb1dc7f1b78b3f8821e1848a1c363d806ec15bb")}})
}
