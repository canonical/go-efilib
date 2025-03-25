// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"bytes"
	"os"

	. "github.com/canonical/go-efilib"

	. "gopkg.in/check.v1"
)

var zeroEUI64 EUI64

type dpSuite struct{}

var _ = Suite(&dpSuite{})

func (s *dpSuite) TestReadAndWriteDevicePath(c *C) {
	b := DecodeHexString(c, "02010c00d041030a0000000001010600001d0101060000000317100001000000000000000000000004012a000100"+
		"0000000800000000000000001000000000007b94de66b2fd2545b75230d66bb2b9600202040434005c004500460049005c007500620075006e00740075005c007"+
		"300680069006d007800360034002e0065006600690000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.String(), Equals, "\\PciRoot(0x0)\\Pci(0x1d,0x0)\\Pci(0x0,0x0)\\NVMe(0x1,00-00-00-00-00-00-00-00)"+
		"\\HD(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960)\\\\EFI\\ubuntu\\shimx64.efi")

	expected := DevicePath{
		&ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x0},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x1d},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0},
		&NVMENamespaceDevicePathNode{
			NamespaceID:   0x1,
			NamespaceUUID: zeroEUI64},
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}
	c.Check(path, DeepEquals, expected)

	var buf bytes.Buffer
	c.Check(path.Write(&buf), IsNil)
	c.Check(buf.Bytes(), DeepEquals, b)
}

func (s *dpSuite) TestDevicePathToString(c *C) {
	b := DecodeHexString(c, "02010c00d041030a0000000001010600001d0101060000000317100001000000000000000000000004012a000100"+
		"0000000800000000000000001000000000007b94de66b2fd2545b75230d66bb2b9600202040434005c004500460049005c007500620075006e00740075005c007"+
		"300680069006d007800360034002e0065006600690000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.ToString(0), Equals, "\\PciRoot(0x0)\\Pci(0x1d,0x0)\\Pci(0x0,0x0)\\NVMe(0x1,00-00-00-00-00-00-00-00)"+
		"\\HD(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960,0x800,0x100000)\\\\EFI\\ubuntu\\shimx64.efi")
}

func (s *dpSuite) TestDevicePathToStringDisplayOnly(c *C) {
	b := DecodeHexString(c, "02010c00d041030a0000000001010600001d0101060000000317100001000000000000000000000004012a000100"+
		"0000000800000000000000001000000000007b94de66b2fd2545b75230d66bb2b9600202040434005c004500460049005c007500620075006e00740075005c007"+
		"300680069006d007800360034002e0065006600690000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.ToString(DevicePathDisplayOnly), Equals, "\\PciRoot(0x0)\\Pci(0x1d,0x0)\\Pci(0x0,0x0)\\NVMe(0x1,00-00-00-00-00-00-00-00)"+
		"\\HD(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960)\\\\EFI\\ubuntu\\shimx64.efi")
}

func (s *dpSuite) TestReadAndWriteDevicePathUnrecognizedType(c *C) {
	b := DecodeHexString(c, "02ff1800000000000000000000000000564d42757300000001553400a2e5179b9108dd42b65380"+
		"b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656030208000000000004012a000f0000000028000000"+
		"0000000050030000000000dbfe3389532f0b49a2455c7fa1f986320202040434005c004500460049005c007500620075006e00740075005c0073"+
		"00680069006d007800360034002e0065006600690000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.String(), Equals, "\\AcpiPath(255,000000000000000000000000564d427573000000)"+
		"\\HardwarePath(85,a2e5179b9108dd42b65380b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656)"+
		"\\Scsi(0x0,0x0)\\HD(15,GPT,8933fedb-2f53-490b-a245-5c7fa1f98632)\\\\EFI\\ubuntu\\shimx64.efi")

	expected := DevicePath{
		&GenericDevicePathNode{
			Type:    ACPIDevicePath,
			SubType: 0xff,
			Data:    DecodeHexString(c, "000000000000000000000000564d427573000000")},
		&GenericDevicePathNode{
			Type:    HardwareDevicePath,
			SubType: 0x55,
			Data:    DecodeHexString(c, "a2e5179b9108dd42b65380b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656")},
		&SCSIDevicePathNode{
			PUN: 0,
			LUN: 0},
		&HardDriveDevicePathNode{
			PartitionNumber: 15,
			PartitionStart:  0x2800,
			PartitionSize:   0x35000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x8933fedb, 0x2f53, 0x490b, 0xa245, [...]uint8{0x5c, 0x7f, 0xa1, 0xf9, 0x86, 0x32})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}
	c.Check(path, DeepEquals, expected)

	var buf bytes.Buffer
	c.Check(path.Write(&buf), IsNil)
	c.Check(buf.Bytes(), DeepEquals, b)
}

func (s *dpSuite) TestDevicePathToStringUnrecognizedType(c *C) {
	b := DecodeHexString(c, "02ff1800000000000000000000000000564d42757300000001553400a2e5179b9108dd42b65380"+
		"b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656030208000000000004012a000f0000000028000000"+
		"0000000050030000000000dbfe3389532f0b49a2455c7fa1f986320202040434005c004500460049005c007500620075006e00740075005c0073"+
		"00680069006d007800360034002e0065006600690000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.ToString(0), Equals, "\\AcpiPath(255,000000000000000000000000564d427573000000)"+
		"\\HardwarePath(85,a2e5179b9108dd42b65380b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656)"+
		"\\Scsi(0x0,0x0)\\HD(15,GPT,8933fedb-2f53-490b-a245-5c7fa1f98632,0x2800,0x35000)\\\\EFI\\ubuntu\\shimx64.efi")
}

func (s *dpSuite) TestDevicePathToStringUnrecognizedTypeDisplayOnly(c *C) {
	b := DecodeHexString(c, "02ff1800000000000000000000000000564d42757300000001553400a2e5179b9108dd42b65380"+
		"b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656030208000000000004012a000f0000000028000000"+
		"0000000050030000000000dbfe3389532f0b49a2455c7fa1f986320202040434005c004500460049005c007500620075006e00740075005c0073"+
		"00680069006d007800360034002e0065006600690000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.ToString(DevicePathDisplayOnly), Equals, "\\AcpiPath(255,000000000000000000000000564d427573000000)"+
		"\\HardwarePath(85,a2e5179b9108dd42b65380b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656)"+
		"\\Scsi(0x0,0x0)\\HD(15,GPT,8933fedb-2f53-490b-a245-5c7fa1f98632)\\\\EFI\\ubuntu\\shimx64.efi")
}

func (s *dpSuite) TestReadAndWriteDevicePathHyperV(c *C) {
	b := DecodeHexString(c, "02021800000000000000000000000000564d42757300000001043400a2e5179b9108dd42b65380"+
		"b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656030208000000000004012a000f0000000028000000"+
		"0000000050030000000000dbfe3389532f0b49a2455c7fa1f986320202040434005c004500460049005c007500620075006e00740075005c0073"+
		"00680069006d007800360034002e0065006600690000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.String(), Equals, "\\AcpiEx(VMBus,0,0x0)"+
		"\\VenHw(9b17e5a2-0891-42dd-b653-80b5c22809ba,d96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656)"+
		"\\Scsi(0x0,0x0)\\HD(15,GPT,8933fedb-2f53-490b-a245-5c7fa1f98632)\\\\EFI\\ubuntu\\shimx64.efi")

	expected := DevicePath{
		&ACPIExtendedDevicePathNode{HIDStr: "VMBus"},
		&VendorDevicePathNode{
			Type: HardwareDevicePath,
			GUID: MakeGUID(0x9b17e5a2, 0x0891, 0x42dd, 0xb653, [...]uint8{0x80, 0xb5, 0xc2, 0x28, 0x09, 0xba}),
			Data: DecodeHexString(c, "d96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656")},
		&SCSIDevicePathNode{
			PUN: 0,
			LUN: 0},
		&HardDriveDevicePathNode{
			PartitionNumber: 15,
			PartitionStart:  0x2800,
			PartitionSize:   0x35000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x8933fedb, 0x2f53, 0x490b, 0xa245, [...]uint8{0x5c, 0x7f, 0xa1, 0xf9, 0x86, 0x32})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}
	c.Check(path, DeepEquals, expected)

	var buf bytes.Buffer
	c.Check(path.Write(&buf), IsNil)
	c.Check(buf.Bytes(), DeepEquals, b)
}

func (s *dpSuite) TestDevicePathToStringHyperV(c *C) {
	b := DecodeHexString(c, "02021800000000000000000000000000564d42757300000001043400a2e5179b9108dd42b65380"+
		"b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656030208000000000004012a000f0000000028000000"+
		"0000000050030000000000dbfe3389532f0b49a2455c7fa1f986320202040434005c004500460049005c007500620075006e00740075005c0073"+
		"00680069006d007800360034002e0065006600690000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.ToString(0), Equals, "\\AcpiEx(0,0,0x0,VMBus,<nil>,<nil>)"+
		"\\VenHw(9b17e5a2-0891-42dd-b653-80b5c22809ba,d96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656)"+
		"\\Scsi(0x0,0x0)\\HD(15,GPT,8933fedb-2f53-490b-a245-5c7fa1f98632,0x2800,0x35000)\\\\EFI\\ubuntu\\shimx64.efi")
}

func (s *dpSuite) TestDevicePathToStringHyperVDisplayOnly(c *C) {
	b := DecodeHexString(c, "02021800000000000000000000000000564d42757300000001043400a2e5179b9108dd42b65380"+
		"b5c22809bad96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656030208000000000004012a000f0000000028000000"+
		"0000000050030000000000dbfe3389532f0b49a2455c7fa1f986320202040434005c004500460049005c007500620075006e00740075005c0073"+
		"00680069006d007800360034002e0065006600690000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.ToString(DevicePathDisplayOnly), Equals, "\\AcpiEx(VMBus,0,0x0)"+
		"\\VenHw(9b17e5a2-0891-42dd-b653-80b5c22809ba,d96361baa104294db60572e2ffb1dc7f5a80e5d23e369c4494ed50c0a0cd8656)"+
		"\\Scsi(0x0,0x0)\\HD(15,GPT,8933fedb-2f53-490b-a245-5c7fa1f98632)\\\\EFI\\ubuntu\\shimx64.efi")
}

func (s *dpSuite) TestReadAndWriteDevicePathPXE(c *C) {
	b := DecodeHexString(c, "02010c00d041030a01000000010106000000010106000000030b2500a0369ff5a7a80000000000"+
		"00000000000000000000000000000000000000000001030c1b0000000000000000000000000000000000000000000000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.String(), Equals, "\\PciRoot(0x1)\\Pci(0x0,0x0)\\Pci(0x0,0x0)\\MacAddr(a0369ff5a7a8,0x1)\\IPv4(0:0:0:0)")

	expected := DevicePath{
		&ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x1,
		},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0,
		},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0,
		},
		&MACAddrDevicePathNode{
			MACAddress: EUI48{0xa0, 0x36, 0x9f, 0xf5, 0xa7, 0xa8},
			IfType:     NetworkInterfaceTypeEthernet,
		},
		&IPv4DevicePathNode{
			LocalAddress:       IPv4Address{0, 0, 0, 0},
			RemoteAddress:      IPv4Address{0, 0, 0, 0},
			LocalPort:          0,
			RemotePort:         0,
			Protocol:           0,
			LocalAddressOrigin: IPv4AddressDHCPAssigned,
			GatewayAddress:     IPv4Address{0, 0, 0, 0},
			SubnetMask:         IPv4Address{0, 0, 0, 0},
		},
	}
	c.Check(path, DeepEquals, expected)

	var buf bytes.Buffer
	c.Check(path.Write(&buf), IsNil)
	c.Check(buf.Bytes(), DeepEquals, b)
}

func (s *dpSuite) TestDevicePathToStringPXE(c *C) {
	b := DecodeHexString(c, "02010c00d041030a01000000010106000000010106000000030b2500a0369ff5a7a80000000000"+
		"00000000000000000000000000000000000000000001030c1b0000000000000000000000000000000000000000000000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.ToString(0), Equals, "\\PciRoot(0x1)\\Pci(0x0,0x0)\\Pci(0x0,0x0)\\MacAddr(a0369ff5a7a8,0x1)\\IPv4(0:0:0:0,0x0,DHCP,0:0:0:0,0:0:0:0,0:0:0:0)")
}

func (s *dpSuite) TestDevicePathToStringPXEDisplayOnly(c *C) {
	b := DecodeHexString(c, "02010c00d041030a01000000010106000000010106000000030b2500a0369ff5a7a80000000000"+
		"00000000000000000000000000000000000000000001030c1b0000000000000000000000000000000000000000000000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.ToString(DevicePathDisplayOnly), Equals, "\\PciRoot(0x1)\\Pci(0x0,0x0)\\Pci(0x0,0x0)\\MacAddr(a0369ff5a7a8,0x1)\\IPv4(0:0:0:0)")
}

func (s *dpSuite) TestReadAndWriteDevicePathSAS(c *C) {
	b := DecodeHexString(c, "02010c00d041030a02000000010106000000010106000000030a2c00b4dd87d48b00d911afdc00"+
		"1083ffca4d00000000176c41005800035000000000000000007100010004012a000100000000080000000000000098210000000000cafc"+
		"7cae5dd5b743a500283fe1fb3f920202040434005c004500460049005c005500420055004e00540055005c005300480049004d00580036"+
		"0034002e0045004600490000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.String(), Equals, "\\PciRoot(0x2)\\Pci(0x0,0x0)\\Pci(0x0,0x0)"+
		"\\SAS(0x5003005800416c17,0x0,0x1,SATA,External,Expanded,0,0x0)\\HD(1,GPT,ae7cfcca-d55d-43b7-a500-283fe1fb3f92)\\\\EFI\\UBUNTU\\SHIMX64.EFI")

	expected := DevicePath{
		&ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x2,
		},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0,
		},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0,
		},
		&VendorDevicePathNode{
			Type: MessagingDevicePath,
			GUID: MakeGUID(0xd487ddb4, 0x008b, 0x11d9, 0xafdc, [...]uint8{0x00, 0x10, 0x83, 0xff, 0xca, 0x4d}),
			Data: DecodeHexString(c, "00000000176c410058000350000000000000000071000100")},
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x219800,
			Signature:       GUIDHardDriveSignature(MakeGUID(0xae7cfcca, 0xd55d, 0x43b7, 0xa500, [...]uint8{0x28, 0x3f, 0xe1, 0xfb, 0x3f, 0x92})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\UBUNTU\\SHIMX64.EFI")}
	c.Check(path, DeepEquals, expected)

	var buf bytes.Buffer
	c.Check(path.Write(&buf), IsNil)
	c.Check(buf.Bytes(), DeepEquals, b)
}

func (s *dpSuite) TestDevicePathToStringSAS(c *C) {
	b := DecodeHexString(c, "02010c00d041030a02000000010106000000010106000000030a2c00b4dd87d48b00d911afdc00"+
		"1083ffca4d00000000176c41005800035000000000000000007100010004012a000100000000080000000000000098210000000000cafc"+
		"7cae5dd5b743a500283fe1fb3f920202040434005c004500460049005c005500420055004e00540055005c005300480049004d00580036"+
		"0034002e0045004600490000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.ToString(0), Equals, "\\PciRoot(0x2)\\Pci(0x0,0x0)\\Pci(0x0,0x0)"+
		"\\VenMsg(d487ddb4-008b-11d9-afdc-001083ffca4d,00000000176c410058000350000000000000000071000100)"+
		"\\HD(1,GPT,ae7cfcca-d55d-43b7-a500-283fe1fb3f92,0x800,0x219800)\\\\EFI\\UBUNTU\\SHIMX64.EFI")
}

func (s *dpSuite) TestDevicePathToStringSASDisplayOnly(c *C) {
	b := DecodeHexString(c, "02010c00d041030a02000000010106000000010106000000030a2c00b4dd87d48b00d911afdc00"+
		"1083ffca4d00000000176c41005800035000000000000000007100010004012a000100000000080000000000000098210000000000cafc"+
		"7cae5dd5b743a500283fe1fb3f920202040434005c004500460049005c005500420055004e00540055005c005300480049004d00580036"+
		"0034002e0045004600490000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.ToString(DevicePathDisplayOnly), Equals, "\\PciRoot(0x2)\\Pci(0x0,0x0)\\Pci(0x0,0x0)"+
		"\\VenMsg(d487ddb4-008b-11d9-afdc-001083ffca4d,00000000176c410058000350000000000000000071000100)"+
		"\\HD(1,GPT,ae7cfcca-d55d-43b7-a500-283fe1fb3f92)\\\\EFI\\UBUNTU\\SHIMX64.EFI")
}

func (s *dpSuite) TestDevicePathToStringSASAllowShortcuts(c *C) {
	b := DecodeHexString(c, "02010c00d041030a02000000010106000000010106000000030a2c00b4dd87d48b00d911afdc00"+
		"1083ffca4d00000000176c41005800035000000000000000007100010004012a000100000000080000000000000098210000000000cafc"+
		"7cae5dd5b743a500283fe1fb3f920202040434005c004500460049005c005500420055004e00540055005c005300480049004d00580036"+
		"0034002e0045004600490000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.ToString(DevicePathAllowShortcuts), Equals, "\\PciRoot(0x2)\\Pci(0x0,0x0)\\Pci(0x0,0x0)"+
		"\\SAS(0x5003005800416c17,0x0,0x1,SATA,External,Expanded,0,0x0)"+
		"\\HD(1,GPT,ae7cfcca-d55d-43b7-a500-283fe1fb3f92,0x800,0x219800)\\\\EFI\\UBUNTU\\SHIMX64.EFI")
}

func (s *dpSuite) TestDevicePathToStringSASDisplayOnlyAndAllowShortcuts(c *C) {
	b := DecodeHexString(c, "02010c00d041030a02000000010106000000010106000000030a2c00b4dd87d48b00d911afdc00"+
		"1083ffca4d00000000176c41005800035000000000000000007100010004012a000100000000080000000000000098210000000000cafc"+
		"7cae5dd5b743a500283fe1fb3f920202040434005c004500460049005c005500420055004e00540055005c005300480049004d00580036"+
		"0034002e0045004600490000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(b))
	c.Assert(err, IsNil)
	c.Check(path.ToString(DevicePathDisplayOnly|DevicePathAllowShortcuts), Equals, "\\PciRoot(0x2)\\Pci(0x0,0x0)\\Pci(0x0,0x0)"+
		"\\SAS(0x5003005800416c17,0x0,0x1,SATA,External,Expanded,0,0x0)\\HD(1,GPT,ae7cfcca-d55d-43b7-a500-283fe1fb3f92)\\\\EFI\\UBUNTU\\SHIMX64.EFI")
}

func (s *dpSuite) TestDevicePathBytes(c *C) {
	src := DecodeHexString(c, "02010c00d041030a0000000001010600001d0101060000000317100001000000000000000000000004012a000100"+
		"0000000800000000000000001000000000007b94de66b2fd2545b75230d66bb2b9600202040434005c004500460049005c007500620075006e00740075005c007"+
		"300680069006d007800360034002e0065006600690000007fff0400")
	path, err := ReadDevicePath(bytes.NewReader(src))
	c.Assert(err, IsNil)

	b, err := path.Bytes()
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, src)
}

func (s *dpSuite) TestNewFilePathDevicePathNode(c *C) {
	p := NewFilePathDevicePathNode("EFI/ubuntu/shimx64.efi")
	c.Check(p, Equals, FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi"))
}

func (s *dpSuite) TestNewFilePathDevicePathNode2(c *C) {
	p := NewFilePathDevicePathNode("/EFI/ubuntu/shimx64.efi")
	c.Check(p, Equals, FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi"))
}

func (s *dpSuite) TestEISAID(c *C) {
	id := EISAID(0xa5a541d0)
	c.Check(id.Vendor(), Equals, "PNP")
	c.Check(id.Product(), DeepEquals, uint16(0xa5a5))
}

func (s *dpSuite) TestNewEISAID(c *C) {
	id, err := NewEISAID("PNP", 0x0a08)
	c.Check(err, IsNil)
	c.Check(id, Equals, EISAID(0x0a0841d0))
}

type testNewHardDriveDevicePathNodeFromDeviceData struct {
	part     int
	expected *HardDriveDevicePathNode
}

func (s *dpSuite) testNewHardDriveDevicePathNodeFromDevice(c *C, data *testNewHardDriveDevicePathNodeFromDeviceData) {
	f, err := os.Open("testdata/partitiontables/valid")
	c.Assert(err, IsNil)
	defer f.Close()

	fi, err := f.Stat()
	c.Assert(err, IsNil)

	node, err := NewHardDriveDevicePathNodeFromDevice(f, fi.Size(), 512, data.part)
	c.Assert(err, IsNil)
	c.Check(node, DeepEquals, data.expected)
}

func (s *dpSuite) TestNewHardDriveDevicePathNodeFromDevice1(c *C) {
	s.testNewHardDriveDevicePathNodeFromDevice(c, &testNewHardDriveDevicePathNodeFromDeviceData{
		part: 1,
		expected: &HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x22,
			PartitionSize:   0x12c,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x506fddfc, 0xad5e, 0x4548, 0xb7dd, [...]uint8{0xe7, 0x73, 0x62, 0x17, 0x5c, 0x31})),
			MBRType:         GPT}})
}

func (s *dpSuite) TestNewHardDriveDevicePathNodeFromDevice2(c *C) {
	s.testNewHardDriveDevicePathNodeFromDevice(c, &testNewHardDriveDevicePathNodeFromDeviceData{
		part: 3,
		expected: &HardDriveDevicePathNode{
			PartitionNumber: 3,
			PartitionStart:  0x1b2,
			PartitionSize:   0x2d,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x94da1fcc, 0x1c0f, 0x5645, 0xabf9, [...]uint8{0xff, 0x9a, 0xc4, 0x68, 0x24, 0x2d})),
			MBRType:         GPT}})
}

type testNewHardDriveDevicePathNodeFromDeviceErrorData struct {
	path string
	part int
}

func (s *dpSuite) testNewHardDriveDevicePathNodeFromDeviceError(c *C, data *testNewHardDriveDevicePathNodeFromDeviceErrorData) error {
	f, err := os.Open(data.path)
	c.Assert(err, IsNil)
	defer f.Close()

	fi, err := f.Stat()
	c.Assert(err, IsNil)

	_, err = NewHardDriveDevicePathNodeFromDevice(f, fi.Size(), 512, data.part)
	return err
}

func (s *dpSuite) TestNewHardDriveDevicePathNodeFromDeviceInvalidPart1(c *C) {
	c.Check(s.testNewHardDriveDevicePathNodeFromDeviceError(c, &testNewHardDriveDevicePathNodeFromDeviceErrorData{
		path: "testdata/partitiontables/valid",
		part: 0}), ErrorMatches, "invalid partition number")
}

func (s *dpSuite) TestNewHardDriveDevicePathNodeFromDeviceInvalidPart2(c *C) {
	c.Check(s.testNewHardDriveDevicePathNodeFromDeviceError(c, &testNewHardDriveDevicePathNodeFromDeviceErrorData{
		path: "testdata/partitiontables/valid",
		part: 300}), ErrorMatches, "invalid partition number 300: device only has 128 partitions")
}

func (s *dpSuite) TestNewHardDriveDevicePathNodeFromDeviceInvalidPart3(c *C) {
	c.Check(s.testNewHardDriveDevicePathNodeFromDeviceError(c, &testNewHardDriveDevicePathNodeFromDeviceErrorData{
		path: "testdata/partitiontables/valid",
		part: 5}), ErrorMatches, "requested partition is unused")
}

func (s *dpSuite) TestNewHardDriveDevicePathNodeFromDeviceInvalidHeader(c *C) {
	c.Check(s.testNewHardDriveDevicePathNodeFromDeviceError(c, &testNewHardDriveDevicePathNodeFromDeviceErrorData{
		path: "testdata/partitiontables/invalid-primary-hdr-checksum",
		part: 1}), Equals, ErrCRCCheck)
}

func (s *dpSuite) TestNewHardDriveDevicePathNodeFromMBRDevice(c *C) {
	f, err := os.Open("testdata/partitiontables/mbr")
	c.Assert(err, IsNil)
	defer f.Close()

	fi, err := f.Stat()
	c.Assert(err, IsNil)

	node, err := NewHardDriveDevicePathNodeFromDevice(f, fi.Size(), 512, 1)
	c.Assert(err, IsNil)
	c.Check(node, DeepEquals, &HardDriveDevicePathNode{
		PartitionNumber: 1,
		PartitionStart:  2048,
		PartitionSize:   19922944,
		Signature:       MBRHardDriveSignature(0xa773bf3f),
		MBRType:         LegacyMBR})
}

func (s *dpSuite) TestDevicePathMatchesFull(c *C) {
	path := DevicePath{
		&ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x0},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x1d},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0},
		&NVMENamespaceDevicePathNode{
			NamespaceID:   0x1,
			NamespaceUUID: zeroEUI64},
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}
	c.Check(path.Matches(path), Equals, DevicePathFullMatch)
}

func (s *dpSuite) TestDevicePathMatchesShortHD(c *C) {
	path := DevicePath{
		&ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x0},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x1d},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0},
		&NVMENamespaceDevicePathNode{
			NamespaceID:   0x1,
			NamespaceUUID: zeroEUI64},
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}

	hdPath := DevicePath{
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}
	c.Check(path.Matches(hdPath), Equals, DevicePathShortFormHDMatch)
}

func (s *dpSuite) TestDevicePathMatchesShortFile(c *C) {
	path := DevicePath{
		&ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x0},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x1d},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0},
		&NVMENamespaceDevicePathNode{
			NamespaceID:   0x1,
			NamespaceUUID: zeroEUI64},
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}

	filePath := DevicePath{
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}
	c.Check(path.Matches(filePath), Equals, DevicePathShortFormFileMatch)
}

func (s *dpSuite) TestDevicePathMatchesShortFileSwapped(c *C) {
	path := DevicePath{
		&ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x0},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x1d},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0},
		&NVMENamespaceDevicePathNode{
			NamespaceID:   0x1,
			NamespaceUUID: zeroEUI64},
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}

	filePath := DevicePath{
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}
	c.Check(filePath.Matches(path), Equals, DevicePathShortFormFileMatch)
}

func (s *dpSuite) TestDevicePathMatchesEmpty(c *C) {
	p := DevicePath{}
	c.Check(p.Matches(DevicePath{}), Equals, DevicePathFullMatch)
}

func (s *dpSuite) TestDevicePathMatchesEmptyOtherNoMatch(c *C) {
	path := DevicePath{
		&ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x0},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x1d},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0},
		&NVMENamespaceDevicePathNode{
			NamespaceID:   0x1,
			NamespaceUUID: zeroEUI64},
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}
	c.Check(path.Matches(DevicePath{}), Equals, DevicePathNoMatch)
}

func (s *dpSuite) TestDevicePathMatchesFullNoMatch(c *C) {
	path := DevicePath{
		&ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x0},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x1d},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0},
		&NVMENamespaceDevicePathNode{
			NamespaceID:   0x1,
			NamespaceUUID: zeroEUI64},
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}

	other := DevicePath{
		&ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x0},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x1d},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x2},
		&NVMENamespaceDevicePathNode{
			NamespaceID:   0x1,
			NamespaceUUID: zeroEUI64},
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}
	c.Check(path.Matches(other), Equals, DevicePathNoMatch)
}

func (s *dpSuite) TestDevicePathMatchesShortHDNoMatch(c *C) {
	path := DevicePath{
		&ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x0},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x1d},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0},
		&NVMENamespaceDevicePathNode{
			NamespaceID:   0x1,
			NamespaceUUID: zeroEUI64},
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x31, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}

	hdPath := DevicePath{
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}
	c.Check(path.Matches(hdPath), Equals, DevicePathNoMatch)
}

func (s *dpSuite) TestDevicePathMatchesShortFileNoMatch(c *C) {
	path := DevicePath{
		&ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x0},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x1d},
		&PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0},
		&NVMENamespaceDevicePathNode{
			NamespaceID:   0x1,
			NamespaceUUID: zeroEUI64},
		&HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
			MBRType:         GPT},
		FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}

	filePath := DevicePath{
		FilePathDevicePathNode("\\EFI\\ubuntu\\grubx64.efi")}
	c.Check(path.Matches(filePath), Equals, DevicePathNoMatch)
}
