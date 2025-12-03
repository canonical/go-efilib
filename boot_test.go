// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"bytes"
	"context"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-efilib"
)

type bootSuite struct {
	mockVars mockVars
	mockCtx  context.Context
}

func (s *bootSuite) SetUpTest(c *C) {
	s.mockVars = make(mockVars)
	s.mockCtx = WithVarsBackend(context.Background(), s.mockVars)
}

func (s *bootSuite) TearDownTest(c *C) {
	s.mockVars = nil
	s.mockCtx = context.Background()
}

var _ = Suite(&bootSuite{})

func (s *bootSuite) TestBootOptionSupportKeyCount3(c *C) {
	opt := BootOptionSupport(0x00000300)
	c.Check(opt.KeyCount(), Equals, uint8(3))
}

func (s *bootSuite) TestBootOptionSupportKeyCount2(c *C) {
	opt := BootOptionSupport(0x00000200)
	c.Check(opt.KeyCount(), Equals, uint8(2))
}

func (s *bootSuite) TestBootOptionSupportKeyCount0(c *C) {
	opt := BootOptionSupport(0x00000000)
	c.Check(opt.KeyCount(), Equals, uint8(0))
}

func (s *bootSuite) TestReadOSIndicationsSupportedVariable1(c *C) {
	s.mockVars.add("OsIndicationsSupported", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	opts, err := ReadOSIndicationsSupportedVariable(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(opts, Equals, OSIndications(OSIndicationFileCapsuleDeliverySupported|OSIndicationCapsuleResultVarSupported))
}

func (s *bootSuite) TestReadOSIndicationsSupportedVariable2(c *C) {
	s.mockVars.add("OsIndicationsSupported", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	opts, err := ReadOSIndicationsSupportedVariable(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(opts, Equals, OSIndications(OSIndicationBootToFWUI|OSIndicationFileCapsuleDeliverySupported|OSIndicationCapsuleResultVarSupported|OSIndicationStartOSRecovery|OSIndicationStartPlatformRecovery))
}

func (s *bootSuite) TestReadOSIndicationsSupportedVariableWrongSize(c *C) {
	s.mockVars.add("OsIndicationsSupported", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	_, err := ReadOSIndicationsSupportedVariable(s.mockCtx)
	c.Check(err, ErrorMatches, `variable contents has an unexpected size \(7 bytes\)`)
}

func (s *bootSuite) TestWriteOSIndicationsVariable1(c *C) {
	c.Check(WriteOSIndicationsVariable(s.mockCtx, OSIndicationBootToFWUI), IsNil)

	data, attrs, err := ReadVariable(s.mockCtx, "OsIndications", GlobalVariable)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess)
	c.Check(data, DeepEquals, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func (s *bootSuite) TestWriteOSIndicationsVariable2(c *C) {
	c.Check(WriteOSIndicationsVariable(s.mockCtx, OSIndicationStartPlatformRecovery), IsNil)

	data, attrs, err := ReadVariable(s.mockCtx, "OsIndications", GlobalVariable)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess)
	c.Check(data, DeepEquals, []byte{0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func (s *bootSuite) TestWriteOSIndicationsVariableInvalidValue(c *C) {
	err := WriteOSIndicationsVariable(s.mockCtx, OSIndicationTimestampRevocation)
	c.Check(err, ErrorMatches, `supplied value contains bits set that have no function`)

	_, _, err = ReadVariable(s.mockCtx, "OsIndications", GlobalVariable)
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *bootSuite) TestReadBootOptionSupportVariable1(c *C) {
	s.mockVars.add("BootOptionSupport", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x01, 0x03, 0x00, 0x00})

	opts, err := ReadBootOptionSupportVariable(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(opts, Equals, BootOptionSupport(BootOptionSupportKey|BootOptionSupportCount))
}

func (s *bootSuite) TestReadBootOptionSupportVariable2(c *C) {
	s.mockVars.add("BootOptionSupport", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x13, 0x03, 0x00, 0x00})

	opts, err := ReadBootOptionSupportVariable(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(opts, Equals, BootOptionSupport(BootOptionSupportKey|BootOptionSupportApp|BootOptionSupportSysPrep|BootOptionSupportCount))
}

func (s *bootSuite) TestReadBootOptionSupportVariableWrongSize(c *C) {
	s.mockVars.add("BootOptionSupport", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x01, 0x03, 0x00, 0x00, 0x00})

	_, err := ReadBootOptionSupportVariable(s.mockCtx)
	c.Check(err, ErrorMatches, `variable contents has an unexpected size \(5 bytes\)`)
}

func (s *bootSuite) TestFormatLoadOptionVariableNameBoot3(c *C) {
	c.Check(FormatLoadOptionVariableName(LoadOptionClassBoot, 3), Equals, "Boot0003")
}

func (s *bootSuite) TestFormatLoadOptionVariableNameBoot14(c *C) {
	c.Check(FormatLoadOptionVariableName(LoadOptionClassBoot, 14), Equals, "Boot000E")
}

func (s *bootSuite) TestFormatLoadOptionVariableNameDriver2(c *C) {
	c.Check(FormatLoadOptionVariableName(LoadOptionClassDriver, 2), Equals, "Driver0002")
}

func (s *bootSuite) TestScanLoadOptionVariableNameBoot3(c *C) {
	class, n, err := ScanLoadOptionVariableName("Boot0003")
	c.Check(err, IsNil)
	c.Check(class, Equals, LoadOptionClassBoot)
	c.Check(n, Equals, uint16(3))
}

func (s *bootSuite) TestScanLoadOptionVariableNameBootF(c *C) {
	class, n, err := ScanLoadOptionVariableName("Boot000F")
	c.Check(err, IsNil)
	c.Check(class, Equals, LoadOptionClassBoot)
	c.Check(n, Equals, uint16(15))
}

func (s *bootSuite) TestScanLoadOptionVariableNameDriver2(c *C) {
	class, n, err := ScanLoadOptionVariableName("Driver0002")
	c.Check(err, IsNil)
	c.Check(class, Equals, LoadOptionClassDriver)
	c.Check(n, Equals, uint16(2))
}

func (s *bootSuite) TestScanLoadOptionVariableNameSysPrep5(c *C) {
	class, n, err := ScanLoadOptionVariableName("SysPrep0005")
	c.Check(err, IsNil)
	c.Check(class, Equals, LoadOptionClassSysPrep)
	c.Check(n, Equals, uint16(5))
}

func (s *bootSuite) TestScanLoadOptionVariableNamePlatformRecovery1(c *C) {
	class, n, err := ScanLoadOptionVariableName("PlatformRecovery0001")
	c.Check(err, IsNil)
	c.Check(class, Equals, LoadOptionClassPlatformRecovery)
	c.Check(n, Equals, uint16(1))
}

func (s *bootSuite) TestScanLoadOptionVariableNameTooShort(c *C) {
	_, _, err := ScanLoadOptionVariableName("001")
	c.Check(err, ErrorMatches, `name too short`)
}

func (s *bootSuite) TestScanLoadOptionVariableInvalidClass(c *C) {
	_, _, err := ScanLoadOptionVariableName("Foo0001")
	c.Check(err, ErrorMatches, `invalid class "Foo"`)
}

func (s *bootSuite) TestScanLoadOptionVariableInvalidNumber(c *C) {
	_, _, err := ScanLoadOptionVariableName("Boot000e")
	c.Check(err, ErrorMatches, `invalid number "000e"`)
}

func (s *bootSuite) TestReadLoadOrderVariableBoot(c *C) {
	s.mockVars.add("BootOrder", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00, 0x01, 0x00, 0x02, 0x00})

	order, err := ReadLoadOrderVariable(s.mockCtx, LoadOptionClassBoot)
	c.Check(err, IsNil)
	c.Check(order, DeepEquals, []uint16{3, 1, 2})
}

func (s *bootSuite) TestReadLoadOrderVariableSysPrep(c *C) {
	s.mockVars.add("SysPrepOrder", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x04, 0x00, 0x05, 0x00, 0x03, 0x00})

	order, err := ReadLoadOrderVariable(s.mockCtx, LoadOptionClassSysPrep)
	c.Check(err, IsNil)
	c.Check(order, DeepEquals, []uint16{4, 5, 3})
}

func (s *bootSuite) TestReadLoadOrderVariableDriver(c *C) {
	s.mockVars.add("DriverOrder", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00, 0x01, 0x00, 0x02, 0x00})

	order, err := ReadLoadOrderVariable(s.mockCtx, LoadOptionClassDriver)
	c.Check(err, IsNil)
	c.Check(order, DeepEquals, []uint16{3, 1, 2})
}

func (s *bootSuite) TestReadLoadOrderVariableWrongClass(c *C) {
	_, err := ReadLoadOrderVariable(s.mockCtx, LoadOptionClassPlatformRecovery)
	c.Check(err, ErrorMatches, `invalid class \"PlatformRecovery\": only suitable for Driver, SysPrep or Boot`)
}

func (s *bootSuite) TestReadLoadOrderVariableOddSize(c *C) {
	s.mockVars.add("BootOrder", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00, 0x01, 0x00, 0x02})

	_, err := ReadLoadOrderVariable(s.mockCtx, LoadOptionClassBoot)
	c.Check(err, ErrorMatches, `BootOrder variable contents has odd size \(5 bytes\)`)
}

func (s *bootSuite) TestWriteLoadOrderVariableBoot(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "ubuntu",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0003", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	opt = &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "Linux Firmware Updater",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")},
		OptionalData: DecodeHexString(c, "5c00660077007500700064007800360034002e006500660069000000")}
	w = new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	c.Check(WriteLoadOrderVariable(s.mockCtx, LoadOptionClassBoot, []uint16{3, 2}), IsNil)

	data, attrs, err := ReadVariable(s.mockCtx, "BootOrder", GlobalVariable)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess)
	c.Check(data, DeepEquals, []byte{0x03, 0x00, 0x02, 0x00})
}

func (s *bootSuite) TestWriteLoadOrderVariableSysPrep(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "System preparation application",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\sysprepx64.efi")}}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("SysPrep0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	c.Check(WriteLoadOrderVariable(s.mockCtx, LoadOptionClassSysPrep, []uint16{2}), IsNil)

	data, attrs, err := ReadVariable(s.mockCtx, "SysPrepOrder", GlobalVariable)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess)
	c.Check(data, DeepEquals, []byte{0x02, 0x00})
}

func (s *bootSuite) TestWriteLoadOrderVariableMissingOption(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "ubuntu",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0003", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	err := WriteLoadOrderVariable(s.mockCtx, LoadOptionClassBoot, []uint16{3, 2})
	c.Check(err, ErrorMatches, `invalid load option 2: variable does not exist`)

	_, _, err = ReadVariable(s.mockCtx, "BootOrder", GlobalVariable)
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *bootSuite) TestWriteLoadOrderVariableWrongClass(c *C) {
	err := WriteLoadOrderVariable(s.mockCtx, LoadOptionClassPlatformRecovery, []uint16{1})
	c.Check(err, ErrorMatches, `invalid class \"PlatformRecovery\": only suitable for Driver, SysPrep or Boot`)

	_, _, err = ReadVariable(s.mockCtx, "PlatformRecoveryOrder", GlobalVariable)
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *bootSuite) TestReadLoadOptionVariableBoot3(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "ubuntu",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0003", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	expectedOpt, err := ReadLoadOption(w)
	c.Assert(err, IsNil)

	opt, err = ReadLoadOptionVariable(s.mockCtx, LoadOptionClassBoot, 3)
	c.Assert(err, IsNil)
	c.Check(opt, DeepEquals, expectedOpt)
}

func (s *bootSuite) TestReadLoadOptionVariableBoot2(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "Linux Firmware Updater",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")},
		OptionalData: DecodeHexString(c, "5c00660077007500700064007800360034002e006500660069000000")}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	expectedOpt, err := ReadLoadOption(w)
	c.Assert(err, IsNil)

	opt, err = ReadLoadOptionVariable(s.mockCtx, LoadOptionClassBoot, 2)
	c.Assert(err, IsNil)
	c.Check(opt, DeepEquals, expectedOpt)
}

func (s *bootSuite) TestReadLoadOptionVariableBoot15(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "ubuntu",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot000F", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	expectedOpt, err := ReadLoadOption(w)
	c.Assert(err, IsNil)

	opt, err = ReadLoadOptionVariable(s.mockCtx, LoadOptionClassBoot, 15)
	c.Assert(err, IsNil)
	c.Check(opt, DeepEquals, expectedOpt)
}

func (s *bootSuite) TestReadLoadOptionVariableSysPrep2(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "System preparation application",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\sysprepx64.efi")}}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("SysPrep0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	expectedOpt, err := ReadLoadOption(w)
	c.Assert(err, IsNil)

	opt, err = ReadLoadOptionVariable(s.mockCtx, LoadOptionClassSysPrep, 2)
	c.Assert(err, IsNil)
	c.Check(opt, DeepEquals, expectedOpt)
}

func (s *bootSuite) TestReadLoadOptionVariableInvalid(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "ubuntu"}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	// add an option with the path termination truncated
	s.mockVars.add("Boot0001", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes()[:len(w.Bytes())-4])

	_, err := ReadLoadOptionVariable(s.mockCtx, LoadOptionClassBoot, 1)
	c.Assert(err, ErrorMatches, `cannot decode LoadOption: unexpected EOF`)
}

func (s *bootSuite) TestWriteLoadOptionVariableBoot3(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "ubuntu",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}

	c.Check(WriteLoadOptionVariable(s.mockCtx, LoadOptionClassBoot, 3, opt), IsNil)

	expectedData := new(bytes.Buffer)
	c.Assert(opt.Write(expectedData), IsNil)

	data, attrs, err := ReadVariable(s.mockCtx, "Boot0003", GlobalVariable)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess)
	c.Check(data, DeepEquals, expectedData.Bytes())
}

func (s *bootSuite) TestWriteLoadOptionVariableBoot2(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "Linux Firmware Updater",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")},
		OptionalData: DecodeHexString(c, "5c00660077007500700064007800360034002e006500660069000000")}

	c.Check(WriteLoadOptionVariable(s.mockCtx, LoadOptionClassBoot, 2, opt), IsNil)

	expectedData := new(bytes.Buffer)
	c.Assert(opt.Write(expectedData), IsNil)

	data, attrs, err := ReadVariable(s.mockCtx, "Boot0002", GlobalVariable)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess)
	c.Check(data, DeepEquals, expectedData.Bytes())
}

func (s *bootSuite) TestWriteLoadOptionVariableBoot15(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "ubuntu",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}

	c.Check(WriteLoadOptionVariable(s.mockCtx, LoadOptionClassBoot, 15, opt), IsNil)

	expectedData := new(bytes.Buffer)
	c.Assert(opt.Write(expectedData), IsNil)

	data, attrs, err := ReadVariable(s.mockCtx, "Boot000F", GlobalVariable)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess)
	c.Check(data, DeepEquals, expectedData.Bytes())
}

func (s *bootSuite) TestWriteLoadOptionVariableSysPrep2(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "System preparation application",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\sysprepx64.efi")}}

	c.Check(WriteLoadOptionVariable(s.mockCtx, LoadOptionClassSysPrep, 2, opt), IsNil)

	expectedData := new(bytes.Buffer)
	c.Assert(opt.Write(expectedData), IsNil)

	data, attrs, err := ReadVariable(s.mockCtx, "SysPrep0002", GlobalVariable)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess)
	c.Check(data, DeepEquals, expectedData.Bytes())
}

func (s *bootSuite) TestWriteLoadOptionVariableWrongClass(c *C) {
	err := WriteLoadOptionVariable(s.mockCtx, LoadOptionClassPlatformRecovery, 1, nil)
	c.Check(err, ErrorMatches, `invalid class \"PlatformRecovery\": only suitable for Driver, SysPrep or Boot`)

	_, _, err = ReadVariable(s.mockCtx, "PlatformRecovery0001", GlobalVariable)
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *bootSuite) TestDeleteLoadOptionVariableBoot3(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "ubuntu",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0003", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	c.Check(DeleteLoadOptionVariable(s.mockCtx, LoadOptionClassBoot, 3), IsNil)

	_, _, err := ReadVariable(s.mockCtx, "Boot0003", GlobalVariable)
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *bootSuite) TestDeleteLoadOptionVariableSysPrep2(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "System preparation application",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\sysprepx64.efi")}}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("SysPrep0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	c.Check(DeleteLoadOptionVariable(s.mockCtx, LoadOptionClassSysPrep, 2), IsNil)

	_, _, err := ReadVariable(s.mockCtx, "SysPrep0002", GlobalVariable)
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *bootSuite) TestDeleteLoadOptionVariableWrongClass(c *C) {
	err := DeleteLoadOptionVariable(s.mockCtx, LoadOptionClassPlatformRecovery, 1)
	c.Check(err, ErrorMatches, `invalid class \"PlatformRecovery\": only suitable for Driver, SysPrep or Boot`)
}

func (s *bootSuite) TestDeleteLoadOptionVariableNotExist(c *C) {
	c.Check(DeleteLoadOptionVariable(s.mockCtx, LoadOptionClassBoot, 3), IsNil)
}

func (s *bootSuite) TestListLoadOptionNumbersBoot(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "ubuntu",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0003", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	opt = &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "Linux Firmware Updater",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")},
		OptionalData: DecodeHexString(c, "5c00660077007500700064007800360034002e006500660069000000")}
	w = new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x01})
	s.mockVars.add("dbx", ImageSecurityDatabaseGuid, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	s.mockVars.add("Boot01", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	opts, err := ListLoadOptionNumbers(s.mockCtx, LoadOptionClassBoot)
	c.Check(err, IsNil)
	c.Check(opts, DeepEquals, []uint16{2, 3})
}

func (s *bootSuite) TestListLoadOptionNumbersSysPrep(c *C) {
	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "System preparation application",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\sysprepx64.efi")}}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("SysPrep0001", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	opt = &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "System preparation application 2",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\Dell\\sysprepx64.efi")}}
	w = new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("SysPrep0005", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x01})
	s.mockVars.add("dbx", ImageSecurityDatabaseGuid, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	s.mockVars.add("SysPrep02", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())
	s.mockVars.add("Boot0003", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	opts, err := ListLoadOptionNumbers(s.mockCtx, LoadOptionClassSysPrep)
	c.Check(err, IsNil)
	c.Check(opts, DeepEquals, []uint16{1, 5})
}

func (s *bootSuite) TestNextAvailableLoadOptionNumberBoot1(c *C) {
	s.mockVars.add("Boot0000", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	s.mockVars.add("Boot0001", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	s.mockVars.add("Boot0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)

	next, err := NextAvailableLoadOptionNumber(s.mockCtx, LoadOptionClassBoot)
	c.Check(err, IsNil)
	c.Check(next, Equals, uint16(3))
}

func (s *bootSuite) TestNextAvailableLoadOptionNumberBoot2(c *C) {
	s.mockVars.add("Boot0000", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	s.mockVars.add("Boot0001", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	s.mockVars.add("Boot0003", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)

	next, err := NextAvailableLoadOptionNumber(s.mockCtx, LoadOptionClassBoot)
	c.Check(err, IsNil)
	c.Check(next, Equals, uint16(2))
}

func (s *bootSuite) TestNextAvailableLoadOptionNumberBoot3(c *C) {
	s.mockVars.add("Boot0001", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	s.mockVars.add("Boot0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	s.mockVars.add("Boot0003", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	s.mockVars.add("Boot0004", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)

	next, err := NextAvailableLoadOptionNumber(s.mockCtx, LoadOptionClassBoot)
	c.Check(err, IsNil)
	c.Check(next, Equals, uint16(0))
}

func (s *bootSuite) TestNextAvailableLoadOptionNumberSysPrep(c *C) {
	s.mockVars.add("SysPrep0000", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	s.mockVars.add("SysPrep0001", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	s.mockVars.add("SysPrep0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	s.mockVars.add("Boot0003", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)

	next, err := NextAvailableLoadOptionNumber(s.mockCtx, LoadOptionClassSysPrep)
	c.Check(err, IsNil)
	c.Check(next, Equals, uint16(3))
}

func (s *bootSuite) TestNextAvailableLoadOptionNumberInvalidClass(c *C) {
	_, err := NextAvailableLoadOptionNumber(s.mockCtx, LoadOptionClassPlatformRecovery)
	c.Check(err, ErrorMatches, `invalid class \"PlatformRecovery\": only suitable for Driver, SysPrep or Boot`)
}

func (s *bootSuite) TestReadBootNextVariable2(c *C) {
	s.mockVars.add("BootNext", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x02, 0x00})

	next, err := ReadBootNextVariable(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(next, Equals, uint16(2))
}

func (s *bootSuite) TestReadBootNextVariable3(c *C) {
	s.mockVars.add("BootNext", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00})

	next, err := ReadBootNextVariable(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(next, Equals, uint16(3))
}

func (s *bootSuite) TestReadBootNextVariableWrongSize(c *C) {
	s.mockVars.add("BootNext", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x02})

	_, err := ReadBootNextVariable(s.mockCtx)
	c.Check(err, ErrorMatches, `BootNext variable contents has the wrong size \(1 bytes\)`)
}

func (s *bootSuite) TestWriteBootNextVariable(c *C) {
	opt := &LoadOption{
		Attributes:  1,
		Description: "Linux Firmware Updater",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")},
		OptionalData: DecodeHexString(c, "5c00660077007500700064007800360034002e006500660069000000")}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	c.Check(WriteBootNextVariable(s.mockCtx, 2), IsNil)

	data, attrs, err := ReadVariable(s.mockCtx, "BootNext", GlobalVariable)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess)
	c.Check(data, DeepEquals, []byte{0x02, 0x00})
}

func (s *bootSuite) TestWriteBootNextVariableMissingOpt(c *C) {
	opt := &LoadOption{
		Attributes:  1,
		Description: "Linux Firmware Updater",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")},
		OptionalData: DecodeHexString(c, "5c00660077007500700064007800360034002e006500660069000000")}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	err := WriteBootNextVariable(s.mockCtx, 1)
	c.Check(err, ErrorMatches, `invalid load option 1: variable does not exist`)

	_, _, err = ReadVariable(s.mockCtx, "BootNext", GlobalVariable)
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *bootSuite) TestDeleteBootNextVariable(c *C) {
	s.mockVars.add("BootNext", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00})

	c.Check(DeleteBootNextVariable(s.mockCtx), IsNil)

	_, _, err := ReadVariable(s.mockCtx, "BootNext", GlobalVariable)
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *bootSuite) TestDeleteBootNextVariableNotExist(c *C) {
	c.Check(DeleteBootNextVariable(s.mockCtx), IsNil)
}

func (s *bootSuite) TestReadBootNextLoadOptionVariable2(c *C) {
	s.mockVars.add("BootNext", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x02, 0x00})

	opt := &LoadOption{
		Attributes:  1,
		Description: "Linux Firmware Updater",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")},
		OptionalData: DecodeHexString(c, "5c00660077007500700064007800360034002e006500660069000000")}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	expectedOpt, err := ReadLoadOption(w)
	c.Assert(err, IsNil)

	opt, err = ReadBootNextLoadOptionVariable(s.mockCtx)
	c.Assert(err, IsNil)
	c.Check(opt, DeepEquals, expectedOpt)
}

func (s *bootSuite) TestReadBootNextLoadOptionVariable3(c *C) {
	s.mockVars.add("BootNext", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00})

	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "ubuntu",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}
	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0003", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	expectedOpt, err := ReadLoadOption(w)
	c.Assert(err, IsNil)

	opt, err = ReadBootNextLoadOptionVariable(s.mockCtx)
	c.Assert(err, IsNil)
	c.Check(opt, DeepEquals, expectedOpt)
}

func (s *bootSuite) TestReadBootNextLoadOptionDanglingOption(c *C) {
	s.mockVars.add("BootNext", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00})

	_, err := ReadBootNextLoadOptionVariable(s.mockCtx)
	c.Assert(err, Equals, ErrVarNotExist)
}

func (s *bootSuite) TestReadBootCurrentVariable3(c *C) {
	s.mockVars.add("BootCurrent", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00})

	next, err := ReadBootCurrentVariable(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(next, Equals, uint16(3))
}

func (s *bootSuite) TestReadBootCurrentVariable4(c *C) {
	s.mockVars.add("BootCurrent", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x04, 0x00})

	next, err := ReadBootCurrentVariable(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(next, Equals, uint16(4))
}

func (s *bootSuite) TestReadOrderedLoadOptionsBoot(c *C) {
	s.mockVars.add("BootOrder", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00, 0x01, 0x00, 0x02, 0x00})

	var expectedOpts []*LoadOption

	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "ubuntu",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}

	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0003", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	expectedOpt, err := ReadLoadOption(w)
	c.Assert(err, IsNil)
	expectedOpts = append(expectedOpts, expectedOpt)

	opt = &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "Linux Firmware Updater",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")},
		OptionalData: DecodeHexString(c, "5c00660077007500700064007800360034002e006500660069000000")}
	w = new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("Boot0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	expectedOpt, err = ReadLoadOption(w)
	c.Assert(err, IsNil)
	expectedOpts = append(expectedOpts, expectedOpt)

	opts, err := ReadOrderedLoadOptionVariables(s.mockCtx, LoadOptionClassBoot)
	c.Assert(err, IsNil)
	c.Check(opts, DeepEquals, expectedOpts)
}

func (s *bootSuite) TestReadOrderedLoadOptionsPlatformRecovery(c *C) {
	var expectedOpts []*LoadOption

	opt := &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "Dell Recovery 1",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\Dell\\recovery1.efi")}}

	w := new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("PlatformRecovery0001", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	expectedOpt, err := ReadLoadOption(w)
	c.Assert(err, IsNil)
	expectedOpts = append(expectedOpts, expectedOpt)

	opt = &LoadOption{
		Attributes:  LoadOptionActive,
		Description: "Dell Recovery 2",
		FilePath: DevicePath{
			&HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       GUIDHardDriveSignature(MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         GPT},
			FilePathDevicePathNode("\\EFI\\Dell\\recovery2.efi")}}
	w = new(bytes.Buffer)
	c.Check(opt.Write(w), IsNil)
	s.mockVars.add("PlatformRecovery0002", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, w.Bytes())

	expectedOpt, err = ReadLoadOption(w)
	c.Assert(err, IsNil)
	expectedOpts = append(expectedOpts, expectedOpt)

	opts, err := ReadOrderedLoadOptionVariables(s.mockCtx, LoadOptionClassPlatformRecovery)
	c.Assert(err, IsNil)
	c.Check(opts, DeepEquals, expectedOpts)
}
