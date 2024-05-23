// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"bytes"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-efilib"
)

type mockBootVarData struct {
	attrs VariableAttributes
	data  []byte
}

type mockBootVars map[GUID]map[string]mockBootVarData

func (v mockBootVars) Get(name string, guid GUID) (VariableAttributes, []byte, error) {
	if _, exists := v[guid]; !exists {
		return 0, nil, ErrVarNotExist
	}
	data, exists := v[guid][name]
	if !exists {
		return 0, nil, ErrVarNotExist
	}
	return data.attrs, data.data, nil
}

func (v mockBootVars) Set(name string, guid GUID, attrs VariableAttributes, data []byte) error {
	return ErrVarPermission
}

func (v mockBootVars) List() ([]VariableDescriptor, error) {
	var out []VariableDescriptor
	for guid := range v {
		for name := range v[guid] {
			out = append(out, VariableDescriptor{Name: name, GUID: guid})
		}
	}
	return out, nil
}

func (v mockBootVars) add(name string, guid GUID, attrs VariableAttributes, data []byte) {
	if _, exists := v[guid]; !exists {
		v[guid] = make(map[string]mockBootVarData)
	}
	v[guid][name] = mockBootVarData{attrs: attrs, data: data}
}

type bootSuite struct {
	mockVars        mockBootVars
	restoreMockVars func()
}

func (s *bootSuite) SetUpTest(c *C) {
	s.mockVars = make(mockBootVars)
	s.restoreMockVars = MockVarsBackend(s.mockVars)
}

func (s *bootSuite) TearDownTest(c *C) {
	if s.restoreMockVars != nil {
		s.restoreMockVars()
	}
	s.mockVars = nil
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

	opts, err := ReadOSIndicationsSupportedVariable()
	c.Check(err, IsNil)
	c.Check(opts, Equals, OSIndications(OSIndicationFileCapsuleDeliverySupported|OSIndicationCapsuleResultVarSupported))
}

func (s *bootSuite) TestReadOSIndicationsSupportedVariable2(c *C) {
	s.mockVars.add("OsIndicationsSupported", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	opts, err := ReadOSIndicationsSupportedVariable()
	c.Check(err, IsNil)
	c.Check(opts, Equals, OSIndications(OSIndicationBootToFWUI|OSIndicationFileCapsuleDeliverySupported|OSIndicationCapsuleResultVarSupported|OSIndicationStartOSRecovery|OSIndicationStartPlatformRecovery))
}

func (s *bootSuite) TestReadOSIndicationsSupportedVariableWrongSize(c *C) {
	s.mockVars.add("OsIndicationsSupported", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	_, err := ReadOSIndicationsSupportedVariable()
	c.Check(err, ErrorMatches, `variable contents has an unexpected size \(7 bytes\)`)
}

func (s *bootSuite) TestReadBootOptionSupportVariable1(c *C) {
	s.mockVars.add("BootOptionSupport", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x01, 0x03, 0x00, 0x00})

	opts, err := ReadBootOptionSupportVariable()
	c.Check(err, IsNil)
	c.Check(opts, Equals, BootOptionSupport(BootOptionSupportKey|BootOptionSupportCount))
}

func (s *bootSuite) TestReadBootOptionSupportVariable2(c *C) {
	s.mockVars.add("BootOptionSupport", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x13, 0x03, 0x00, 0x00})

	opts, err := ReadBootOptionSupportVariable()
	c.Check(err, IsNil)
	c.Check(opts, Equals, BootOptionSupport(BootOptionSupportKey|BootOptionSupportApp|BootOptionSupportSysPrep|BootOptionSupportCount))
}

func (s *bootSuite) TestReadBootOptionSupportVariableWrongSIze(c *C) {
	s.mockVars.add("BootOptionSupport", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x01, 0x03, 0x00, 0x00, 0x00})

	_, err := ReadBootOptionSupportVariable()
	c.Check(err, ErrorMatches, `variable contents has an unexpected size \(5 bytes\)`)
}

func (s *bootSuite) TestReadLoadOrderVariableBoot(c *C) {
	s.mockVars.add("BootOrder", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00, 0x01, 0x00, 0x02, 0x00})

	order, err := ReadLoadOrderVariable(LoadOptionClassBoot)
	c.Check(err, IsNil)
	c.Check(order, DeepEquals, []uint16{3, 1, 2})
}

func (s *bootSuite) TestReadLoadOrderVariableSysPrep(c *C) {
	s.mockVars.add("SysPrepOrder", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x04, 0x00, 0x05, 0x00, 0x03, 0x00})

	order, err := ReadLoadOrderVariable(LoadOptionClassSysPrep)
	c.Check(err, IsNil)
	c.Check(order, DeepEquals, []uint16{4, 5, 3})
}

func (s *bootSuite) TestReadLoadOrderVariableDriver(c *C) {
	s.mockVars.add("DriverOrder", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00, 0x01, 0x00, 0x02, 0x00})

	order, err := ReadLoadOrderVariable(LoadOptionClassDriver)
	c.Check(err, IsNil)
	c.Check(order, DeepEquals, []uint16{3, 1, 2})
}

func (s *bootSuite) TestReadLoadOrderVariableWrongClass(c *C) {
	_, err := ReadLoadOrderVariable(LoadOptionClassPlatformRecovery)
	c.Check(err, ErrorMatches, `invalid class \"PlatformRecovery\": function only suitable for Driver, SysPrep or Boot`)
}

func (s *bootSuite) TestReadLoadOrderVariableOddSize(c *C) {
	s.mockVars.add("BootOrder", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00, 0x01, 0x00, 0x02})

	_, err := ReadLoadOrderVariable(LoadOptionClassBoot)
	c.Check(err, ErrorMatches, `BootOrder variable contents has odd size \(5 bytes\)`)
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

	opt, err = ReadLoadOptionVariable(LoadOptionClassBoot, 3)
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

	opt, err = ReadLoadOptionVariable(LoadOptionClassBoot, 2)
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

	opt, err = ReadLoadOptionVariable(LoadOptionClassSysPrep, 2)
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

	_, err := ReadLoadOptionVariable(LoadOptionClassBoot, 1)
	c.Assert(err, ErrorMatches, `cannot decode LoadOption: unexpected EOF`)
}

func (s *bootSuite) TestReadBootNextVariable2(c *C) {
	s.mockVars.add("BootNext", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x02, 0x00})

	next, err := ReadBootNextVariable()
	c.Check(err, IsNil)
	c.Check(next, Equals, uint16(2))
}

func (s *bootSuite) TestReadBootNextVariable3(c *C) {
	s.mockVars.add("BootNext", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00})

	next, err := ReadBootNextVariable()
	c.Check(err, IsNil)
	c.Check(next, Equals, uint16(3))
}

func (s *bootSuite) TestReadBootNextVariableWrongSize(c *C) {
	s.mockVars.add("BootNext", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x02})

	_, err := ReadBootNextVariable()
	c.Check(err, ErrorMatches, `BootNext variable contents has the wrong size \(1 bytes\)`)
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

	opt, err = ReadBootNextLoadOptionVariable()
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

	opt, err = ReadBootNextLoadOptionVariable()
	c.Assert(err, IsNil)
	c.Check(opt, DeepEquals, expectedOpt)
}

func (s *bootSuite) TestReadBootNextLoadOptionDanglingOption(c *C) {
	s.mockVars.add("BootNext", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00})

	_, err := ReadBootNextLoadOptionVariable()
	c.Assert(err, Equals, ErrVarNotExist)
}

func (s *bootSuite) TestReadBootCurrentVariable3(c *C) {
	s.mockVars.add("BootCurrent", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x03, 0x00})

	next, err := ReadBootCurrentVariable()
	c.Check(err, IsNil)
	c.Check(next, Equals, uint16(3))
}

func (s *bootSuite) TestReadBootCurrentVariable4(c *C) {
	s.mockVars.add("BootCurrent", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0x04, 0x00})

	next, err := ReadBootCurrentVariable()
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

	opts, err := ReadOrderedLoadOptionVariables(LoadOptionClassBoot)
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

	opts, err := ReadOrderedLoadOptionVariables(LoadOptionClassPlatformRecovery)
	c.Assert(err, IsNil)
	c.Check(opts, DeepEquals, expectedOpts)
}