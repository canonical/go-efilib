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

type securebootSuite struct {
	mockVars mockVars
	mockCtx  context.Context
}

func (s *securebootSuite) SetUpTest(c *C) {
	s.mockVars = make(mockVars)
	s.mockCtx = WithVarsBackend(context.Background(), s.mockVars)
}

func (s *securebootSuite) TearDownTest(c *C) {
	s.mockVars = nil
	s.mockCtx = context.Background()
}

var _ = Suite(&securebootSuite{})

func (s *securebootSuite) TestComputeSecureBootModeSetupModeOld(c *C) {
	s.mockVars.add("SetupMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("PK", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeTimeBasedAuthenticatedWriteAccess, nil)

	mode, err := ComputeSecureBootMode(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(mode, Equals, SetupMode)
}

func (s *securebootSuite) TestComputeSecureBootModeSetupModeNew(c *C) {
	s.mockVars.add("SetupMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("AuditMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("DeployedMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("PK", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeTimeBasedAuthenticatedWriteAccess, nil)

	mode, err := ComputeSecureBootMode(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(mode, Equals, SetupMode)
}

func (s *securebootSuite) TestComputeSecureBootModeAuditMode(c *C) {
	s.mockVars.add("SetupMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("AuditMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("DeployedMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("PK", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeTimeBasedAuthenticatedWriteAccess, nil)

	mode, err := ComputeSecureBootMode(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(mode, Equals, AuditMode)
}

func (s *securebootSuite) TestComputeSecureBootModeUserModeOld(c *C) {
	pk := SignatureDatabase{
		{
			Type:   CertX509Guid,
			Header: []byte{},
			Signatures: []*SignatureData{
				{
					Owner: dellOwnerGuid,
					Data:  ReadFile(c, "testdata/sigdbs/1/cert-0.der"),
				},
			},
		},
	}
	w := new(bytes.Buffer)
	c.Assert(pk.Write(w), IsNil)

	s.mockVars.add("SetupMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("PK", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeTimeBasedAuthenticatedWriteAccess, w.Bytes())

	mode, err := ComputeSecureBootMode(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(mode, Equals, UserMode)
}

func (s *securebootSuite) TestComputeSecureBootModeUserModeNew(c *C) {
	pk := SignatureDatabase{
		{
			Type:   CertX509Guid,
			Header: []byte{},
			Signatures: []*SignatureData{
				{
					Owner: dellOwnerGuid,
					Data:  ReadFile(c, "testdata/sigdbs/1/cert-0.der"),
				},
			},
		},
	}
	w := new(bytes.Buffer)
	c.Assert(pk.Write(w), IsNil)

	s.mockVars.add("SetupMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("AuditMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("DeployedMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("PK", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeTimeBasedAuthenticatedWriteAccess, w.Bytes())

	mode, err := ComputeSecureBootMode(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(mode, Equals, UserMode)
}

func (s *securebootSuite) TestComputeSecureBootModeDeployedMode(c *C) {
	pk := SignatureDatabase{
		{
			Type:   CertX509Guid,
			Header: []byte{},
			Signatures: []*SignatureData{
				{
					Owner: dellOwnerGuid,
					Data:  ReadFile(c, "testdata/sigdbs/1/cert-0.der"),
				},
			},
		},
	}
	w := new(bytes.Buffer)
	c.Assert(pk.Write(w), IsNil)

	s.mockVars.add("SetupMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("AuditMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("DeployedMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("PK", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeTimeBasedAuthenticatedWriteAccess, w.Bytes())

	mode, err := ComputeSecureBootMode(s.mockCtx)
	c.Check(err, IsNil)
	c.Check(mode, Equals, DeployedMode)
}

func (s *securebootSuite) TestComputeSecureBootModeSetupModeSecureBootErr(c *C) {
	s.mockVars.add("SetupMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("PK", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeTimeBasedAuthenticatedWriteAccess, nil)

	_, err := ComputeSecureBootMode(s.mockCtx)
	c.Check(err, ErrorMatches, `inconsistent secure boot mode: firmware indicates secure boot is enabled in setup mode`)
	var sample *InconsistentSecureBootModeError
	c.Check(err, FitsTypeOf, sample)
}

func (s *securebootSuite) TestComputeSecureBootModeSetupModePKErr(c *C) {
	pk := SignatureDatabase{
		{
			Type:   CertX509Guid,
			Header: []byte{},
			Signatures: []*SignatureData{
				{
					Owner: dellOwnerGuid,
					Data:  ReadFile(c, "testdata/sigdbs/1/cert-0.der"),
				},
			},
		},
	}
	w := new(bytes.Buffer)
	c.Assert(pk.Write(w), IsNil)

	s.mockVars.add("SetupMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("PK", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeTimeBasedAuthenticatedWriteAccess, w.Bytes())

	_, err := ComputeSecureBootMode(s.mockCtx)
	c.Check(err, ErrorMatches, `inconsistent secure boot mode: firmware indicates setup mode is enabled with a platform key enrolled`)
	var sample *InconsistentSecureBootModeError
	c.Check(err, FitsTypeOf, sample)
}

func (s *securebootSuite) TestComputeSecureBootModeSetupModeDeployedModeErr(c *C) {
	s.mockVars.add("SetupMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("AuditMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("DeployedMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("PK", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeTimeBasedAuthenticatedWriteAccess, nil)

	_, err := ComputeSecureBootMode(s.mockCtx)
	c.Check(err, ErrorMatches, `inconsistent secure boot mode: firmware indicates deployed mode is enabled in setup mode`)
	var sample *InconsistentSecureBootModeError
	c.Check(err, FitsTypeOf, sample)
}

func (s *securebootSuite) TestComputeSecureBootModeUserModePKErr(c *C) {
	s.mockVars.add("SetupMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("PK", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeTimeBasedAuthenticatedWriteAccess, nil)

	_, err := ComputeSecureBootMode(s.mockCtx)
	c.Check(err, ErrorMatches, `inconsistent secure boot mode: firmware indicates it isn't in setup mode when no platform key is enrolled`)
	var sample *InconsistentSecureBootModeError
	c.Check(err, FitsTypeOf, sample)
}

func (s *securebootSuite) TestComputeSecureBootModeUserModeAuditModeErr(c *C) {
	pk := SignatureDatabase{
		{
			Type:   CertX509Guid,
			Header: []byte{},
			Signatures: []*SignatureData{
				{
					Owner: dellOwnerGuid,
					Data:  ReadFile(c, "testdata/sigdbs/1/cert-0.der"),
				},
			},
		},
	}
	w := new(bytes.Buffer)
	c.Assert(pk.Write(w), IsNil)

	s.mockVars.add("SetupMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("AuditMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("DeployedMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("PK", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeTimeBasedAuthenticatedWriteAccess, w.Bytes())

	_, err := ComputeSecureBootMode(s.mockCtx)
	c.Check(err, ErrorMatches, `inconsistent secure boot mode: firmware indicates audit mode is enabled when not in setup mode`)
	var sample *InconsistentSecureBootModeError
	c.Check(err, FitsTypeOf, sample)
}

func (s *securebootSuite) TestIsDeployedModeSupportedFalse(c *C) {
	s.mockVars.add("SetupMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("PK", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeTimeBasedAuthenticatedWriteAccess, nil)

	c.Check(IsDeployedModeSupported(s.mockCtx), Equals, false)
}

func (s *securebootSuite) TestIsDeployedModeSupportedTrue(c *C) {
	s.mockVars.add("SetupMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1})
	s.mockVars.add("AuditMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("DeployedMode", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("SecureBoot", GlobalVariable, AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{0})
	s.mockVars.add("PK", GlobalVariable, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeTimeBasedAuthenticatedWriteAccess, nil)

	c.Check(IsDeployedModeSupported(s.mockCtx), Equals, true)
}
