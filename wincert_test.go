// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"crypto"
	"os"
	"time"

	. "github.com/canonical/go-efilib"

	. "gopkg.in/check.v1"

	"go.mozilla.org/pkcs7"
)

type wincertSuite struct{}

var _ = Suite(&wincertSuite{})

func (s *wincertSuite) TestReadWinCertificateGUID(c *C) {
	f, err := os.Open("testdata/sigs/cert-type-guid.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	cert, err := ReadWinCertificate(f)
	c.Assert(err, IsNil)
	guidCert, ok := cert.(*WinCertificateGUID)
	c.Assert(ok, Equals, true)
	c.Check(guidCert.Type, Equals, CertTypePKCS7Guid)
}

func (s *wincertSuite) TestReadWinCertificateAuthenticode(c *C) {
	f, err := os.Open("testdata/sigs/cert-type-authenticode.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	cert, err := ReadWinCertificate(f)
	c.Assert(err, IsNil)
	authenticodeCert, ok := cert.(WinCertificateAuthenticode)
	c.Check(ok, Equals, true)

	p7, err := pkcs7.Parse(authenticodeCert)
	c.Assert(err, IsNil)
	signer := p7.GetOnlySigner()
	c.Assert(signer, NotNil)

	h := crypto.SHA256.New()
	h.Write(signer.RawTBSCertificate)
	c.Check(h.Sum(nil), DeepEquals, DecodeHexString(c, "08954ce3da028da0128a81435159f543d70ccd789ee86ea55630dab9a765644e"))
}

func (s *wincertSuite) TestReadWinCertificateInvalidRevision(c *C) {
	f, err := os.Open("testdata/sigs/cert-invalid-revision.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = ReadWinCertificate(f)
	c.Assert(err, ErrorMatches, "unexpected revision")
}

func (s *wincertSuite) TestReadWinCertificateInvalidType(c *C) {
	f, err := os.Open("testdata/sigs/cert-invalid-type.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = ReadWinCertificate(f)
	c.Assert(err, ErrorMatches, "unexpected type")
}

func (s *wincertSuite) TestReadTimeBasedVariableAuthentication(c *C) {
	f, err := os.Open("testdata/authenticated-var-payloads/MS-2016-08-08.bin")
	c.Assert(err, IsNil)
	defer f.Close()

	auth, err := ReadTimeBasedVariableAuthentication(f)
	c.Assert(err, IsNil)
	c.Check(auth.TimeStamp, DeepEquals, time.Date(2010, 3, 6, 19, 17, 21, 0, time.FixedZone("", 0)))
	c.Check(auth.AuthInfo.Type, Equals, CertTypePKCS7Guid)
	_, err = ReadSignatureDatabase(f)
	c.Check(err, IsNil)
}
