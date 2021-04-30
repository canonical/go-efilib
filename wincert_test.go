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

func (s *wincertSuite) TestDecodeWinCertificateGUID(c *C) {
	f, err := os.Open("testdata/sigs/cert-type-guid.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	cert, err := DecodeWinCertificate(f)
	c.Assert(err, IsNil)
	guidCert, ok := cert.(*WinCertificateGUID)
	c.Assert(ok, Equals, true)
	c.Check(guidCert.Type, Equals, CertTypePKCS7Guid)
}

func (s *wincertSuite) TestDecodeWinCertificateAuthenticode(c *C) {
	f, err := os.Open("testdata/sigs/cert-type-authenticode.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	cert, err := DecodeWinCertificate(f)
	c.Assert(err, IsNil)
	authenticodeCert, ok := cert.(WinCertificateAuthenticode)
	c.Check(ok, Equals, true)

	p7, err := pkcs7.Parse(authenticodeCert)
	c.Assert(err, IsNil)
	signer := p7.GetOnlySigner()
	c.Assert(signer, NotNil)

	h := crypto.SHA256.New()
	h.Write(signer.RawTBSCertificate)
	c.Check(h.Sum(nil), DeepEquals, decodeHexString(c, "08954ce3da028da0128a81435159f543d70ccd789ee86ea55630dab9a765644e"))
}

func (s *wincertSuite) TestDecodeWinCertificateInvalidRevision(c *C) {
	f, err := os.Open("testdata/sigs/cert-invalid-revision.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = DecodeWinCertificate(f)
	c.Assert(err, ErrorMatches, "unexpected revision")
}

func (s *wincertSuite) TestDecodeWinCertificateInvalidType(c *C) {
	f, err := os.Open("testdata/sigs/cert-invalid-type.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = DecodeWinCertificate(f)
	c.Assert(err, ErrorMatches, "unexpected type")
}

func (s *wincertSuite) TestDecodeTimeBasedVariableAuthentication(c *C) {
	f, err := os.Open("testdata/authenticated-var-payloads/MS-2016-08-08.bin")
	c.Assert(err, IsNil)
	defer f.Close()

	auth, err := DecodeTimeBasedVariableAuthentication(f)
	c.Assert(err, IsNil)
	c.Check(auth.TimeStamp, DeepEquals, time.Date(2010, 3, 6, 19, 17, 21, 0, time.FixedZone("", 0)))
	c.Check(auth.AuthInfo.Type, Equals, CertTypePKCS7Guid)
	_, err = DecodeSignatureDatabase(f)
	c.Check(err, IsNil)
}
