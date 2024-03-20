// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"crypto"
	"crypto/x509"
	"os"
	"time"

	. "github.com/canonical/go-efilib"

	. "gopkg.in/check.v1"
)

type wincertSuite struct{}

var _ = Suite(&wincertSuite{})

func (s *wincertSuite) TestReadWinCertificateGUID(c *C) {
	f, err := os.Open("testdata/sigs/cert-type-guid.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	cert, err := ReadWinCertificate(f)
	c.Assert(err, IsNil)
	guidCert, ok := cert.(WinCertificateGUID)
	c.Assert(ok, Equals, true)
	c.Assert(guidCert.GUIDType(), Equals, CertTypePKCS7Guid)

	p7cert, ok := cert.(*WinCertificatePKCS7)
	c.Assert(ok, Equals, true)

	signers := p7cert.GetSigners()
	c.Assert(signers, HasLen, 1)

	h := crypto.SHA256.New()
	h.Write(signers[0].RawTBSCertificate)
	c.Check(h.Sum(nil), DeepEquals, DecodeHexString(c, "607af875b99b8711204eede2c04bdf58d8f65adad8f3013a341503ca878175ea"))

	caBytes, err := os.ReadFile("testdata/certs/MicCorKEKCA2011_2011-06-24.crt")
	c.Check(err, IsNil)
	ca, err := x509.ParseCertificate(caBytes)
	c.Assert(err, IsNil)

	c.Check(p7cert.CertLikelyTrustAnchor(ca), Equals, true)

	caBytes, err = os.ReadFile("testdata/certs/canonical-uefi-ca.der")
	c.Check(err, IsNil)
	ca, err = x509.ParseCertificate(caBytes)
	c.Assert(err, IsNil)

	c.Check(p7cert.CertLikelyTrustAnchor(ca), Equals, false)
}

func (s *wincertSuite) TestReadWinCertificateAuthenticode(c *C) {
	f, err := os.Open("testdata/sigs/cert-type-authenticode.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	cert, err := ReadWinCertificate(f)
	c.Assert(err, IsNil)
	authenticodeCert, ok := cert.(*WinCertificateAuthenticode)
	c.Check(ok, Equals, true)

	h := crypto.SHA256.New()
	h.Write(authenticodeCert.GetSigner().RawTBSCertificate)
	c.Check(h.Sum(nil), DeepEquals, DecodeHexString(c, "08954ce3da028da0128a81435159f543d70ccd789ee86ea55630dab9a765644e"))

	caBytes, err := os.ReadFile("testdata/certs/canonical-uefi-ca.der")
	c.Check(err, IsNil)
	ca, err := x509.ParseCertificate(caBytes)
	c.Assert(err, IsNil)

	c.Check(authenticodeCert.CertLikelyTrustAnchor(ca), Equals, true)

	caBytes, err = os.ReadFile("testdata/certs/MicCorKEKCA2011_2011-06-24.crt")
	c.Check(err, IsNil)
	ca, err = x509.ParseCertificate(caBytes)
	c.Assert(err, IsNil)

	c.Check(authenticodeCert.CertLikelyTrustAnchor(ca), Equals, false)

	c.Check(authenticodeCert.DigestAlgorithm(), Equals, crypto.SHA256)
	c.Check(authenticodeCert.Digest(), DeepEquals, DecodeHexString(c, "b886cc19bdfff84a4e7b9fc2375309ec857bae5deb01635f6a73d9ed73304e50"))
}

func (s *wincertSuite) TestWinCertificationAuthenticodeCertLikelyTrustAnchorWithPartialCert(c *C) {
	f, err := os.Open("testdata/sigs/cert-type-authenticode.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	cert, err := ReadWinCertificate(f)
	c.Assert(err, IsNil)
	authenticodeCert, ok := cert.(*WinCertificateAuthenticode)
	c.Check(ok, Equals, true)

	caBytes, err := os.ReadFile("testdata/certs/canonical-uefi-ca.der")
	c.Check(err, IsNil)
	ca, err := x509.ParseCertificate(caBytes)
	c.Assert(err, IsNil)

	ca = &x509.Certificate{
		RawSubject:         ca.RawSubject,
		SubjectKeyId:       ca.SubjectKeyId,
		SignatureAlgorithm: ca.SignatureAlgorithm,
		RawIssuer:          ca.RawIssuer,
		AuthorityKeyId:     ca.AuthorityKeyId,
		PublicKeyAlgorithm: ca.PublicKeyAlgorithm,
	}
	c.Check(authenticodeCert.CertLikelyTrustAnchor(ca), Equals, true)

	caBytes, err = os.ReadFile("testdata/certs/MicCorKEKCA2011_2011-06-24.crt")
	c.Check(err, IsNil)
	ca, err = x509.ParseCertificate(caBytes)
	c.Assert(err, IsNil)

	ca = &x509.Certificate{
		RawSubject:         ca.RawSubject,
		SubjectKeyId:       ca.SubjectKeyId,
		SignatureAlgorithm: ca.SignatureAlgorithm,
		RawIssuer:          ca.RawIssuer,
		AuthorityKeyId:     ca.AuthorityKeyId,
		PublicKeyAlgorithm: ca.PublicKeyAlgorithm,
	}
	c.Check(authenticodeCert.CertLikelyTrustAnchor(ca), Equals, false)
}

func (s *wincertSuite) TestWinCertificationAuthenticodeSelfSigned(c *C) {
	f, err := os.Open("testdata/sigs/cert-type-authenticode-self-signed.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	cert, err := ReadWinCertificate(f)
	c.Assert(err, IsNil)
	authenticodeCert, ok := cert.(*WinCertificateAuthenticode)
	c.Check(ok, Equals, true)

	h := crypto.SHA256.New()
	h.Write(authenticodeCert.GetSigner().RawTBSCertificate)
	c.Check(h.Sum(nil), DeepEquals, DecodeHexString(c, "9f7950889a4a2195d9e3959123db19877617b95a3027ce8beef9b9c92fd4b438"))

	caBytes, err := os.ReadFile("testdata/certs/PkKek-1-snakeoil.der")
	c.Check(err, IsNil)
	ca, err := x509.ParseCertificate(caBytes)
	c.Assert(err, IsNil)

	c.Check(authenticodeCert.CertLikelyTrustAnchor(ca), Equals, true)

	caBytes, err = os.ReadFile("testdata/certs/MicCorKEKCA2011_2011-06-24.crt")
	c.Check(err, IsNil)
	ca, err = x509.ParseCertificate(caBytes)
	c.Assert(err, IsNil)

	c.Check(authenticodeCert.CertLikelyTrustAnchor(ca), Equals, false)

	c.Check(authenticodeCert.DigestAlgorithm(), Equals, crypto.SHA256)
	c.Check(authenticodeCert.Digest(), DeepEquals, DecodeHexString(c, "bf6b6dfdb1f6435a81e4808db7f846d86d170566e4753d4384fdab6504be4fb9"))
}

func (s *wincertSuite) TestWinCertificationAuthenticodeCertLikelyTrustAnchorWithPartialCertSelfSigned(c *C) {
	f, err := os.Open("testdata/sigs/cert-type-authenticode-self-signed.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	cert, err := ReadWinCertificate(f)
	c.Assert(err, IsNil)
	authenticodeCert, ok := cert.(*WinCertificateAuthenticode)
	c.Check(ok, Equals, true)

	caBytes, err := os.ReadFile("testdata/certs/PkKek-1-snakeoil.der")
	c.Check(err, IsNil)
	ca, err := x509.ParseCertificate(caBytes)
	c.Assert(err, IsNil)

	ca = &x509.Certificate{
		RawSubject:         ca.RawSubject,
		SubjectKeyId:       ca.SubjectKeyId,
		SignatureAlgorithm: ca.SignatureAlgorithm,
		RawIssuer:          ca.RawIssuer,
		AuthorityKeyId:     ca.AuthorityKeyId,
		PublicKeyAlgorithm: ca.PublicKeyAlgorithm,
	}
	c.Check(authenticodeCert.CertLikelyTrustAnchor(ca), Equals, true)

	caBytes, err = os.ReadFile("testdata/certs/MicCorKEKCA2011_2011-06-24.crt")
	c.Check(err, IsNil)
	ca, err = x509.ParseCertificate(caBytes)
	c.Assert(err, IsNil)

	ca = &x509.Certificate{
		RawSubject:         ca.RawSubject,
		SubjectKeyId:       ca.SubjectKeyId,
		SignatureAlgorithm: ca.SignatureAlgorithm,
		RawIssuer:          ca.RawIssuer,
		AuthorityKeyId:     ca.AuthorityKeyId,
		PublicKeyAlgorithm: ca.PublicKeyAlgorithm,
	}
	c.Check(authenticodeCert.CertLikelyTrustAnchor(ca), Equals, false)
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
	c.Check(auth.AuthInfo.GUIDType(), Equals, CertTypePKCS7Guid)
	_, err = ReadSignatureDatabase(f)
	c.Check(err, IsNil)
}
