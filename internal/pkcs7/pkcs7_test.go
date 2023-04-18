// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package pkcs7_test

import (
	"io/ioutil"
	"os"
	"testing"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-efilib/internal/pkcs7"
)

func Test(t *testing.T) { TestingT(t) }

type pkcs7Suite struct{}

var _ = Suite(&pkcs7Suite{})

func (s *pkcs7Suite) TestUnmarshalPKCS7(c *C) {
	f, err := os.Open("../../testdata/sigs/pkcs7.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	c.Check(err, IsNil)

	p, err := UnmarshalPKCS7(b)
	c.Assert(err, IsNil)
	c.Assert(p.GetSigners(), HasLen, 1)
	c.Check(p.GetSigners()[0].Subject.String(), Equals, "CN=Microsoft Windows UEFI Key Exchange Key,OU=MOPR,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US")
}

func (s *pkcs7Suite) TestUnmarshalAuthenticode(c *C) {
	f, err := os.Open("../../testdata/sigs/authenticode.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	c.Check(err, IsNil)

	p, err := UnmarshalAuthenticode(b)
	c.Assert(err, IsNil)
	c.Assert(p.GetSigners(), HasLen, 1)
	c.Check(p.GetSigners()[0].Subject.String(), Equals, "CN=Canonical Ltd. Secure Boot Signing (2017),OU=Secure Boot,O=Canonical Ltd.,ST=Isle of Man,C=GB")
}

func (s *pkcs7Suite) TestUnmarshalAuthenticodeWithTrailingBytes(c *C) {
	f, err := os.Open("../../testdata/sigs/authenticode-with-trailing-bytes.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	c.Check(err, IsNil)

	p, err := UnmarshalAuthenticode(b)
	c.Assert(err, IsNil)
	c.Assert(p.GetSigners(), HasLen, 1)
	c.Check(p.GetSigners()[0].Subject.String(), Equals, "CN=Microsoft Windows UEFI Driver Publisher,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US")
}
