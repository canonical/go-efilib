// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"crypto"
	"os"

	. "github.com/canonical/go-efilib"

	. "gopkg.in/check.v1"
)

type peSuite struct{}

var _ = Suite(&peSuite{})

type testComputePeImageDigestData struct {
	alg    crypto.Hash
	path   string
	digest []byte
}

func (s *peSuite) testComputePeImageDigest(c *C, data *testComputePeImageDigestData) {
	f, err := os.Open(data.path)
	c.Assert(err, IsNil)
	fi, err := f.Stat()
	c.Assert(err, IsNil)
	d, err := ComputePeImageDigest(data.alg, f, fi.Size())
	c.Assert(err, IsNil)
	c.Check(d, DeepEquals, data.digest)
	c.Logf("%x", d)
}

func (s *peSuite) TestComputePeImageDigest1(c *C) {
	s.testComputePeImageDigest(c, &testComputePeImageDigestData{
		alg:    crypto.SHA256,
		path:   "testdata/efiimages/mockshim.efi.signed",
		digest: DecodeHexString(c, "1d91795a82b24a61c5b5f4b5843062fd10fc42e2d403c5a65f811014df231c9f"),
	})
}

func (s *peSuite) TestComputePeImageDigest2(c *C) {
	s.testComputePeImageDigest(c, &testComputePeImageDigestData{
		alg:    crypto.SHA256,
		path:   "testdata/efiimages/mock.efi.signed",
		digest: DecodeHexString(c, "5a03ecd3cc4caf9eabc8d7295772c0b74e2998d1631bbde372acbf2ffad4031a"),
	})
}

func (s *peSuite) TestComputePeImageDigest3(c *C) {
	s.testComputePeImageDigest(c, &testComputePeImageDigestData{
		alg:    crypto.SHA1,
		path:   "testdata/efiimages/mockshim.efi.signed",
		digest: DecodeHexString(c, "2e65c395448b8fcfce99f0421bb396f7a66cc207"),
	})
}

func (s *peSuite) TestComputePeImageDigest4(c *C) {
	s.testComputePeImageDigest(c, &testComputePeImageDigestData{
		alg:    crypto.SHA256,
		path:   "testdata/efiimages/mock.efi",
		digest: DecodeHexString(c, "d74047a878cab6614ffc3569e6aff636470773c8b73dfb4288c54742e6c85945"),
	})
}
