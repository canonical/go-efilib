// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"bytes"
	"fmt"
	"io"
	"os"

	. "github.com/canonical/go-efilib"

	. "gopkg.in/check.v1"
)

type dbSuite struct{}

var _ = Suite(&dbSuite{})

var microsoftOwnerGuid = MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b})
var dellOwnerGuid = MakeGUID(0x70564dce, 0x9afc, 0x4ee3, 0x85fc, [...]uint8{0x94, 0x96, 0x49, 0xd7, 0xe4, 0x5c})

func (s *dbSuite) TestSignatureDataEqual(c *C) {
	d := SignatureData{
		Owner: microsoftOwnerGuid,
		Data:  []byte("foo")}
	c.Check(d.Equal(&d), Equals, true)
}

func (s *dbSuite) TestSignatureDataNotEqual1(c *C) {
	x := SignatureData{
		Owner: microsoftOwnerGuid,
		Data:  []byte("foo")}
	y := SignatureData{
		Owner: dellOwnerGuid,
		Data:  []byte("foo")}
	c.Check(x.Equal(&y), Equals, false)
}

func (s *dbSuite) TestSignatureDataNotEqual2(c *C) {
	x := SignatureData{
		Owner: microsoftOwnerGuid,
		Data:  []byte("foo")}
	y := SignatureData{
		Owner: microsoftOwnerGuid,
		Data:  []byte("bar")}
	c.Check(x.Equal(&y), Equals, false)
}

type testDecodeSignatureDatabaseData struct {
	path string
	db   SignatureDatabase
}

func (s *dbSuite) testDecodeSignatureDatabase(c *C, data *testDecodeSignatureDatabaseData) {
	f, err := os.Open(data.path)
	c.Assert(err, IsNil)
	defer f.Close()

	db, err := DecodeSignatureDatabase(f)
	c.Check(err, IsNil)
	c.Check(db, DeepEquals, data.db)
}

func (s *dbSuite) TestDecodeSignatureDatabase1(c *C) {
	s.testDecodeSignatureDatabase(c, &testDecodeSignatureDatabaseData{
		path: "testdata/sigdbs/1.siglist",
		db: SignatureDatabase{
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: dellOwnerGuid,
						Data:  readFile(c, "testdata/sigdbs/1/cert-0.der"),
					},
				},
			},
		},
	})
}

func (s *dbSuite) TestDecodeSignatureDatabase2(c *C) {
	s.testDecodeSignatureDatabase(c, &testDecodeSignatureDatabaseData{
		path: "testdata/sigdbs/2.siglist",
		db: SignatureDatabase{
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: dellOwnerGuid,
						Data:  readFile(c, "testdata/sigdbs/2/cert-0.der"),
					},
				},
			},
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: microsoftOwnerGuid,
						Data:  readFile(c, "testdata/sigdbs/2/cert-1.der"),
					},
				},
			},
		},
	})
}

func (s *dbSuite) TestDecodeSignatureDatabase3(c *C) {
	s.testDecodeSignatureDatabase(c, &testDecodeSignatureDatabaseData{
		path: "testdata/sigdbs/3.siglist",
		db: SignatureDatabase{
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: dellOwnerGuid,
						Data:  readFile(c, "testdata/sigdbs/3/cert-0.der"),
					},
				},
			},
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: microsoftOwnerGuid,
						Data:  readFile(c, "testdata/sigdbs/3/cert-1.der"),
					},
				},
			},
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: microsoftOwnerGuid,
						Data:  readFile(c, "testdata/sigdbs/3/cert-2.der"),
					},
				},
			},
		},
	})
}

func (s *dbSuite) TestDecodeSignatureDatabase4(c *C) {
	var db SignatureDatabase
	db = append(db, &SignatureList{
		Type:   CertX509Guid,
		Header: []byte{},
		Signatures: []*SignatureData{
			{
				Data: readFile(c, "testdata/sigdbs/4/cert-0.der"),
			},
		},
	})

	hashes := SignatureList{Type: CertSHA256Guid, Header: []byte{}}
	for i := 1; i < 78; i++ {
		hashes.Signatures = append(hashes.Signatures, &SignatureData{
			Owner: microsoftOwnerGuid,
			Data:  readFile(c, fmt.Sprintf("testdata/sigdbs/4/cert-%d.hash", i)),
		})
	}
	db = append(db, &hashes)

	s.testDecodeSignatureDatabase(c, &testDecodeSignatureDatabaseData{
		path: "testdata/sigdbs/4.siglist",
		db:   db})
}

func (s *dbSuite) TestDecodeSignatureListWithInconsistentSizeFields(c *C) {
	f, err := os.Open("testdata/sigdbs/inconsistent-sizes.siglist")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = DecodeSignatureDatabase(f)
	c.Check(err, ErrorMatches, "cannot read EFI_SIGNATURE_LIST 1: inconsistent size fields")
}

func (s *dbSuite) TestDecodeSignatureListWithInvalidSignatureSize(c *C) {
	f, err := os.Open("testdata/sigdbs/invalid-signature-size.siglist")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = DecodeSignatureDatabase(f)
	c.Check(err, ErrorMatches, "cannot read EFI_SIGNATURE_LIST 0: invalid SignatureSize")
}

func (s *dbSuite) testEncodeSignatureDatabase(c *C, path string) {
	f, err := os.Open(path)
	c.Assert(err, IsNil)
	defer f.Close()

	var b bytes.Buffer
	db, err := DecodeSignatureDatabase(io.TeeReader(f, &b))
	c.Check(err, IsNil)

	var e bytes.Buffer
	c.Check(db.Encode(&e), IsNil)
	c.Check(e.Bytes(), DeepEquals, b.Bytes())
}

func (s *dbSuite) TestEncodeSignatureDatabase1(c *C) {
	s.testEncodeSignatureDatabase(c, "testdata/sigdbs/1.siglist")
}

func (s *dbSuite) TestEncodeSignatureDatabase2(c *C) {
	s.testEncodeSignatureDatabase(c, "testdata/sigdbs/2.siglist")
}

func (s *dbSuite) TestEncodeSignatureDatabase3(c *C) {
	s.testEncodeSignatureDatabase(c, "testdata/sigdbs/3.siglist")
}

func (s *dbSuite) TestEncodeSignatureDatabase4(c *C) {
	s.testEncodeSignatureDatabase(c, "testdata/sigdbs/4.siglist")
}

func (s *dbSuite) TestEncodeSignatureWithWrongSize(c *C) {
	db := SignatureDatabase{
		{
			Type: CertX509Guid,
			Signatures: []*SignatureData{
				{
					Data: readFile(c, "testdata/sigdbs/3/cert-1.der"),
				},
				{
					Data: readFile(c, "testdata/sigdbs/3/cert-2.der"),
				},
			},
		},
	}
	var b bytes.Buffer
	c.Check(db.Encode(&b), ErrorMatches, "cannot encode signature list 0: signature 1 contains the wrong size")
}
