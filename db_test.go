// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
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

type testReadSignatureListData struct {
	path string
	db   SignatureDatabase
}

func (s *dbSuite) testReadSignatureList(c *C, data *testReadSignatureListData) {
	f, err := os.Open(data.path)
	c.Assert(err, IsNil)
	defer f.Close()

	for i := 0; i < len(data.db); i++ {
		l, err := ReadSignatureList(f)
		c.Check(err, IsNil)
		c.Check(l, DeepEquals, data.db[i])
	}
}

func (s *dbSuite) TestReadSignatureList1(c *C) {
	s.testReadSignatureList(c, &testReadSignatureListData{
		path: "testdata/sigdbs/1.siglist",
		db: SignatureDatabase{
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
		},
	})
}

func (s *dbSuite) TestReadSignatureList2(c *C) {
	s.testReadSignatureList(c, &testReadSignatureListData{
		path: "testdata/sigdbs/2.siglist",
		db: SignatureDatabase{
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: dellOwnerGuid,
						Data:  ReadFile(c, "testdata/sigdbs/2/cert-0.der"),
					},
				},
			},
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: microsoftOwnerGuid,
						Data:  ReadFile(c, "testdata/sigdbs/2/cert-1.der"),
					},
				},
			},
		},
	})
}

func (s *dbSuite) TestReadSignatureList3(c *C) {
	s.testReadSignatureList(c, &testReadSignatureListData{
		path: "testdata/sigdbs/3.siglist",
		db: SignatureDatabase{
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: dellOwnerGuid,
						Data:  ReadFile(c, "testdata/sigdbs/3/cert-0.der"),
					},
				},
			},
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: microsoftOwnerGuid,
						Data:  ReadFile(c, "testdata/sigdbs/3/cert-1.der"),
					},
				},
			},
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: microsoftOwnerGuid,
						Data:  ReadFile(c, "testdata/sigdbs/3/cert-2.der"),
					},
				},
			},
		},
	})
}

func (s *dbSuite) TestReadSignatureList4(c *C) {
	var db SignatureDatabase
	db = append(db, &SignatureList{
		Type:   CertX509Guid,
		Header: []byte{},
		Signatures: []*SignatureData{
			{
				Data: ReadFile(c, "testdata/sigdbs/4/cert-0.der"),
			},
		},
	})

	hashes := SignatureList{Type: CertSHA256Guid, Header: []byte{}}
	for i := 1; i < 78; i++ {
		hashes.Signatures = append(hashes.Signatures, &SignatureData{
			Owner: microsoftOwnerGuid,
			Data:  ReadFile(c, fmt.Sprintf("testdata/sigdbs/4/cert-%d.hash", i)),
		})
	}
	db = append(db, &hashes)

	s.testReadSignatureList(c, &testReadSignatureListData{
		path: "testdata/sigdbs/4.siglist",
		db:   db})
}

type testReadSignatureDatabaseData struct {
	path string
	db   SignatureDatabase
}

func (s *dbSuite) testReadSignatureDatabase(c *C, data *testReadSignatureDatabaseData) {
	f, err := os.Open(data.path)
	c.Assert(err, IsNil)
	defer f.Close()

	db, err := ReadSignatureDatabase(f)
	c.Check(err, IsNil)
	c.Check(db, DeepEquals, data.db)
}

func (s *dbSuite) TestReadSignatureDatabase1(c *C) {
	s.testReadSignatureDatabase(c, &testReadSignatureDatabaseData{
		path: "testdata/sigdbs/1.siglist",
		db: SignatureDatabase{
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
		},
	})
}

func (s *dbSuite) TestReadSignatureDatabase2(c *C) {
	s.testReadSignatureDatabase(c, &testReadSignatureDatabaseData{
		path: "testdata/sigdbs/2.siglist",
		db: SignatureDatabase{
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: dellOwnerGuid,
						Data:  ReadFile(c, "testdata/sigdbs/2/cert-0.der"),
					},
				},
			},
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: microsoftOwnerGuid,
						Data:  ReadFile(c, "testdata/sigdbs/2/cert-1.der"),
					},
				},
			},
		},
	})
}

func (s *dbSuite) TestReadSignatureDatabase3(c *C) {
	s.testReadSignatureDatabase(c, &testReadSignatureDatabaseData{
		path: "testdata/sigdbs/3.siglist",
		db: SignatureDatabase{
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: dellOwnerGuid,
						Data:  ReadFile(c, "testdata/sigdbs/3/cert-0.der"),
					},
				},
			},
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: microsoftOwnerGuid,
						Data:  ReadFile(c, "testdata/sigdbs/3/cert-1.der"),
					},
				},
			},
			{
				Type:   CertX509Guid,
				Header: []byte{},
				Signatures: []*SignatureData{
					{
						Owner: microsoftOwnerGuid,
						Data:  ReadFile(c, "testdata/sigdbs/3/cert-2.der"),
					},
				},
			},
		},
	})
}

func (s *dbSuite) TestReadSignatureDatabase4(c *C) {
	var db SignatureDatabase
	db = append(db, &SignatureList{
		Type:   CertX509Guid,
		Header: []byte{},
		Signatures: []*SignatureData{
			{
				Data: ReadFile(c, "testdata/sigdbs/4/cert-0.der"),
			},
		},
	})

	hashes := SignatureList{Type: CertSHA256Guid, Header: []byte{}}
	for i := 1; i < 78; i++ {
		hashes.Signatures = append(hashes.Signatures, &SignatureData{
			Owner: microsoftOwnerGuid,
			Data:  ReadFile(c, fmt.Sprintf("testdata/sigdbs/4/cert-%d.hash", i)),
		})
	}
	db = append(db, &hashes)

	s.testReadSignatureDatabase(c, &testReadSignatureDatabaseData{
		path: "testdata/sigdbs/4.siglist",
		db:   db})
}

func (s *dbSuite) TestReadSignatureListWithInvalidSignatureHeaderField(c *C) {
	f, err := os.Open("testdata/sigdbs/invalid-sigheader-size.siglist")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = ReadSignatureDatabase(f)
	c.Check(err, ErrorMatches, "cannot read EFI_SIGNATURE_LIST 0: signature header size too large")
}

func (s *dbSuite) TestReadSignatureListWithInconsistentSizeFields1(c *C) {
	f, err := os.Open("testdata/sigdbs/inconsistent-sizes1.siglist")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = ReadSignatureDatabase(f)
	c.Check(err, ErrorMatches, "cannot read EFI_SIGNATURE_LIST 0: inconsistent size fields: total signatures payload size underflows")
}

func (s *dbSuite) TestReadSignatureListWithInconsistentSizeFields(c *C) {
	f, err := os.Open("testdata/sigdbs/inconsistent-sizes2.siglist")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = ReadSignatureDatabase(f)
	c.Check(err, ErrorMatches, "cannot read EFI_SIGNATURE_LIST 1: inconsistent size fields: total signatures payload size not a multiple of the individual signature size")
}

func (s *dbSuite) TestReadSignatureListWithInvalidSignatureSize(c *C) {
	f, err := os.Open("testdata/sigdbs/invalid-signature-size.siglist")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = ReadSignatureDatabase(f)
	c.Check(err, ErrorMatches, "cannot read EFI_SIGNATURE_LIST 0: invalid SignatureSize")
}

func (s *dbSuite) TestReadSignatureListWithInvalidSignatureSizeDivideByZero(c *C) {
	f, err := os.Open("testdata/sigdbs/invalid-signature-size-divide-by-zero.siglist")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = ReadSignatureDatabase(f)
	c.Check(err, ErrorMatches, "cannot read EFI_SIGNATURE_LIST 0: invalid SignatureSize")
}

func (s *dbSuite) testWriteSignatureDatabase(c *C, path string) {
	f, err := os.Open(path)
	c.Assert(err, IsNil)
	defer f.Close()

	var b bytes.Buffer
	db, err := ReadSignatureDatabase(io.TeeReader(f, &b))
	c.Check(err, IsNil)

	var e bytes.Buffer
	c.Check(db.Write(&e), IsNil)
	c.Check(e.Bytes(), DeepEquals, b.Bytes())
}

func (s *dbSuite) TestWriteSignatureDatabase1(c *C) {
	s.testWriteSignatureDatabase(c, "testdata/sigdbs/1.siglist")
}

func (s *dbSuite) TestWriteSignatureDatabase2(c *C) {
	s.testWriteSignatureDatabase(c, "testdata/sigdbs/2.siglist")
}

func (s *dbSuite) TestWriteSignatureDatabase3(c *C) {
	s.testWriteSignatureDatabase(c, "testdata/sigdbs/3.siglist")
}

func (s *dbSuite) TestWriteSignatureDatabase4(c *C) {
	s.testWriteSignatureDatabase(c, "testdata/sigdbs/4.siglist")
}

func (s *dbSuite) TestWriteSignatureWithWrongSize(c *C) {
	db := SignatureDatabase{
		{
			Type: CertX509Guid,
			Signatures: []*SignatureData{
				{
					Data: ReadFile(c, "testdata/sigdbs/3/cert-1.der"),
				},
				{
					Data: ReadFile(c, "testdata/sigdbs/3/cert-2.der"),
				},
			},
		},
	}
	var b bytes.Buffer
	c.Check(db.Write(&b), ErrorMatches, "cannot encode signature list 0: signature 1 contains the wrong size")
}

func (s *dbSuite) TestSignatureDatabaseBytes(c *C) {
	f, err := os.Open("testdata/sigdbs/4.siglist")
	c.Assert(err, IsNil)
	defer f.Close()

	var src bytes.Buffer
	db, err := ReadSignatureDatabase(io.TeeReader(f, &src))
	c.Check(err, IsNil)

	b, err := db.Bytes()
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, src.Bytes())
}

func (s *dbSuite) TestWriteSignatureData(c *C) {
	d := SignatureData{
		Owner: dellOwnerGuid,
		Data:  ReadFile(c, "testdata/sigdbs/1/cert-0.der")}

	var b bytes.Buffer
	c.Check(d.Write(&b), IsNil)

	var owner GUID
	_, err := b.Read(owner[:])
	c.Check(err, IsNil)
	c.Check(owner, Equals, d.Owner)

	data, err := ioutil.ReadAll(&b)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, d.Data)
}
