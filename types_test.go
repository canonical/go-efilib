package efi_test

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"os"
	"time"

	. "github.com/canonical/go-efilib"

	. "gopkg.in/check.v1"

	"go.mozilla.org/pkcs7"
)

type typesSuite struct{}

var _ = Suite(&typesSuite{})

type testMakeGUIDData struct {
	a        uint32
	b        uint16
	c        uint16
	d        uint16
	e        [6]uint8
	expected []byte
}

func (s *typesSuite) testMakeGUID(c *C, data *testMakeGUIDData) {
	g := MakeGUID(data.a, data.b, data.c, data.d, data.e)
	var expected GUID
	copy(expected[:], data.expected)
	c.Check(g, Equals, expected)
}

func (s *typesSuite) TestMakeGUID1(c *C) {
	s.testMakeGUID(c, &testMakeGUIDData{
		a: 0x8be4df61, b: 0x93ca, c: 0x11d2, d: 0xaa0d, e: [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c},
		expected: decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8c")})
}

func (s *typesSuite) TestMakeGUID2(c *C) {
	s.testMakeGUID(c, &testMakeGUIDData{
		a: 0xd719b2cb, b: 0x3d3a, c: 0x4596, d: 0xa3bc, e: [...]uint8{0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f},
		expected: decodeHexString(c, "cbb219d73a3d9645a3bcdad00e67656f")})
}

type testGUIDStringData struct {
	x        []byte
	expected string
}

func (s *typesSuite) testGUIDString(c *C, data *testGUIDStringData) {
	var g GUID
	copy(g[:], data.x)
	c.Check(g.String(), Equals, data.expected)
}

func (s *typesSuite) TestGUIDString1(c *C) {
	s.testGUIDString(c, &testGUIDStringData{
		x:        decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8c"),
		expected: "8be4df61-93ca-11d2-aa0d-00e098032b8c"})
}

func (s *typesSuite) TestGUIDString2(c *C) {
	s.testGUIDString(c, &testGUIDStringData{
		x:        decodeHexString(c, "cbb219d73a3d9645a3bcdad00e67656f"),
		expected: "d719b2cb-3d3a-4596-a3bc-dad00e67656f"})
}

type testReadGUIDData struct {
	r        *bytes.Reader
	expected []byte
}

func (s *typesSuite) testReadGUID(c *C, data *testReadGUIDData) {
	start := data.r.Len()
	out, err := ReadGUID(data.r)
	c.Check(err, IsNil)
	c.Check(start-data.r.Len(), Equals, 16)
	var expected GUID
	copy(expected[:], data.expected)
	c.Check(out, Equals, expected)
}

func (s *typesSuite) TestReadGUID1(c *C) {
	s.testReadGUID(c, &testReadGUIDData{
		r:        bytes.NewReader(decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8c")),
		expected: decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8c")})
}

func (s *typesSuite) TestReadGUID2(c *C) {
	s.testReadGUID(c, &testReadGUIDData{
		r:        bytes.NewReader(decodeHexString(c, "cbb219d73a3d9645a3bcdad00e67656f")),
		expected: decodeHexString(c, "cbb219d73a3d9645a3bcdad00e67656f")})
}

func (s *typesSuite) TestReadGUID3(c *C) {
	s.testReadGUID(c, &testReadGUIDData{
		r:        bytes.NewReader(decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8caaaaaaaaaaaaaa")),
		expected: decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8c")})
}

type testReadPartitionTableHeaderData struct {
	r        *bytes.Reader
	expected *PartitionTableHeader
}

func (s *typesSuite) testReadPartitionTableHeader(c *C, data *testReadPartitionTableHeaderData) {
	start := data.r.Len()
	out, err := ReadPartitionTableHeader(data.r)
	c.Assert(err, IsNil)
	c.Check(start-data.r.Len(), Equals, 92)
	c.Check(out, DeepEquals, data.expected)
}

func (s *typesSuite) TestReadPartitionTableHeader1(c *C) {
	s.testReadPartitionTableHeader(c, &testReadPartitionTableHeaderData{
		r: bytes.NewReader(decodeHexString(c, "4546492050415254000001005c000000edeb4e64000000000100000000000000af5277ee000000002200000000"+
			"0000008e5277ee00000000c273aea42f0e1345bd3c456da7f7f0fd02000000000000008000000080000000f628450b")),
		expected: &PartitionTableHeader{
			TableHeader: TableHeader{
				Signature:  0x5452415020494645,
				Revision:   0x10000,
				HeaderSize: 92,
				CRC:        0x644eebed,
				Reserved:   0},
			MyLBA:                    1,
			AlternateLBA:             4000797359,
			FirstUsableLBA:           34,
			LastUsableLBA:            4000797326,
			DiskGUID:                 MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
			PartitionEntryLBA:        2,
			NumberOfPartitionEntries: 128,
			SizeOfPartitionEntry:     128,
			PartitionEntryArrayCRC32: 0x0b4528f6}})
}

func (s *typesSuite) TestReadPartitionTableHeader2(c *C) {
	s.testReadPartitionTableHeader(c, &testReadPartitionTableHeaderData{
		r: bytes.NewReader(decodeHexString(c, "4546492050415254000001005c000000edeb4e64000000000100000000000000af5277ee000000002200000000"+
			"0000008e5277ee00000000c273aea42f0e1345bd3c456da7f7f0fd02000000000000008000000080000000f628450ba5a5a5a5a5a5a5a5")),
		expected: &PartitionTableHeader{
			TableHeader: TableHeader{
				Signature:  0x5452415020494645,
				Revision:   0x10000,
				HeaderSize: 92,
				CRC:        0x644eebed,
				Reserved:   0},
			MyLBA:                    1,
			AlternateLBA:             4000797359,
			FirstUsableLBA:           34,
			LastUsableLBA:            4000797326,
			DiskGUID:                 MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
			PartitionEntryLBA:        2,
			NumberOfPartitionEntries: 128,
			SizeOfPartitionEntry:     128,
			PartitionEntryArrayCRC32: 0x0b4528f6}})
}

type testDecodePartitionEntryData struct {
	r        *bytes.Reader
	sz       uint32
	expected *PartitionEntry
}

func (s *typesSuite) testDecodePartitionEntry(c *C, data *testDecodePartitionEntryData) {
	start := data.r.Len()
	raw, err := ReadPartitionEntry(data.r, data.sz)
	c.Check(err, IsNil)
	c.Check(start-data.r.Len(), Equals, int(data.sz))
	entry, err := raw.Decode()
	c.Assert(err, IsNil)
	c.Check(entry, DeepEquals, data.expected)
}

func (s *typesSuite) TestDecodePartitionEntry1(c *C) {
	s.testDecodePartitionEntry(c, &testDecodePartitionEntryData{
		r: bytes.NewReader(decodeHexString(c, "28732ac11ff8d211ba4b00a0c93ec93b7b94de66b2fd2545b75230d66bb2b9600008000000000000ff071000"+
			"0000000000000000000000004500460049002000530079007300740065006d00200050006100720074006900740069006f006e00000000000000000000000000"+
			"0000000000000000000000000000000000000000")),
		sz: 128,
		expected: &PartitionEntry{
			PartitionTypeGUID:   MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
			UniquePartitionGUID: MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
			StartingLBA:         2048,
			EndingLBA:           1050623,
			Attributes:          0,
			PartitionName:       "EFI System Partition"}})
}

func (s *typesSuite) TestDecodePartitionEntry2(c *C) {
	s.testDecodePartitionEntry(c, &testDecodePartitionEntryData{
		r: bytes.NewReader(decodeHexString(c, "af3dc60f838472478e793d69d8477de4dc171b63b7ed1d4da7616dce3efce4150008100000000000ffe72600000"+
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"+
			"0000000000000000000000000000000000000")),
		sz: 128,
		expected: &PartitionEntry{
			PartitionTypeGUID:   MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
			UniquePartitionGUID: MakeGUID(0x631b17dc, 0xedb7, 0x4d1d, 0xa761, [...]uint8{0x6d, 0xce, 0x3e, 0xfc, 0xe4, 0x15}),
			StartingLBA:         1050624,
			EndingLBA:           2549759,
			Attributes:          0,
			PartitionName:       ""}})
}

type testDecodeSignatureDatabaseData struct {
	path string
	db   SignatureDatabase
}

func (s *typesSuite) testDecodeSignatureDatabase(c *C, data *testDecodeSignatureDatabaseData) {
	f, err := os.Open(data.path)
	c.Assert(err, IsNil)
	defer f.Close()

	db, err := DecodeSignatureDatabase(f)
	c.Check(err, IsNil)
	c.Check(db, DeepEquals, data.db)
}

var microsoftOwnerGuid = MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b})
var dellOwnerGuid = MakeGUID(0x70564dce, 0x9afc, 0x4ee3, 0x85fc, [...]uint8{0x94, 0x96, 0x49, 0xd7, 0xe4, 0x5c})

func (s *typesSuite) TestDecodeSignatureDatabase1(c *C) {
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

func (s *typesSuite) TestDecodeSignatureDatabase2(c *C) {
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

func (s *typesSuite) TestDecodeSignatureDatabase3(c *C) {
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

func (s *typesSuite) TestDecodeSignatureDatabase4(c *C) {
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

func (s *typesSuite) TestDecodeSignatureListWithInconsistentSizeFields(c *C) {
	f, err := os.Open("testdata/sigdbs/inconsistent-sizes.siglist")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = DecodeSignatureDatabase(f)
	c.Check(err, ErrorMatches, "EFI_SIGNATURE_LIST 1 has inconsistent size fields")
}

func (s *typesSuite) TestDecodeSignatureListWithInvalidSignatureSize(c *C) {
	f, err := os.Open("testdata/sigdbs/invalid-signature-size.siglist")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = DecodeSignatureDatabase(f)
	c.Check(err, ErrorMatches, "EFI_SIGNATURE_LIST 0 has an invalid SignatureSize field")
}

func (s *typesSuite) testEncodeSignatureDatabase(c *C, path string) {
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

func (s *typesSuite) TestEncodeSignatureDatabase1(c *C) {
	s.testEncodeSignatureDatabase(c, "testdata/sigdbs/1.siglist")
}

func (s *typesSuite) TestEncodeSignatureDatabase2(c *C) {
	s.testEncodeSignatureDatabase(c, "testdata/sigdbs/2.siglist")
}

func (s *typesSuite) TestEncodeSignatureDatabase3(c *C) {
	s.testEncodeSignatureDatabase(c, "testdata/sigdbs/3.siglist")
}

func (s *typesSuite) TestEncodeSignatureDatabase4(c *C) {
	s.testEncodeSignatureDatabase(c, "testdata/sigdbs/4.siglist")
}

func (s *typesSuite) TestEncodeSignatureWithWrongSize(c *C) {
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

func (s *typesSuite) TestDecodeWinCertificateGUID(c *C) {
	f, err := os.Open("testdata/sigs/cert-type-guid.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	cert, err := DecodeWinCertificate(f)
	c.Assert(err, IsNil)
	guidCert, ok := cert.(*WinCertificateGUID)
	c.Assert(ok, Equals, true)
	c.Check(guidCert.Type, Equals, CertTypePKCS7Guid)
}

func (s *typesSuite) TestDecodeWinCertificateAuthenticode(c *C) {
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

func (s *typesSuite) TestDecodeWinCertificateInvalidRevision(c *C) {
	f, err := os.Open("testdata/sigs/cert-invalid-revision.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = DecodeWinCertificate(f)
	c.Assert(err, ErrorMatches, "unexpected revision")
}

func (s *typesSuite) TestDecodeWinCertificateInvalidType(c *C) {
	f, err := os.Open("testdata/sigs/cert-invalid-type.sig")
	c.Assert(err, IsNil)
	defer f.Close()

	_, err = DecodeWinCertificate(f)
	c.Assert(err, ErrorMatches, "unexpected type")
}

func (s *typesSuite) TestDecodeTimeBasedVariableAuthentication(c *C) {
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
