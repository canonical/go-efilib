// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-efilib"
)

type mockVarFile struct {
	name   string
	fs     *mockEfiVarfs
	closed bool
}

func (f *mockVarFile) Close() error {
	if f.closed {
		return errors.New("file already closed")
	}
	f.closed = true
	f.fs.openCount -= 1
	return nil
}

func (f *mockVarFile) MakeImmutable() (func() error, error) {
	v := f.fs.vars[f.name]
	if !v.immutable {
		return func() error { return nil }, nil
	}
	v.immutable = false
	return func() error {
		v.immutable = true
		return nil
	}, nil
}

func (f *mockVarFile) pathErr(op string, err error) error {
	return &os.PathError{Op: op, Path: filepath.Join("/sys/firmware/efi/efivars", f.name), Err: err}
}

type mockVarWriter struct {
	flags int
	*mockVarFile
}

func (w *mockVarWriter) Read(_ []byte) (int, error) {
	if w.closed {
		return 0, errors.New("file already closed")
	}

	return 0, w.pathErr("read", syscall.EBADF)
}

func (w *mockVarWriter) Write(data []byte) (int, error) {
	if w.closed {
		return 0, errors.New("file already closed")
	}

	if len(data) < 4 {
		return 0, w.pathErr("write", syscall.EINVAL)
	}

	attrs := VariableAttributes(binary.LittleEndian.Uint32(data))

	switch {
	case w.flags&os.O_APPEND != 0 && attrs&AttributeAppendWrite != 0:
	case w.flags&os.O_APPEND == 0 && attrs&AttributeAppendWrite == 0:
	default:
		return 0, w.pathErr("write", syscall.EINVAL)
	}

	attrs &^= AttributeAppendWrite

	v := w.fs.vars[w.name]
	if len(v.data) > 0 && VariableAttributes(binary.LittleEndian.Uint32(v.data)) != attrs {
		return 0, w.pathErr("write", syscall.EINVAL)
	}

	n := len(data)

	switch {
	case w.flags&os.O_APPEND != 0:
		if len(v.data) > 0 {
			data = data[4:]
		}
		v.data = append(v.data, data...)
	case len(data) == 4:
		v.data = nil
	default:
		v.data = data
	}

	return n, nil
}

type mockVarReader struct {
	io.Reader
	*mockVarFile
}

func (r *mockVarReader) Read(data []byte) (int, error) {
	if r.closed {
		return 0, errors.New("file already closed")
	}
	return r.Reader.Read(data)
}

func (r *mockVarReader) Write(_ []byte) (int, error) {
	if r.closed {
		return 0, errors.New("file already closed")
	}

	return 0, &os.PathError{Op: "write", Path: "/foo", Err: syscall.EBADF}
}

type mockEfiVar struct {
	data      []byte
	perm      os.FileMode
	immutable bool
}

type mockEfiVarfs struct {
	vars      map[string]*mockEfiVar
	openCount int
}

func (m *mockEfiVarfs) Open(name string, flags int, perm os.FileMode) (VarReadWriteCloser, error) {
	if flags&^(os.O_RDONLY|os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL) != 0 {
		return nil, errors.New("forbidden flags")
	}

	switch flags & (os.O_RDONLY | os.O_WRONLY) {
	case os.O_RDONLY:
		v, ok := m.vars[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		m.openCount += 1
		return &mockVarReader{Reader: bytes.NewReader(v.data), mockVarFile: &mockVarFile{name: name, fs: m}}, nil
	case os.O_WRONLY:
		v, ok := m.vars[name]
		switch {
		case !ok && flags&os.O_CREATE == 0:
			return nil, os.ErrNotExist
		case !ok && flags&os.O_EXCL == 0:
			return nil, errors.New("forbidden create flags")
		case !ok:
			v = &mockEfiVar{perm: perm, immutable: true}
			m.vars[name] = v
		case v.immutable:
			return nil, os.ErrPermission
		}
		m.openCount += 1
		return &mockVarWriter{flags: flags, mockVarFile: &mockVarFile{name: name, fs: m}}, nil
	default:
		return nil, syscall.EINVAL
	}
}

type varsSuite struct {
	mockEfiVarfs *mockEfiVarfs

	restoreVarsStatfs  func()
	restoreOpenVarFile func()
}

func (s *varsSuite) SetUpTest(c *C) {
	s.mockEfiVarfs = &mockEfiVarfs{vars: make(map[string]*mockEfiVar)}
	s.mockEfiVarfs.vars["SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = &mockEfiVar{data: decodeHexString(c, "0600000001"), immutable: true}
	s.mockEfiVarfs.vars["BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = &mockEfiVar{data: decodeHexString(c, "070000000000")}
	s.mockEfiVarfs.vars["Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{data: decodeHexString(c, "07000000a5a5a5a5"), immutable: true}

	s.restoreVarsStatfs = MockVarsStatfs(func(path string, st *unix.Statfs_t) error {
		if path != "/sys/firmware/efi/efivars" {
			return syscall.ENOENT
		}

		if err := unix.Statfs("testdata", st); err != nil {
			return err
		}
		st.Type = unix.EFIVARFS_MAGIC
		return nil
	})

	s.restoreOpenVarFile = MockOpenVarFile(func(path string, flags int, perm os.FileMode) (VarReadWriteCloser, error) {
		name, err := filepath.Rel("/sys/firmware/efi/efivars", path)
		if err != nil {
			return nil, err
		}
		return s.mockEfiVarfs.Open(name, flags, perm)
	})
}

func (s *varsSuite) TearDownTest(c *C) {
	s.restoreOpenVarFile()
	s.restoreVarsStatfs()

	c.Check(s.mockEfiVarfs.openCount, Equals, 0)
}

var _ = Suite(&varsSuite{})

type testReadVarData struct {
	name          string
	guid          GUID
	expectedData  []byte
	expectedAttrs VariableAttributes
}

func (s *varsSuite) testReadVar(c *C, data *testReadVarData) {
	val, attrs, err := ReadVar(data.name, data.guid)
	c.Check(err, IsNil)
	c.Check(val, DeepEquals, data.expectedData)
	c.Check(attrs, Equals, data.expectedAttrs)
}

func (s *varsSuite) TestReadVar1(c *C) {
	s.testReadVar(c, &testReadVarData{
		name:          "SecureBoot",
		guid:          MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		expectedData:  []byte{0x01},
		expectedAttrs: AttributeBootserviceAccess | AttributeRuntimeAccess})
}

func (s *varsSuite) TestReadVar2(c *C) {
	s.testReadVar(c, &testReadVarData{
		name:          "BootOrder",
		guid:          MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		expectedData:  []byte{0x00, 0x00},
		expectedAttrs: AttributeNonVolatile | AttributeBootserviceAccess | AttributeRuntimeAccess})
}

func (s *varsSuite) TestReadVar3(c *C) {
	s.testReadVar(c, &testReadVarData{
		name:          "Test",
		guid:          MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		expectedData:  decodeHexString(c, "a5a5a5a5"),
		expectedAttrs: AttributeNonVolatile | AttributeBootserviceAccess | AttributeRuntimeAccess})
}

func (s *varsSuite) TestReadVarNotFound1(c *C) {
	_, _, err := ReadVar("NotFound", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVariableNotFound)
}

func (s *varsSuite) TestReadVarNotFound2(c *C) {
	s.mockEfiVarfs.vars["NotFound-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{}
	_, _, err := ReadVar("NotFound", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVariableNotFound)
}

func (s *varsSuite) TestReadVarVarsUnavailable1(c *C) {
	restore := MockVarsStatfs(func(path string, st *unix.Statfs_t) error {
		if err := unix.Statfs(filepath.Join("testdata", path), st); err != nil {
			return err
		}
		st.Type = unix.SYSFS_MAGIC
		return nil
	})
	defer restore()

	_, _, err := ReadVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVarsUnavailable)
}

func (s *varsSuite) TestReadVarVarsUnavailable2(c *C) {
	restore := MockVarsStatfs(func(path string, st *unix.Statfs_t) error {
		return syscall.ENOENT
	})
	defer restore()

	_, _, err := ReadVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVarsUnavailable)
}

func (s *varsSuite) TestWriteVariableImmutable(c *C) {
	err := WriteVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "080808080808"))
	c.Check(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, decodeHexString(c, "07000000080808080808"))
	c.Check(v.immutable, Equals, true)
}

func (s *varsSuite) TestWriteVariableMutable(c *C) {
	err := WriteVar("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "0001"))
	c.Check(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, decodeHexString(c, "070000000001"))
	c.Check(v.immutable, Equals, false)
}

func (s *varsSuite) TestWriteVariableAppend(c *C) {
	err := WriteVar("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeAppendWrite,
		decodeHexString(c, "0001"))
	c.Check(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, decodeHexString(c, "0700000000000001"))
	c.Check(v.immutable, Equals, false)
}

func (s *varsSuite) TestCreateVariable(c *C) {
	err := WriteVar("Test2", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "a5a5a5a5"))
	c.Assert(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["Test2-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, decodeHexString(c, "07000000a5a5a5a5"))
	c.Check(v.perm, Equals, os.FileMode(0644))
}
