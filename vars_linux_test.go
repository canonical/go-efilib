// Copyright 2021 Canonical Ltd.
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
	"time"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-efilib"
)

const immutableFlag = 0x00000010

type mockDirent struct {
	name string
	mode os.FileMode
	size int64
}

func (d mockDirent) Name() string       { return string(d.name) }
func (d mockDirent) Size() int64        { return d.size }
func (d mockDirent) Mode() os.FileMode  { return d.mode }
func (d mockDirent) ModTime() time.Time { return time.Time{} }
func (d mockDirent) IsDir() bool        { return d.mode.IsDir() }
func (d mockDirent) Sys() interface{}   { return nil }

type mockEfivarfsFile struct {
	name   string
	fs     *mockEfiVarfs
	v      *mockEfiVar
	closed bool
}

func (f *mockEfivarfsFile) Read(_ []byte) (int, error) {
	if f.closed {
		return 0, errors.New("file already closed")
	}

	return 0, f.pathErr("read", syscall.EBADF)
}

func (f *mockEfivarfsFile) Write(_ []byte) (int, error) {
	if f.closed {
		return 0, errors.New("file already closed")
	}

	return 0, f.pathErr("write", syscall.EBADF)
}

func (f *mockEfivarfsFile) Close() error {
	if f.closed {
		return errors.New("file already closed")
	}
	f.closed = true
	f.fs.openCount -= 1
	return nil
}

func (f *mockEfivarfsFile) Readdir(n int) ([]os.FileInfo, error) {
	if f.closed {
		return nil, errors.New("file already closed")
	}
	return nil, &os.PathError{Op: "readdirent", Path: f.name, Err: syscall.EBADF}
}

func (f *mockEfivarfsFile) GetInodeFlags() (uint32, error) {
	if f.closed {
		return 0, errors.New("file already closed")
	}
	return f.v.flags, nil
}

func (f *mockEfivarfsFile) SetInodeFlags(flags uint32) error {
	if f.closed {
		return errors.New("file already closed")
	}
	f.v.flags = flags
	return nil
}

func (f *mockEfivarfsFile) pathErr(op string, err error) error {
	return &os.PathError{Op: op, Path: f.name, Err: err}
}

type mockEfivarfsWriterFile struct {
	flags int
	*mockEfivarfsFile
}

func (w *mockEfivarfsWriterFile) Write(data []byte) (int, error) {
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

	if len(w.v.data) > 0 && VariableAttributes(binary.LittleEndian.Uint32(w.v.data)) != attrs {
		return 0, w.pathErr("write", syscall.EINVAL)
	}

	n := len(data)

	switch {
	case w.flags&os.O_APPEND != 0:
		if len(w.v.data) > 0 {
			data = data[4:]
		}
		w.v.data = append(w.v.data, data...)
	case len(data) == 4:
		w.v.data = nil
	default:
		w.v.data = data
	}

	return n, nil
}

type mockEfivarfsReaderFile struct {
	io.Reader
	*mockEfivarfsFile
}

func (r *mockEfivarfsReaderFile) Read(data []byte) (int, error) {
	if r.closed {
		return 0, errors.New("file already closed")
	}
	return r.Reader.Read(data)
}

type mockEfivarfsDir struct {
	*mockEfivarfsFile
}

func (f *mockEfivarfsDir) Read(_ []byte) (int, error) {
	if f.closed {
		return 0, errors.New("file already closed")
	}
	return 0, io.EOF
}

func (f *mockEfivarfsDir) Readdir(n int) (out []os.FileInfo, err error) {
	if f.closed {
		return nil, errors.New("file already closed")
	}
	out = append(out, mockDirent{name: ".", mode: os.ModeDir | 0755})
	out = append(out, mockDirent{name: "..", mode: os.ModeDir | 0755})
	for k, v := range f.fs.vars {
		out = append(out, mockDirent{filepath.Base(k), v.mode, int64(len(v.data))})
	}
	if n < 0 {
		return out, nil
	}
	if n > len(out) {
		n = len(out)
	}
	return out[:n], nil
}

func (f *mockEfivarfsDir) SetInodeFlags(flags uint32) error {
	return errors.New("unsupported")
}

type mockEfiVar struct {
	data  []byte
	mode  os.FileMode
	flags uint32
}

type mockEfiVarfs struct {
	vars      map[string]*mockEfiVar
	openCount int
}

func (m *mockEfiVarfs) Open(name string, flags int, perm os.FileMode) (VarFile, error) {
	if flags&^(os.O_RDONLY|os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL) != 0 {
		return nil, errors.New("forbidden flags")
	}

	switch flags & (os.O_RDONLY | os.O_WRONLY) {
	case os.O_RDONLY:
		if name == "/sys/firmware/efi/efivars" {
			m.openCount += 1
			return &mockEfivarfsDir{mockEfivarfsFile: &mockEfivarfsFile{name: name, fs: m}}, nil
		}
		v, ok := m.vars[name]
		if !ok {
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ENOENT}
		}
		m.openCount += 1
		return &mockEfivarfsReaderFile{Reader: bytes.NewReader(v.data), mockEfivarfsFile: &mockEfivarfsFile{name: name, v: v, fs: m}}, nil
	case os.O_WRONLY:
		v, ok := m.vars[name]
		switch {
		case !ok && flags&os.O_CREATE == 0:
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ENOENT}
		case !ok && perm&os.ModeType != 0:
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EINVAL}
		case !ok:
			v = &mockEfiVar{mode: perm, flags: immutableFlag}
			m.vars[name] = v
		case v.flags&immutableFlag != 0:
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EPERM}
		}
		m.openCount += 1
		return &mockEfivarfsWriterFile{flags: flags, mockEfivarfsFile: &mockEfivarfsFile{name: name, v: v, fs: m}}, nil
	default:
		return nil, syscall.EINVAL
	}
}

type varsLinuxSuite struct {
	mockEfiVarfs       *mockEfiVarfs
	restoreBackend     func()
	restoreOpenVarFile func()
}

func (s *varsLinuxSuite) SetUpTest(c *C) {
	s.mockEfiVarfs = &mockEfiVarfs{vars: make(map[string]*mockEfiVar)}
	s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = &mockEfiVar{data: decodeHexString(c, "0600000001"), flags: immutableFlag}
	s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = &mockEfiVar{data: decodeHexString(c, "070000000000")}
	s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{data: decodeHexString(c, "07000000a5a5a5a5"), flags: immutableFlag}

	s.restoreBackend = MockVarsBackend(EfivarfsVarsBackend{})
	s.restoreOpenVarFile = MockOpenVarFile(s.mockEfiVarfs.Open)
}

func (s *varsLinuxSuite) TearDownTest(c *C) {
	s.restoreOpenVarFile()
	s.restoreBackend()
	c.Check(s.mockEfiVarfs.openCount, Equals, 0)
}

var _ = Suite(&varsLinuxSuite{})

func (s *varsLinuxSuite) TestProbeEfivarfs(c *C) {
	restore := MockVarsStatfs(func(path string, st *unix.Statfs_t) error {
		if path != "/sys/firmware/efi/efivars" {
			return syscall.ENOENT
		}

		if err := unix.Statfs("testdata", st); err != nil {
			return err
		}
		st.Type = EFIVARFS_MAGIC
		return nil
	})
	defer restore()

	c.Check(ProbeEfivarfs(), Equals, true)
}

func (s *varsLinuxSuite) TestProbeEfivarfsNOENT(c *C) {
	restore := MockVarsStatfs(func(path string, st *unix.Statfs_t) error {
		return syscall.ENOENT
	})
	defer restore()

	c.Check(ProbeEfivarfs(), Equals, false)
}

func (s *varsLinuxSuite) TestProbeEfivarfsBadFS(c *C) {
	restore := MockVarsStatfs(func(path string, st *unix.Statfs_t) error {
		unix.Statfs("testdata", st)
		st.Type = unix.SYSFS_MAGIC
		return nil
	})
	defer restore()

	c.Check(ProbeEfivarfs(), Equals, false)
}

type testReadVarData struct {
	name          string
	guid          GUID
	expectedData  []byte
	expectedAttrs VariableAttributes
}

func (s *varsLinuxSuite) testReadVar(c *C, data *testReadVarData) {
	val, attrs, err := ReadVar(data.name, data.guid)
	c.Check(err, IsNil)
	c.Check(val, DeepEquals, data.expectedData)
	c.Check(attrs, Equals, data.expectedAttrs)
}

func (s *varsLinuxSuite) TestReadVar1(c *C) {
	s.testReadVar(c, &testReadVarData{
		name:          "SecureBoot",
		guid:          MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		expectedData:  []byte{0x01},
		expectedAttrs: AttributeBootserviceAccess | AttributeRuntimeAccess})
}

func (s *varsLinuxSuite) TestReadVar2(c *C) {
	s.testReadVar(c, &testReadVarData{
		name:          "BootOrder",
		guid:          MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		expectedData:  []byte{0x00, 0x00},
		expectedAttrs: AttributeNonVolatile | AttributeBootserviceAccess | AttributeRuntimeAccess})
}

func (s *varsLinuxSuite) TestReadVar3(c *C) {
	s.testReadVar(c, &testReadVarData{
		name:          "Test",
		guid:          MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		expectedData:  decodeHexString(c, "a5a5a5a5"),
		expectedAttrs: AttributeNonVolatile | AttributeBootserviceAccess | AttributeRuntimeAccess})
}

func (s *varsLinuxSuite) TestReadVarNotFound1(c *C) {
	_, _, err := ReadVar("NotFound", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *varsLinuxSuite) TestReadVarNotFound2(c *C) {
	s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/NotFound-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{}
	_, _, err := ReadVar("NotFound", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *varsLinuxSuite) TestWriteVarImmutable(c *C) {
	err := WriteVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "080808080808"))
	c.Check(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, decodeHexString(c, "07000000080808080808"))
	c.Check(v.flags, Equals, uint32(immutableFlag))
}

func (s *varsLinuxSuite) TestWriteVarMutable(c *C) {
	err := WriteVar("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "0001"))
	c.Check(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, decodeHexString(c, "070000000001"))
	c.Check(v.flags, Equals, uint32(0))
}

func (s *varsLinuxSuite) TestWriteVarAppend(c *C) {
	err := WriteVar("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeAppendWrite,
		decodeHexString(c, "0001"))
	c.Check(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, decodeHexString(c, "0700000000000001"))
	c.Check(v.flags, Equals, uint32(0))
}

func (s *varsLinuxSuite) TestCreateVar(c *C) {
	err := WriteVar("Test2", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "a5a5a5a5"))
	c.Assert(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test2-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, decodeHexString(c, "07000000a5a5a5a5"))
	c.Check(v.mode, Equals, os.FileMode(0644))
}

func (s *varsLinuxSuite) TestWriteVarEACCES(c *C) {
	var restore func()
	restore = MockOpenVarFile(func(path string, flags int, perm os.FileMode) (VarFile, error) {
		if flags&os.O_WRONLY == 0 {
			return nil, Defer
		}

		restore()
		restore = nil
		return nil, &os.PathError{Op: "open", Path: path, Err: syscall.EACCES}
	})
	defer func() {
		if restore == nil {
			return
		}
		restore()
	}()

	err := WriteVar("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "0001"))
	c.Check(err, Equals, ErrVarPermission)
}

func (s *varsLinuxSuite) TestWriteVarRace(c *C) {
	var restore func()
	restore = MockOpenVarFile(func(path string, flags int, perm os.FileMode) (VarFile, error) {
		if flags&os.O_WRONLY != 0 {
			// Simulate another process flipping the immutable flag back
			s.mockEfiVarfs.vars[path].flags = immutableFlag
			restore()
			restore = nil
		}

		return nil, Defer
	})
	defer func() {
		if restore == nil {
			return
		}
		restore()
	}()

	err := WriteVar("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "0001"))
	c.Check(err, IsNil)
}

func (s *varsLinuxSuite) TestWriteVarRaceGiveUp(c *C) {
	count := 0
	restore := MockOpenVarFile(func(path string, flags int, perm os.FileMode) (VarFile, error) {
		if flags&os.O_WRONLY != 0 {
			// Simulate another process flipping the immutable flag back
			s.mockEfiVarfs.vars[path].flags = immutableFlag
			count += 1
		}

		return nil, Defer
	})
	defer restore()

	err := WriteVar("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "0001"))
	c.Check(err, Equals, ErrVarPermission)
	c.Check(count, Equals, 5)
}

func (s *varsLinuxSuite) TestListVars(c *C) {
	ents, err := ListVars()
	c.Check(err, IsNil)
	c.Check(ents, DeepEquals, []VarEntry{
		{Name: "BootOrder", GUID: MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c})},
		{Name: "SecureBoot", GUID: MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c})},
		{Name: "Test", GUID: MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20})}})
}

func (s *varsLinuxSuite) TestListVarsInvalidNames(c *C) {
	fs := &mockEfiVarfs{vars: make(map[string]*mockEfiVar)}
	fs.vars["Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{data: decodeHexString(c, "00000000000000000000"), mode: os.ModeDir | 0755}
	fs.vars["e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{data: decodeHexString(c, "00000000000000000000"), mode: 0644}
	fs.vars["Test+e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{data: decodeHexString(c, "00000000000000000000"), mode: 0644}
	fs.vars["Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{mode: 0644}
	fs.vars["Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{data: decodeHexString(c, "00000000000000000000"), mode: 0644}

	restore := MockOpenVarFile(fs.Open)
	defer restore()

	ents, err := ListVars()
	c.Check(err, IsNil)
	c.Check(ents, DeepEquals, []VarEntry{{Name: "Test", GUID: MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20})}})
}
