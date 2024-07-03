// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

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

func (f *mockEfivarfsFile) GetInodeFlags() (uint, error) {
	if f.closed {
		return 0, errors.New("file already closed")
	}
	return f.v.flags, nil
}

func (f *mockEfivarfsFile) SetInodeFlags(flags uint) error {
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

func (f *mockEfivarfsDir) SetInodeFlags(flags uint) error {
	return errors.New("unsupported")
}

type mockEfiVar struct {
	data  []byte
	mode  os.FileMode
	flags uint
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

func (m *mockEfiVarfs) Remove(path string) error {
	v, ok := m.vars[path]
	if !ok {
		return &os.PathError{Op: "unlink", Path: path, Err: syscall.ENOENT}
	}

	if v.flags&immutableFlag != 0 {
		return &os.PathError{Op: "open", Path: path, Err: syscall.EPERM}
	}

	delete(m.vars, path)
	return nil
}

var efivarfsVarContext = WithVarsBackend(context.Background(), EfivarfsVarsBackend{})

type varsLinuxSuite struct {
	mockEfiVarfs         *mockEfiVarfs
	restoreOpenVarFile   func()
	restoreRemoveVarFile func()
}

func (s *varsLinuxSuite) SetUpTest(c *C) {
	s.mockEfiVarfs = &mockEfiVarfs{vars: make(map[string]*mockEfiVar)}
	s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = &mockEfiVar{data: DecodeHexString(c, "0600000001"), flags: immutableFlag}
	s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = &mockEfiVar{data: DecodeHexString(c, "070000000000")}
	s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{data: DecodeHexString(c, "07000000a5a5a5a5"), flags: immutableFlag}
	s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test2-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{data: DecodeHexString(c, "070000005a5a5a5a")}

	s.restoreOpenVarFile = MockOpenVarFile(s.mockEfiVarfs.Open)
	s.restoreRemoveVarFile = MockRemoveVarFile(s.mockEfiVarfs.Remove)
}

func (s *varsLinuxSuite) TearDownTest(c *C) {
	s.restoreRemoveVarFile()
	s.restoreOpenVarFile()
	c.Check(s.mockEfiVarfs.openCount, Equals, 0)
}

var _ = Suite(&varsLinuxSuite{})

type testReadVariableData struct {
	name          string
	guid          GUID
	expectedData  []byte
	expectedAttrs VariableAttributes
}

func (s *varsLinuxSuite) testReadVariable(c *C, data *testReadVariableData) {
	val, attrs, err := ReadVariable(efivarfsVarContext, data.name, data.guid)
	c.Check(err, IsNil)
	c.Check(val, DeepEquals, data.expectedData)
	c.Check(attrs, Equals, data.expectedAttrs)
}

func (s *varsLinuxSuite) TestReadVariable1(c *C) {
	s.testReadVariable(c, &testReadVariableData{
		name:          "SecureBoot",
		guid:          MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		expectedData:  []byte{0x01},
		expectedAttrs: AttributeBootserviceAccess | AttributeRuntimeAccess})
}

func (s *varsLinuxSuite) TestReadVariable2(c *C) {
	s.testReadVariable(c, &testReadVariableData{
		name:          "BootOrder",
		guid:          MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		expectedData:  []byte{0x00, 0x00},
		expectedAttrs: AttributeNonVolatile | AttributeBootserviceAccess | AttributeRuntimeAccess})
}

func (s *varsLinuxSuite) TestReadVariable3(c *C) {
	s.testReadVariable(c, &testReadVariableData{
		name:          "Test",
		guid:          MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		expectedData:  DecodeHexString(c, "a5a5a5a5"),
		expectedAttrs: AttributeNonVolatile | AttributeBootserviceAccess | AttributeRuntimeAccess})
}

func (s *varsLinuxSuite) TestReadVariableNotFound1(c *C) {
	_, _, err := ReadVariable(efivarfsVarContext, "NotFound", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *varsLinuxSuite) TestReadVariableNotFound2(c *C) {
	s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/NotFound-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{}
	_, _, err := ReadVariable(efivarfsVarContext, "NotFound", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *varsLinuxSuite) TestWriteVariableImmutable(c *C) {
	err := WriteVariable(efivarfsVarContext, "Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, DecodeHexString(c, "080808080808"))
	c.Check(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, DecodeHexString(c, "07000000080808080808"))
	c.Check(v.flags, Equals, uint(immutableFlag))
}

func (s *varsLinuxSuite) TestWriteVariableMutable(c *C) {
	err := WriteVariable(efivarfsVarContext, "BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, DecodeHexString(c, "0001"))
	c.Check(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, DecodeHexString(c, "070000000001"))
	c.Check(v.flags, Equals, uint(0))
}

func (s *varsLinuxSuite) TestWriteVariableAppend(c *C) {
	err := WriteVariable(efivarfsVarContext, "BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeAppendWrite,
		DecodeHexString(c, "0001"))
	c.Check(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, DecodeHexString(c, "0700000000000001"))
	c.Check(v.flags, Equals, uint(0))
}

func (s *varsLinuxSuite) TestCreateVariable(c *C) {
	err := WriteVariable(efivarfsVarContext, "Test3", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, DecodeHexString(c, "a5a5a5a5"))
	c.Assert(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test3-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, DecodeHexString(c, "07000000a5a5a5a5"))
	c.Check(v.mode, Equals, os.FileMode(0644))
}

func (s *varsLinuxSuite) TestDeleteVariableImmutable(c *C) {
	err := WriteVariable(efivarfsVarContext, "Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	c.Check(err, IsNil)

	_, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"]
	c.Check(ok, Equals, false)
}

func (s *varsLinuxSuite) TestDeleteVariableMutable(c *C) {
	err := WriteVariable(efivarfsVarContext, "Test2", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	c.Check(err, IsNil)

	_, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test2-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"]
	c.Check(ok, Equals, false)
}

func (s *varsLinuxSuite) TestDeleteVariableNotExist(c *C) {
	err := WriteVariable(efivarfsVarContext, "NotFound", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	c.Check(err, IsNil)
}

func (s *varsLinuxSuite) TestWriteVariableEACCES(c *C) {
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

	err := WriteVariable(efivarfsVarContext, "BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, DecodeHexString(c, "0001"))
	c.Check(err, Equals, ErrVarPermission)
}

func (s *varsLinuxSuite) TestWriteVariableRace(c *C) {
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

	err := WriteVariable(efivarfsVarContext, "BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, DecodeHexString(c, "0001"))
	c.Check(err, IsNil)
}

func (s *varsLinuxSuite) TestWriteVariableRaceGiveUp(c *C) {
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

	err := WriteVariable(efivarfsVarContext, "BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, DecodeHexString(c, "0001"))
	c.Check(err, Equals, ErrVarPermission)
	c.Check(count, Equals, 5)
}

func (s *varsLinuxSuite) TestDeleteVariableRace(c *C) {
	var restore func()
	restore = MockRemoveVarFile(func(path string) error {
		// Simulate another process flipping the immutable flag back
		s.mockEfiVarfs.vars[path].flags = immutableFlag
		restore()
		restore = nil

		return Defer
	})
	defer func() {
		if restore == nil {
			return
		}
		restore()
	}()

	err := WriteVariable(efivarfsVarContext, "Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	c.Check(err, IsNil)

	_, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"]
	c.Check(ok, Equals, false)
}

func (s *varsLinuxSuite) TestDeleteVariableRaceGiveUp(c *C) {
	count := 0
	restore := MockRemoveVarFile(func(path string) error {
		// Simulate another process flipping the immutable flag back
		s.mockEfiVarfs.vars[path].flags = immutableFlag
		count += 1
		return Defer
	})
	defer restore()

	err := WriteVariable(efivarfsVarContext, "Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, nil)
	c.Check(err, Equals, ErrVarPermission)
	c.Check(count, Equals, 5)
}

func (s *varsLinuxSuite) TestListVariables(c *C) {
	ents, err := ListVariables(efivarfsVarContext)
	c.Check(err, IsNil)
	c.Check(ents, DeepEquals, []VariableDescriptor{
		{Name: "Test", GUID: MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20})},
		{Name: "Test2", GUID: MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20})},
		{Name: "BootOrder", GUID: MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c})},
		{Name: "SecureBoot", GUID: MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c})}})
}

func (s *varsLinuxSuite) TestListVariablesInvalidNames(c *C) {
	fs := &mockEfiVarfs{vars: make(map[string]*mockEfiVar)}
	fs.vars["Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{data: DecodeHexString(c, "00000000000000000000"), mode: os.ModeDir | 0755}
	fs.vars["e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{data: DecodeHexString(c, "00000000000000000000"), mode: 0644}
	fs.vars["Test+e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{data: DecodeHexString(c, "00000000000000000000"), mode: 0644}
	fs.vars["Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{mode: 0644}
	fs.vars["Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{data: DecodeHexString(c, "00000000000000000000"), mode: 0644}

	restore := MockOpenVarFile(fs.Open)
	defer restore()

	ents, err := ListVariables(efivarfsVarContext)
	c.Check(err, IsNil)
	c.Check(ents, DeepEquals, []VariableDescriptor{{Name: "Test", GUID: MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20})}})
}
