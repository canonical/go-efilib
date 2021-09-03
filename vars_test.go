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
	"sort"
	"syscall"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-efilib"
)

type mockDirent struct {
	name string
	mode os.FileMode
}

func (d mockDirent) Name() string { return string(d.name) }

func (d mockDirent) IsDir() bool                { return d.mode.IsDir() }
func (d mockDirent) Type() os.FileMode          { return d.mode }
func (d mockDirent) Info() (os.FileInfo, error) { return nil, nil }

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
	return &os.PathError{Op: op, Path: f.name, Err: err}
}

type mockVarWriterFile struct {
	flags int
	*mockVarFile
}

func (w *mockVarWriterFile) Read(_ []byte) (int, error) {
	if w.closed {
		return 0, errors.New("file already closed")
	}

	return 0, w.pathErr("read", syscall.EBADF)
}

func (w *mockVarWriterFile) Write(data []byte) (int, error) {
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

type mockVarReaderFile struct {
	io.Reader
	*mockVarFile
}

func (r *mockVarReaderFile) Read(data []byte) (int, error) {
	if r.closed {
		return 0, errors.New("file already closed")
	}
	return r.Reader.Read(data)
}

func (r *mockVarReaderFile) Write(_ []byte) (int, error) {
	if r.closed {
		return 0, errors.New("file already closed")
	}

	return 0, r.pathErr("write", syscall.EBADF)
}

type mockEfiVar struct {
	data      []byte
	mode      os.FileMode
	immutable bool
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
		v, ok := m.vars[name]
		if !ok {
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ENOENT}
		}
		m.openCount += 1
		return &mockVarReaderFile{Reader: bytes.NewReader(v.data), mockVarFile: &mockVarFile{name: name, fs: m}}, nil
	case os.O_WRONLY:
		v, ok := m.vars[name]
		switch {
		case !ok && flags&os.O_CREATE == 0:
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ENOENT}
		case !ok && perm&os.ModeType != 0:
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EINVAL}
		case !ok:
			v = &mockEfiVar{mode: perm, immutable: true}
			m.vars[name] = v
		case v.immutable:
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EPERM}
		}
		m.openCount += 1
		return &mockVarWriterFile{flags: flags, mockVarFile: &mockVarFile{name: name, fs: m}}, nil
	default:
		return nil, syscall.EINVAL
	}
}

func (m *mockEfiVarfs) List() (out []os.DirEntry) {
	for k, v := range m.vars {
		out = append(out, mockDirent{filepath.Base(k), v.mode})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name() < out[j].Name()
	})
	return out
}

func (m *mockEfiVarfs) Unlink(name string) error {
	v, ok := m.vars[name]
	if !ok {
		return &os.PathError{Op: "remove", Path: name, Err: syscall.ENOENT}
	}
	if v.immutable {
		return &os.PathError{Op: "remove", Path: name, Err: syscall.EPERM}
	}
	delete(m.vars, name)
	return nil
}

type varsSuite struct {
	mockEfiVarfs *mockEfiVarfs

	restoreOpenVarFile   func()
	restoreReadVarDir    func()
	restoreUnlinkVarFile func()
	restoreVarsStatfs    func()
}

func (s *varsSuite) SetUpTest(c *C) {
	s.mockEfiVarfs = &mockEfiVarfs{vars: make(map[string]*mockEfiVar)}
	s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = &mockEfiVar{data: decodeHexString(c, "0600000001"), immutable: true}
	s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = &mockEfiVar{data: decodeHexString(c, "070000000000")}
	s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{data: decodeHexString(c, "07000000a5a5a5a5"), immutable: true}

	s.restoreOpenVarFile = MockOpenVarFile(s.mockEfiVarfs.Open)

	s.restoreReadVarDir = MockReadVarDir(func(path string) ([]os.DirEntry, error) {
		if path != "/sys/firmware/efi/efivars" {
			return nil, &os.PathError{Op: "open", Path: path, Err: syscall.ENOENT}
		}
		return s.mockEfiVarfs.List(), nil
	})

	s.restoreUnlinkVarFile = MockUnlinkVarFile(s.mockEfiVarfs.Unlink)

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
}

func (s *varsSuite) TearDownTest(c *C) {
	s.restoreVarsStatfs()
	s.restoreUnlinkVarFile()
	s.restoreReadVarDir()
	s.restoreOpenVarFile()

	c.Check(s.mockEfiVarfs.openCount, Equals, 0)
}

func (s *varsSuite) mockWrongFsType() (restore func()) {
	return MockVarsStatfs(func(path string, st *unix.Statfs_t) error {
		if err := unix.Statfs(filepath.Join("testdata"), st); err != nil {
			return err
		}
		st.Type = unix.SYSFS_MAGIC
		return nil
	})
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
	s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/NotFound-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"] = &mockEfiVar{}
	_, _, err := ReadVar("NotFound", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVariableNotFound)
}

func (s *varsSuite) TestReadVarVarsUnavailable(c *C) {
	restore := s.mockWrongFsType()
	defer restore()

	_, _, err := ReadVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVarsUnavailable)
}

func (s *varsSuite) TestWriteVarImmutable(c *C) {
	err := WriteVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "080808080808"))
	c.Check(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, decodeHexString(c, "07000000080808080808"))
	c.Check(v.immutable, Equals, true)
}

func (s *varsSuite) TestWriteVarMutable(c *C) {
	err := WriteVar("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "0001"))
	c.Check(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, decodeHexString(c, "070000000001"))
	c.Check(v.immutable, Equals, false)
}

func (s *varsSuite) TestWriteVarAppend(c *C) {
	err := WriteVar("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess|AttributeAppendWrite,
		decodeHexString(c, "0001"))
	c.Check(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, decodeHexString(c, "0700000000000001"))
	c.Check(v.immutable, Equals, false)
}

func (s *varsSuite) TestCreateVar(c *C) {
	err := WriteVar("Test2", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "a5a5a5a5"))
	c.Assert(err, IsNil)

	v, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test2-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"]
	c.Check(ok, Equals, true)
	c.Check(v.data, DeepEquals, decodeHexString(c, "07000000a5a5a5a5"))
	c.Check(v.mode, Equals, os.FileMode(0644))
}

func (s *varsSuite) TestWriteVarVarsUnavailable(c *C) {
	restore := s.mockWrongFsType()
	defer restore()

	err := WriteVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "080808080808"))
	c.Check(err, Equals, ErrVarsUnavailable)
}

func (s *varsSuite) TestWriteVarEACCES(c *C) {
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
	c.Check(err, ErrorMatches, "open /sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c: permission denied")
}

func (s *varsSuite) TestWriteVarRace(c *C) {
	var restore func()
	restore = MockOpenVarFile(func(path string, flags int, perm os.FileMode) (VarFile, error) {
		if flags&os.O_WRONLY != 0 {
			// Simulate another process flipping the immutable flag back
			s.mockEfiVarfs.vars[path].immutable = true
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

func (s *varsSuite) TestWriteVarRaceGiveUp(c *C) {
	count := 0
	restore := MockOpenVarFile(func(path string, flags int, perm os.FileMode) (VarFile, error) {
		if flags&os.O_WRONLY != 0 {
			// Simulate another process flipping the immutable flag back
			s.mockEfiVarfs.vars[path].immutable = true
			count += 1
		}

		return nil, Defer
	})
	defer restore()

	err := WriteVar("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, decodeHexString(c, "0001"))
	c.Check(err, ErrorMatches, "open /sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c: operation not permitted")
	c.Check(count, Equals, 5)
}

func (s *varsSuite) TestDeleteVarImmutable(c *C) {
	c.Check(DeleteVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20})), IsNil)
	_, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"]
	c.Check(ok, Equals, false)
}

func (s *varsSuite) TestDeleteVarMutable(c *C) {
	c.Check(DeleteVar("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c})), IsNil)
	_, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"]
	c.Check(ok, Equals, false)
}

func (s *varsSuite) TestDeleteVarUnavailable(c *C) {
	err := DeleteVar("Test2", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVariableNotFound)
}

func (s *varsSuite) TestDeleteVarVarsUnavailable(c *C) {
	restore := s.mockWrongFsType()
	defer restore()

	err := DeleteVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, Equals, ErrVarsUnavailable)
}

func (s *varsSuite) TestDeleteVarEACCES(c *C) {
	restore := MockUnlinkVarFile(func(path string) error {
		return &os.PathError{Op: "remove", Path: path, Err: syscall.EACCES}
	})
	defer restore()

	err := DeleteVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, ErrorMatches, "remove /sys/firmware/efi/efivars/Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520: permission denied")
}

func (s *varsSuite) TestDeleteVarRace(c *C) {
	var restore func()
	restore = MockUnlinkVarFile(func(path string) error {
		// Simulate another process flipping the immutable flag back
		s.mockEfiVarfs.vars[path].immutable = true
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

	c.Check(DeleteVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20})), IsNil)
	_, ok := s.mockEfiVarfs.vars["/sys/firmware/efi/efivars/Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520"]
	c.Check(ok, Equals, false)
}

func (s *varsSuite) TestDeleteVarRaceGiveUp(c *C) {
	count := 0
	restore := MockUnlinkVarFile(func(path string) error {
		// Simulate another process flipping the immutable flag back
		s.mockEfiVarfs.vars[path].immutable = true
		count += 1
		return Defer
	})
	defer restore()

	err := DeleteVar("Test", MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20}))
	c.Check(err, ErrorMatches, "remove /sys/firmware/efi/efivars/Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520: operation not permitted")
}

func (s *varsSuite) TestListVars(c *C) {
	ents, err := ListVars()
	c.Check(err, IsNil)
	c.Check(ents, DeepEquals, []VarEntry{
		{Name: "BootOrder", GUID: MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c})},
		{Name: "SecureBoot", GUID: MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c})},
		{Name: "Test", GUID: MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20})}})
}

func (s *varsSuite) TestListVarsInvalidNames(c *C) {
	restore := MockReadVarDir(func(_ string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			mockDirent{name: "Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520", mode: os.ModeDir | os.FileMode(0755)},
			mockDirent{name: "e1f6e301-bcfc-4eff-bca1-54f1d6bd4520", mode: 0644},
			mockDirent{name: "Test+e1f6e301-bcfc-4eff-bca1-54f1d6bd4520", mode: 0644},
			mockDirent{name: "Test-e1f6e301-bcfc-4eff-bca1-54f1d6bd4520", mode: 0644},
		}, nil
	})
	defer restore()

	ents, err := ListVars()
	c.Check(err, IsNil)
	c.Check(ents, DeepEquals, []VarEntry{{Name: "Test", GUID: MakeGUID(0xe1f6e301, 0xbcfc, 0x4eff, 0xbca1, [...]uint8{0x54, 0xf1, 0xd6, 0xbd, 0x45, 0x20})}})
}
