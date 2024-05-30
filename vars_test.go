// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"errors"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-efilib"
)

type mockBootVarData struct {
	attrs VariableAttributes
	data  []byte
}

type mockBootVars map[GUID]map[string]*mockBootVarData

func (v mockBootVars) Get(name string, guid GUID) (VariableAttributes, []byte, error) {
	if _, exists := v[guid]; !exists {
		return 0, nil, ErrVarNotExist
	}
	data, exists := v[guid][name]
	if !exists {
		return 0, nil, ErrVarNotExist
	}
	return data.attrs, data.data, nil
}

func (v mockBootVars) Set(name string, guid GUID, attrs VariableAttributes, data []byte) error {
	if attrs&^(AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess) > 0 {
		return errors.New("invalid attributes")
	}
	if _, exists := v[guid]; !exists {
		v[guid] = make(map[string]*mockBootVarData)
	}
	mockData, exists := v[guid][name]
	if !exists {
		if len(data) == 0 {
			return nil
		}
		v[guid][name] = &mockBootVarData{attrs: attrs, data: data}
		return nil
	}
	if attrs != mockData.attrs {
		return errors.New("invalid attributes")
	}
	if len(data) == 0 {
		delete(v[guid], name)
		return nil
	}
	mockData.data = data
	return nil
}

func (v mockBootVars) List() ([]VariableDescriptor, error) {
	var out []VariableDescriptor
	for guid := range v {
		for name := range v[guid] {
			out = append(out, VariableDescriptor{Name: name, GUID: guid})
		}
	}
	return out, nil
}

func (v mockBootVars) add(name string, guid GUID, attrs VariableAttributes, data []byte) {
	if _, exists := v[guid]; !exists {
		v[guid] = make(map[string]*mockBootVarData)
	}
	v[guid][name] = &mockBootVarData{attrs: attrs, data: data}
}

type varsSuite struct {
	restoreBackend func()
}

var _ = Suite(&varsSuite{})

func (s *varsSuite) SetUpTest(c *C) {
	s.restoreBackend = MockVarsBackend(NullVarsBackend{})
}

func (s *varsSuite) TearDownTest(c *C) {
	s.restoreBackend()
}

func (s *varsSuite) TestNullReadVariable(c *C) {
	_, _, err := ReadVariable("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}))
	c.Check(err, Equals, ErrVarsUnavailable)
}

func (s *varsSuite) TestNullWriteVariable(c *C) {
	err := WriteVariable("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, DecodeHexString(c, "0001"))
	c.Check(err, Equals, ErrVarsUnavailable)
}

func (s *varsSuite) TestNullListVariables(c *C) {
	_, err := ListVariables()
	c.Check(err, Equals, ErrVarsUnavailable)
}
