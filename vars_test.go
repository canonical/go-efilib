// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"context"
	"errors"
	"sort"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-efilib"
)

type mockVarData struct {
	attrs VariableAttributes
	data  []byte
}

type mockVars map[VariableDescriptor]*mockVarData

func (v mockVars) Get(name string, guid GUID) (VariableAttributes, []byte, error) {
	data, exists := v[VariableDescriptor{Name: name, GUID: guid}]
	if !exists {
		return 0, nil, ErrVarNotExist
	}
	return data.attrs, data.data, nil
}

func (v mockVars) Set(name string, guid GUID, attrs VariableAttributes, data []byte) error {
	if attrs&^(AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess) > 0 {
		return errors.New("invalid attributes")
	}
	mockData, exists := v[VariableDescriptor{Name: name, GUID: guid}]
	if !exists {
		if len(data) == 0 {
			return nil
		}
		v[VariableDescriptor{Name: name, GUID: guid}] = &mockVarData{attrs: attrs, data: data}
		return nil
	}
	if attrs != mockData.attrs {
		return errors.New("invalid attributes")
	}
	if len(data) == 0 {
		delete(v, VariableDescriptor{Name: name, GUID: guid})
		return nil
	}
	mockData.data = data
	return nil
}

func (v mockVars) List() ([]VariableDescriptor, error) {
	var out []VariableDescriptor
	for desc := range v {
		out = append(out, desc)
	}
	return out, nil
}

func (v mockVars) add(name string, guid GUID, attrs VariableAttributes, data []byte) {
	v[VariableDescriptor{Name: name, GUID: guid}] = &mockVarData{attrs: attrs, data: data}
}

type mockVars2 struct {
	mockVars
}

func makeMockVars2() mockVars2 {
	return mockVars2{
		mockVars: make(mockVars),
	}
}

func (v mockVars2) Get(ctx context.Context, name string, guid GUID) (VariableAttributes, []byte, error) {
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	default:
	}
	return v.mockVars.Get(name, guid)
}

func (v mockVars2) Set(ctx context.Context, name string, guid GUID, attrs VariableAttributes, data []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return v.mockVars.Set(name, guid, attrs, data)
}

func (v mockVars2) List(ctx context.Context) ([]VariableDescriptor, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return v.mockVars.List()
}

type varsSuite struct{}

var _ = Suite(&varsSuite{})

func (s *varsSuite) TestNullVarsBackendGet(c *C) {
	var backend NullVarsBackend
	_, _, err := backend.Get("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}))
	c.Check(err, Equals, ErrVarsUnavailable)
}

func (s *varsSuite) TestNullVarsBackendSet(c *C) {
	var backend NullVarsBackend
	err := backend.Set("BootOrder", MakeGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}),
		AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, DecodeHexString(c, "0001"))
	c.Check(err, Equals, ErrVarsUnavailable)
}

func (s *varsSuite) TestNullVarsBackendList(c *C) {
	var backend NullVarsBackend
	_, err := backend.List()
	c.Check(err, Equals, ErrVarsUnavailable)
}

func (s *varsSuite) TestGetVarsBackendNil(c *C) {
	backend := GetVarsBackend(context.Background())
	c.Assert(backend, FitsTypeOf, &VarsBackendWrapper{})
	wrapper := backend.(*VarsBackendWrapper)
	c.Check(wrapper.Backend, FitsTypeOf, NullVarsBackend{})
}

func (s *varsSuite) TestGetVarsBackendWithVarsBackend(c *C) {
	vars := make(mockVars)
	expected := &vars
	ctx := WithVarsBackend(context.Background(), expected)

	backend := GetVarsBackend(ctx)
	c.Assert(backend, FitsTypeOf, &VarsBackendWrapper{})
	wrapper := backend.(*VarsBackendWrapper)
	c.Check(wrapper.Backend, Equals, expected)
}

func (s *varsSuite) TestGetVarsBackendInvalidTypePanics(c *C) {
	ctx := context.WithValue(context.Background(), VarsBackendKey{}, string("lol, idiot"))
	c.Check(func() { GetVarsBackend(ctx) }, PanicMatches, `invalid variable backend type \"string\": \"lol, idiot\"`)
}

func (s *varsSuite) TestGetVarsBackendWithVarsBackend2(c *C) {
	vars := makeMockVars2()
	expected := &vars
	ctx := WithVarsBackend2(context.Background(), expected)
	c.Check(GetVarsBackend(ctx), Equals, expected)
}

func (s *varsSuite) TestReadVariable1(c *C) {
	vars := makeMockVars2()
	vars.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	vars.add("Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte("test payload"))

	ctx := WithVarsBackend2(context.Background(), vars)
	data, attrs, err := ReadVariable(ctx, "Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}))
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{1, 2, 3})
	c.Check(attrs, Equals, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess)
}

func (s *varsSuite) TestReadVariable2(c *C) {
	vars := makeMockVars2()
	vars.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	vars.add("Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte("test payload"))

	ctx := WithVarsBackend2(context.Background(), vars)
	data, attrs, err := ReadVariable(ctx, "Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}))
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("test payload"))
	c.Check(attrs, Equals, AttributeBootserviceAccess|AttributeRuntimeAccess)
}

func (s *varsSuite) TestReadVariableErr(c *C) {
	vars := makeMockVars2()
	vars.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	vars.add("Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte("test payload"))

	ctx := WithVarsBackend2(context.Background(), vars)
	_, _, err := ReadVariable(ctx, "Bar", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}))
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *varsSuite) TestReadVariableCancelled(c *C) {
	vars := makeMockVars2()

	ctx, cancel := context.WithCancel(WithVarsBackend2(context.Background(), vars))
	cancel()
	_, _, err := ReadVariable(ctx, "Bar", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}))
	c.Check(err, ErrorMatches, `context canceled`)
}

func (s *varsSuite) TestWriteVariable1(c *C) {
	vars := makeMockVars2()
	ctx := WithVarsBackend2(context.Background(), vars)

	err := WriteVariable(ctx, "Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	c.Check(err, IsNil)
	c.Check(vars.mockVars[VariableDescriptor{Name: "Foo", GUID: MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c})}], DeepEquals, &mockVarData{
		attrs: AttributeNonVolatile | AttributeBootserviceAccess | AttributeRuntimeAccess,
		data:  []byte{1, 2, 3},
	})
}

func (s *varsSuite) TestWriteVariable2(c *C) {
	vars := makeMockVars2()
	ctx := WithVarsBackend2(context.Background(), vars)

	err := WriteVariable(ctx, "Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte("test payload"))
	c.Check(err, IsNil)
	c.Check(vars.mockVars[VariableDescriptor{Name: "Bar", GUID: MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45})}], DeepEquals, &mockVarData{
		attrs: AttributeBootserviceAccess | AttributeRuntimeAccess,
		data:  []byte("test payload"),
	})
}

func (s *varsSuite) TestWriteVariableErr(c *C) {
	vars := makeMockVars2()
	vars.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})

	ctx := WithVarsBackend2(context.Background(), vars)

	err := WriteVariable(ctx, "Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{4, 5, 6, 7})
	c.Check(err, ErrorMatches, `invalid attributes`)
}

func (s *varsSuite) TestWriteVariableCancel(c *C) {
	vars := makeMockVars2()

	ctx, cancel := context.WithCancel(WithVarsBackend2(context.Background(), vars))
	cancel()
	err := WriteVariable(ctx, "Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{4, 5, 6, 7})
	c.Check(err, ErrorMatches, `context canceled`)
}

func (s *varsSuite) TestListVariables(c *C) {
	vars := makeMockVars2()
	vars.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	vars.add("Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte("test payload"))

	ctx := WithVarsBackend2(context.Background(), vars)
	names, err := ListVariables(ctx)
	c.Check(err, IsNil)
	c.Check(names, DeepEquals, []VariableDescriptor{
		{
			Name: "Foo",
			GUID: MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}),
		},
		{
			Name: "Bar",
			GUID: MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}),
		},
	})
}

func (s *varsSuite) TestListVariablesCancel(c *C) {
	vars := makeMockVars2()

	ctx, cancel := context.WithCancel(WithVarsBackend2(context.Background(), vars))
	cancel()
	_, err := ListVariables(ctx)
	c.Check(err, ErrorMatches, `context canceled`)
}

func (s *varsSuite) TestVarsBackendWrapperGet(c *C) {
	vars := make(mockVars)
	vars.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})

	wrapper := &VarsBackendWrapper{Backend: vars}

	attrs, data, err := wrapper.Get(context.Background(), "Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}))
	c.Check(err, IsNil)
	c.Check(attrs, Equals, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess)
	c.Check(data, DeepEquals, []byte{1, 2, 3})

}

func (s *varsSuite) TestVarsBackendWrapperSet(c *C) {
	vars := make(mockVars)

	wrapper := &VarsBackendWrapper{Backend: vars}

	err := wrapper.Set(context.Background(), "Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	c.Check(err, IsNil)
	c.Check(vars[VariableDescriptor{Name: "Foo", GUID: MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c})}], DeepEquals, &mockVarData{
		attrs: AttributeNonVolatile | AttributeBootserviceAccess | AttributeRuntimeAccess,
		data:  []byte{1, 2, 3},
	})
}

func (s *varsSuite) TestVarsBackendWrapperList(c *C) {
	vars := make(mockVars)
	vars.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	vars.add("Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte("test payload"))

	wrapper := &VarsBackendWrapper{Backend: vars}

	names, err := wrapper.List(context.Background())
	c.Check(err, IsNil)
	sort.Stable(VariableDescriptorSlice(names))
	c.Check(names, DeepEquals, []VariableDescriptor{
		{
			Name: "Foo",
			GUID: MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}),
		},
		{
			Name: "Bar",
			GUID: MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}),
		},
	})
}
