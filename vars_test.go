// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi_test

import (
	"context"
	"errors"
	"fmt"
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
	c.Check(backend, FitsTypeOf, NullVarsBackend{})
}

func (s *varsSuite) TestGetVarsBackendWithVarsBackend(c *C) {
	expected := new(mockVars)
	ctx := WithVarsBackend(context.Background(), expected)
	c.Check(GetVarsBackend(ctx), Equals, expected)
}

func (s *varsSuite) TestGetVarsBackendInvalidTypePanics(c *C) {
	ctx := context.WithValue(context.Background(), VarsBackendKey{}, string("lol, idiot"))
	c.Check(func() { GetVarsBackend(ctx) }, PanicMatches, `invalid variable backend type \"string\": \"lol, idiot\"`)
}

func (s *varsSuite) TestGetVarsBackendWithVarsBackend2(c *C) {
	vars := makeMockVars2()
	expected := &vars
	ctx := WithVarsBackend2(context.Background(), expected)
	backend := GetVarsBackend(ctx)
	shimBackend, ok := backend.(*VarsBackend2ToVarsBackendShim)
	c.Assert(ok, Equals, true)
	c.Check(shimBackend.Context, Equals, ctx)
	c.Check(shimBackend.Backend, Equals, expected)
}

func (s *varsSuite) TestReadVariable1(c *C) {
	vars := make(mockVars)
	vars.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	vars.add("Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte("test payload"))

	ctx := WithVarsBackend(context.Background(), vars)
	data, attrs, err := ReadVariable(ctx, "Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}))
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{1, 2, 3})
	c.Check(attrs, Equals, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess)
}

func (s *varsSuite) TestReadVariable2(c *C) {
	vars := make(mockVars)
	vars.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	vars.add("Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte("test payload"))

	ctx := WithVarsBackend(context.Background(), vars)
	data, attrs, err := ReadVariable(ctx, "Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}))
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("test payload"))
	c.Check(attrs, Equals, AttributeBootserviceAccess|AttributeRuntimeAccess)
}

func (s *varsSuite) TestReadVariableErr(c *C) {
	vars := make(mockVars)
	vars.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	vars.add("Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte("test payload"))

	ctx := WithVarsBackend(context.Background(), vars)
	_, _, err := ReadVariable(ctx, "Bar", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}))
	c.Check(err, Equals, ErrVarNotExist)
}

func (s *varsSuite) TestWriteVariable1(c *C) {
	vars := make(mockVars)
	ctx := WithVarsBackend(context.Background(), vars)

	err := WriteVariable(ctx, "Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	c.Check(err, IsNil)
	c.Check(vars[VariableDescriptor{Name: "Foo", GUID: MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c})}], DeepEquals, &mockVarData{
		attrs: AttributeNonVolatile | AttributeBootserviceAccess | AttributeRuntimeAccess,
		data:  []byte{1, 2, 3},
	})
}

func (s *varsSuite) TestWriteVariable2(c *C) {
	vars := make(mockVars)
	ctx := WithVarsBackend(context.Background(), vars)

	err := WriteVariable(ctx, "Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte("test payload"))
	c.Check(err, IsNil)
	c.Check(vars[VariableDescriptor{Name: "Bar", GUID: MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45})}], DeepEquals, &mockVarData{
		attrs: AttributeBootserviceAccess | AttributeRuntimeAccess,
		data:  []byte("test payload"),
	})
}

func (s *varsSuite) TestWriteVariableErr(c *C) {
	vars := make(mockVars)
	vars.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})

	ctx := WithVarsBackend(context.Background(), vars)

	err := WriteVariable(ctx, "Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{4, 5, 6, 7})
	c.Check(err, ErrorMatches, `invalid attributes`)
}

func (s *varsSuite) TestListVariables(c *C) {
	vars := make(mockVars)
	vars.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	vars.add("Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte("test payload"))

	ctx := WithVarsBackend(context.Background(), vars)
	names, err := ListVariables(ctx)
	c.Check(err, IsNil)
	sort.Slice(names, func(i, j int) bool {
		return fmt.Sprintf("%s-%v", names[i].Name, names[i].GUID) < fmt.Sprintf("%s-%v", names[j].Name, names[j].GUID)
	})
	c.Check(names, DeepEquals, []VariableDescriptor{
		{
			Name: "Bar",
			GUID: MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}),
		},
		{
			Name: "Foo",
			GUID: MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}),
		},
	})
}

func (s *varsSuite) TestVarsBackend2ToVarsBackendShimGet(c *C) {
	vars2 := makeMockVars2()
	vars2.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})

	ctx := context.Background()
	vars := VarsBackend2ToVarsBackend(ctx, vars2)

	attrs, data, err := vars.Get("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}))
	c.Check(err, IsNil)
	c.Check(attrs, Equals, AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess)
	c.Check(data, DeepEquals, []byte{1, 2, 3})
}

func (s *varsSuite) TestVarsBackend2ToVarsBackendShimGetErr(c *C) {
	vars2 := makeMockVars2()
	vars2.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})

	ctx, cancel := context.WithCancel(context.Background())
	vars := VarsBackend2ToVarsBackend(ctx, vars2)

	cancel()

	_, _, err := vars.Get("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}))
	c.Check(err, ErrorMatches, `context canceled`)
}

func (s *varsSuite) TestVarsBackend2ToVarsBackendShimSet(c *C) {
	vars2 := makeMockVars2()

	ctx := context.Background()
	vars := VarsBackend2ToVarsBackend(ctx, vars2)

	err := vars.Set("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	c.Check(err, IsNil)
	c.Check(vars2.mockVars[VariableDescriptor{Name: "Foo", GUID: MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c})}], DeepEquals, &mockVarData{
		attrs: AttributeNonVolatile | AttributeBootserviceAccess | AttributeRuntimeAccess,
		data:  []byte{1, 2, 3},
	})
}

func (s *varsSuite) TestVarsBackend2ToVarsBackendShimSetErr(c *C) {
	vars2 := makeMockVars2()

	ctx, cancel := context.WithCancel(context.Background())
	vars := VarsBackend2ToVarsBackend(ctx, vars2)

	cancel()

	err := vars.Set("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	c.Check(err, ErrorMatches, `context canceled`)
}

func (s *varsSuite) TestVarsBackend2ToVarsBackendShimList(c *C) {
	vars2 := makeMockVars2()
	vars2.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	vars2.add("Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte("test payload"))

	ctx := context.Background()
	vars := VarsBackend2ToVarsBackend(ctx, vars2)

	names, err := vars.List()
	c.Check(err, IsNil)
	sort.Slice(names, func(i, j int) bool {
		return fmt.Sprintf("%s-%v", names[i].Name, names[i].GUID) < fmt.Sprintf("%s-%v", names[j].Name, names[j].GUID)
	})
	c.Check(names, DeepEquals, []VariableDescriptor{
		{
			Name: "Bar",
			GUID: MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}),
		},
		{
			Name: "Foo",
			GUID: MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}),
		},
	})
}

func (s *varsSuite) TestVarsBackend2ToVarsBackendShimListErr(c *C) {
	vars2 := makeMockVars2()
	vars2.add("Foo", MakeGUID(0x1cbf52c3, 0xdeee, 0x45ac, 0xb227, [...]uint8{0xeb, 0xe6, 0xa0, 0xe5, 0x8a, 0x5c}), AttributeNonVolatile|AttributeBootserviceAccess|AttributeRuntimeAccess, []byte{1, 2, 3})
	vars2.add("Bar", MakeGUID(0x811539c4, 0x812d, 0x4ad6, 0x8c7e, [...]uint8{0xf8, 0xc9, 0xc5, 0x09, 0x53, 0x45}), AttributeBootserviceAccess|AttributeRuntimeAccess, []byte("test payload"))

	ctx, cancel := context.WithCancel(context.Background())
	vars := VarsBackend2ToVarsBackend(ctx, vars2)

	cancel()

	_, err := vars.List()
	c.Check(err, ErrorMatches, `context canceled`)
}
