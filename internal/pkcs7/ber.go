package pkcs7

import (
	"bytes"
	"encoding/asn1"
	"io"
	"math"
)

type asn1Object interface {
	Write(w io.Writer) error
}

type asn1Primitive struct {
	class    int
	tag      int
	contents []byte
}

func (p asn1Primitive) Write(w io.Writer) error {
	val := asn1.RawValue{
		Class: p.class,
		Tag:   p.tag,
		Bytes: p.contents}
	b, err := asn1.Marshal(val)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

type asn1Structured struct {
	class    int
	tag      int
	contents []asn1Object
}

func (s asn1Structured) Write(w io.Writer) error {
	tmp := new(bytes.Buffer)
	for _, o := range s.contents {
		if err := o.Write(tmp); err != nil {
			return err
		}
	}

	val := asn1.RawValue{
		Class:      s.class,
		Tag:        s.tag,
		IsCompound: true,
		Bytes:      tmp.Bytes()}
	b, err := asn1.Marshal(val)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func parseBase256Int(bytes []byte) (int, error) {
	// encoding/asn1 expects these to fit into an int32, so numbers up to
	// 4 bytes are valid. If there are more bytes, make sure they're all
	// leading zeros.
	for len(bytes) > 4 {
		b := bytes[0]
		bytes = bytes[1:]
		if b != 0 {
			return 0, asn1.SyntaxError{Msg: "base-256 number too large"}
		}
	}

	var ret64 int64
	for i := 0; i < len(bytes); i++ {
		b := bytes[i]
		n := len(bytes) - i - 1
		ret64 |= int64(b) << (8 * n)
	}
	if ret64 > math.MaxInt32 {
		return 0, asn1.SyntaxError{Msg: "base-256 number too large"}
	}

	return int(ret64), nil

}

func parseBase128Int(bytes []byte) (int, error) {
	// encoding/asn1 expects these to fit into an int32, so numbers up to
	// 5 bytes are valid. If there are more bytes, make sure they're all
	// leading zeros.
	for len(bytes) > 5 {
		b := bytes[0]
		bytes = bytes[1:]
		if b != 0x80 {
			return 0, asn1.SyntaxError{Msg: "base-128 number too large"}
		}
	}

	var ret64 int64
	for i := 0; i < len(bytes); i++ {
		b := bytes[i]
		n := len(bytes) - i - 1
		ret64 |= int64(b) << (7 * n)
	}
	if ret64 > math.MaxInt32 {
		return 0, asn1.SyntaxError{Msg: "base-128 number too large"}
	}

	return int(ret64), nil
}

func readBase128Int(r io.ByteReader) (int, error) {
	var bytes []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, asn1.SyntaxError{Msg: "base-128 number truncated"}
		}
		bytes = append(bytes, b&0x7f)
		if b&0x80 == 0 {
			break
		}
	}
	return parseBase128Int(bytes)
}

func isEndOfContents(obj asn1Object) bool {
	p, ok := obj.(asn1Primitive)
	if !ok {
		return false
	}
	return p.class == 0 && p.tag == 0 && len(p.contents) == 1 && p.contents[0] == 0
}

type reader struct {
	r *bytes.Reader
	n int
}

func newReader(data []byte) *reader {
	return &reader{r: bytes.NewReader(data)}
}

func (r *reader) Read(data []byte) (n int, err error) {
	n, err = r.r.Read(data)
	r.n += n
	return n, err
}

func (r *reader) ReadByte() (b byte, err error) {
	b, err = r.r.ReadByte()
	if err != nil {
		return 0, err
	}
	r.n += 1
	return b, nil
}

func readBERObject(ber []byte) (int, asn1Object, error) {
	r := newReader(ber)

	b, err := r.ReadByte()
	if err != nil {
		return 0, nil, asn1.SyntaxError{Msg: "object truncated before tag"}
	}

	class := int((b & 0xc0) >> 6)

	constructed := false
	if b&0x20 != 0 {
		constructed = true
	}

	var tag int
	if b&0x1f == 0x1f {
		// high tag number case
		tag, err = readBase128Int(r)
		if err != nil {
			return 0, nil, err
		}
	} else {
		tag = int(b & 0x1f)
	}

	b, err = r.ReadByte()
	if err != nil {
		return 0, nil, asn1.SyntaxError{Msg: "object truncated before length"}
	}

	var length int
	indefinite := false
	switch {
	case b == 0xff:
		return 0, nil, asn1.SyntaxError{Msg: "invalid length"}
	case b > 0x80:
		bytes := make([]byte, int(b&0x7f))
		if _, err := r.Read(bytes); err != nil {
			return 0, nil, asn1.SyntaxError{Msg: "length base-156 truncated"}
		}
		l, err := parseBase256Int(bytes)
		if err != nil {
			return 0, nil, err
		}
		length = l
	case b == 0x80:
		if !constructed {
			return 0, nil, asn1.SyntaxError{Msg: "tag / length mismatch (cannot be primitive and indefinite)"}
		}
		indefinite = true
	default:
		length = int(b)
	}

	content := ber[r.n:]
	if !indefinite {
		if length > len(content) {
			return 0, nil, asn1.SyntaxError{Msg: "object content truncated"}
		}
		content = content[:length]
	}

	if !constructed {
		return r.n + len(content), asn1Primitive{
			class:    class,
			tag:      tag,
			contents: content}, nil
	}

	total := r.n
	ret := asn1Structured{
		class: class,
		tag:   tag}

	for len(content) > 0 {
		n, obj, err := readBERObject(content)
		if err != nil {
			return total + n, nil, err
		}
		total += n
		content = content[n:]

		if isEndOfContents(obj) {
			break
		}

		ret.contents = append(ret.contents, obj)
	}

	return total, ret, nil
}

// fixupBER attempts to make some BER encodings compatible with go's
// encoding/asn1 package which only supports DER encoding. This does not
// convert a BER encoding in to DER, and it is not possible to do this in
// a generic way anyway because it can't handle type-specific rules for
// types with context-specific, private or application specific tags.
// What this does do is make lengths and high tag number fields properly
// DER encoded.
//
// This shouldn't be necessary because UEFI requires DER encodings, but
// there are some artefacts in the wild that have length encodings that
// aren't proper DER, such as the 2016 dbx update which contains long-form
// lengths for lengths that can be represented by the short-form encoding.
func fixupBER(ber []byte) ([]byte, error) {
	_, obj, err := readBERObject(ber)
	if err != nil {
		return nil, err
	}

	w := new(bytes.Buffer)
	if err := obj.Write(w); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}
