package efi_test

import (
	"encoding/hex"
	"io/ioutil"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

func decodeHexString(c *C, s string) []byte {
	x, err := hex.DecodeString(s)
	c.Assert(err, IsNil)
	return x
}

func readFile(c *C, path string) []byte {
	data, err := ioutil.ReadFile(path)
	c.Assert(err, IsNil)
	return data
}
