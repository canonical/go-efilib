// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"encoding/hex"
	"os/exec"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type TarFileMixin struct{}

func (m *TarFileMixin) UnpackTar(c *C, path string) string {
	dir := c.MkDir()

	cmd := exec.Command("tar", "-xaf", path, "-C", dir)
	c.Assert(cmd.Run(), IsNil)

	return dir
}

func DecodeHexString(c *C, s string) []byte {
	x, err := hex.DecodeString(s)
	c.Assert(err, IsNil)
	return x
}
