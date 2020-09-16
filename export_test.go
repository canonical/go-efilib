package efi

import (
	"golang.org/x/sys/unix"
)

func MockVarsRoot(path string, fstype int64) (restore func()) {
	origRoot := varsRoot
	origStatfs := unixStatfs
	varsRoot = path
	unixStatfs = func(path string, st *unix.Statfs_t) error {
		if err := unix.Statfs(path, st); err != nil {
			return err
		}
		st.Type = fstype
		return nil
	}

	return func() {
		varsRoot = origRoot
		unixStatfs = origStatfs
	}
}
