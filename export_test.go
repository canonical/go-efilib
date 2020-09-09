package efi

import (
	"golang.org/x/sys/unix"
)

func MockVarsRoot(path string, fstype int64) (restore func()) {
	origRoot := varsRoot
	origStatfs := varsStatfs
	varsRoot = path
	varsStatfs = func(path string, st *unix.Statfs_t) error {
		if err := unix.Statfs(path, st); err != nil {
			return err
		}
		st.Type = fstype
		return nil
	}

	return func() {
		varsRoot = origRoot
		varsStatfs = origStatfs
	}
}
