//go:build !windows

package provision

import (
	"os"
	"path/filepath"
	"syscall"
)

func checkPath(p string) error {
	i, e := os.Lstat(p)
	if e != nil {
		return e
	}
	if i.Mode()&os.ModeSymlink != 0 || (!i.IsDir() && !i.Mode().IsRegular()) {
		return ErrInvalid
	}
	if i.Mode().Perm()&0077 != 0 {
		return ErrInvalid
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return ErrInvalid
	}
	return nil
}
func prepareRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) {
		return ErrInvalid
	}
	if e := os.MkdirAll(root, 0700); e != nil {
		return e
	}
	i, e := os.Lstat(root)
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return ErrInvalid
	}
	if e = os.Chmod(root, 0700); e != nil {
		return e
	}
	return checkPath(root)
}
func protectFile(p string) error { return os.Chmod(p, 0600) }
