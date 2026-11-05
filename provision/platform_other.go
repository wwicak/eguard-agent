//go:build !windows

package provision

import (
	"os"
	"path/filepath"
)

func checkPath(p string) error {
	i, e := os.Lstat(p)
	if e != nil {
		return e
	}
	if i.Mode()&os.ModeSymlink != 0 {
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
	return checkPath(root)
}
func protectFile(string) error { return nil }
