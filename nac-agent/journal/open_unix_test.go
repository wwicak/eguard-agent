//go:build !windows

package journal

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSymlinkExistingFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "db")
	s, e := Create(p, bound)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	link := filepath.Join(t.TempDir(), "link")
	if e = os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if s, e = Open(link, bound); e == nil {
		s.Close()
		t.Fatal("symlink accepted")
	}
}
func TestFIFOExistingFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if e := syscall.Mkfifo(p, 0600); e != nil {
		t.Fatal(e)
	}
	if s, e := Open(p, bound); e == nil {
		s.Close()
		t.Fatal("FIFO accepted")
	}
}
func TestCreateDoesNotFollowExistingSymlink(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	link := filepath.Join(t.TempDir(), "link")
	if e := os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	if s, e := Create(link, bound); e == nil {
		s.Close()
		t.Fatal("symlink created state")
	}
	if _, e := os.Lstat(target); !os.IsNotExist(e) {
		t.Fatal("symlink target modified")
	}
}
