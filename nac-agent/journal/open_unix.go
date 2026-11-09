//go:build !windows

package journal

import (
	"golang.org/x/sys/unix"
	"os"
)

func openRegular(path string, flags int, mode os.FileMode) (*os.File, error) {
	fd, e := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), path), nil
}
