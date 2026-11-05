//go:build windows

package journal

import (
	"golang.org/x/sys/windows"
	"os"
)

func openRegular(path string, flags int, mode os.FileMode) (*os.File, error) {
	name, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	var info windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(h, &info); e != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		windows.CloseHandle(h)
		return nil, ErrInvalid
	}
	return os.NewFile(uintptr(h), path), nil
}
