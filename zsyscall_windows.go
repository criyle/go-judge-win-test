// Code generated by 'go generate'; DO NOT EDIT.

package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	moduser32   = windows.NewLazySystemDLL("user32.dll")

	procCreateRestrictedToken   = modadvapi32.NewProc("CreateRestrictedToken")
	procGetThreadDesktop        = moduser32.NewProc("GetThreadDesktop")
	procGetProcessWindowStation = moduser32.NewProc("GetProcessWindowStation")
	procCreateDesktopW          = moduser32.NewProc("CreateDesktopW")
)

func CreateRestrictedToken(existingToken windows.Token, flags uint32, disableSidCount uint32, sidsToDisable *windows.SIDAndAttributes, deletePrivilegeCount uint32, privilegesToDelete *windows.SIDAndAttributes, restrictedSidCount uint32, sidToRestrict *windows.SIDAndAttributes, newTokenHandle *windows.Token) (err error) {
	r1, _, e1 := syscall.Syscall9(procCreateRestrictedToken.Addr(), 9, uintptr(existingToken), uintptr(flags), uintptr(disableSidCount), uintptr(unsafe.Pointer(sidsToDisable)), uintptr(deletePrivilegeCount), uintptr(unsafe.Pointer(privilegesToDelete)), uintptr(restrictedSidCount), uintptr(unsafe.Pointer(sidToRestrict)), uintptr(unsafe.Pointer(newTokenHandle)))
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetThreadDesktop(threadID uint32) (h HDESK) {
	r0, _, _ := syscall.Syscall(procGetThreadDesktop.Addr(), 1, uintptr(threadID), 0, 0)
	h = HDESK(r0)
	return
}

func GetProcessWindowStation() (h HWINSTA) {
	r0, _, _ := syscall.Syscall(procGetProcessWindowStation.Addr(), 0, 0, 0, 0)
	h = HWINSTA(r0)
	return
}

func CreateDesktop(lpszDesktop *uint16, lpszDevice *uint16, pDevmode uintptr, dwFlags uint32, dwDesiredAccess windows.ACCESS_MASK, lpsa *windows.SecurityAttributes) (h HDESK, err error) {
	r0, _, e1 := syscall.Syscall6(procCreateDesktopW.Addr(), 6, uintptr(unsafe.Pointer(lpszDesktop)), uintptr(unsafe.Pointer(lpszDevice)), uintptr(pDevmode), uintptr(dwFlags), uintptr(dwDesiredAccess), uintptr(unsafe.Pointer(lpsa)))
	h = HDESK(r0)
	if h == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}
