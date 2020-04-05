package main

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type JOBOBJECT_ASSOCIATE_COMPLETION_PORT struct {
	CompletionKey  uintptr
	CompletionPort windows.Handle
}

const (
	// https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
	SECURITY_MANDATORY_LOW_RID uint32 = 0x00001000
)

// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken
// CreateRestrictedToken

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	user32      = windows.NewLazySystemDLL("user32.dll")

	procCreateProcessAsUserW    = modadvapi32.NewProc("CreateProcessAsUserW")
	procCreateRestrictedToken   = modadvapi32.NewProc("CreateRestrictedToken")
	procGetThreadDesktop        = user32.NewProc("GetThreadDesktop")
	procGetProcessWindowStation = user32.NewProc("GetProcessWindowStation")
	procCreateDesktopW          = user32.NewProc("CreateDesktopW")
)

// BOOL CreateRestrictedToken(
// 	HANDLE               ExistingTokenHandle,
// 	DWORD                Flags,
// 	DWORD                DisableSidCount,
// 	PSID_AND_ATTRIBUTES  SidsToDisable,
// 	DWORD                DeletePrivilegeCount,
// 	PLUID_AND_ATTRIBUTES PrivilegesToDelete,
// 	DWORD                RestrictedSidCount,
// 	PSID_AND_ATTRIBUTES  SidsToRestrict,
// 	PHANDLE              NewTokenHandle
// );

func createRestrictedToken(
	ExistingTokenHandle windows.Token,
	Flags uint32,
	DisableSidCount uint32,
	SidsToDisable *windows.SIDAndAttributes,
	DeletePrivilegeCount uint32,
	PrivilegesToDelete *windows.SIDAndAttributes,
	RestrictedSidCount uint32,
	SidsToRestrict *windows.SIDAndAttributes,
	NewTokenHandle *windows.Token,
) (err error) {
	r1, _, e1 := syscall.Syscall9(
		procCreateRestrictedToken.Addr(), 9,
		uintptr(ExistingTokenHandle), uintptr(Flags),
		uintptr(DisableSidCount),
		uintptr(unsafe.Pointer(SidsToDisable)),
		uintptr(DeletePrivilegeCount),
		uintptr(unsafe.Pointer(PrivilegesToDelete)),
		uintptr(RestrictedSidCount),
		uintptr(unsafe.Pointer(SidsToRestrict)),
		uintptr(unsafe.Pointer(NewTokenHandle)))
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

// CreateRestrictedToken Flags
const (
	DISABLE_MAX_PRIVILEGE = 1 << iota
	SANDBOX_INERT
	LUA_TOKEN
	WRITE_RESTRICTED
)

// HDESK GetThreadDesktop(
// 	DWORD dwThreadId
// );

type HDESK windows.Handle
type HWINSTA windows.Handle

func getThreadDesktop(threadID uint32) (h HDESK) {
	r1, _, _ := syscall.Syscall(procGetThreadDesktop.Addr(), 1, uintptr(threadID), 0, 0)
	h = HDESK(r1)
	return
}

func getProcessWindowStation() (h HWINSTA) {
	r1, _, _ := syscall.Syscall(procGetProcessWindowStation.Addr(), 0, 0, 0, 0)
	h = HWINSTA(r1)
	return
}

// HDESK CreateDesktopW(
// 	LPCWSTR               lpszDesktop,
// 	LPCWSTR               lpszDevice,
// 	DEVMODEW              *pDevmode,
// 	DWORD                 dwFlags,
// 	ACCESS_MASK           dwDesiredAccess,
// 	LPSECURITY_ATTRIBUTES lpsa
//   );

func createDesktop(desktop, device *uint16,
	devMode uintptr, flags uint32,
	desiredAccess windows.ACCESS_MASK,
	security *windows.SecurityAttributes) (h HDESK, err error) {
	r1, _, e1 := syscall.Syscall6(procCreateDesktopW.Addr(), 6,
		uintptr(unsafe.Pointer(desktop)),
		uintptr(unsafe.Pointer(device)),
		uintptr(devMode),
		uintptr(flags), uintptr(desiredAccess),
		uintptr(unsafe.Pointer(security)))
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	h = HDESK(r1)
	return
}

const (
	DESKTOP_READOBJECTS windows.ACCESS_MASK = 1 << iota
	DESKTOP_CREATEWINDOW
	DESKTOP_CREATEMENU
	DESKTOP_HOOKCONTROL
	DESKTOP_JOURNALRECORD
	DESKTOP_JOURNALPLAYBACK
	DESKTOP_ENUMERATE
	DESKTOP_WRITEOBJECTS
	DESKTOP_SWITCHDESKTOP // 0x0100L
)

const (
	DELETE windows.ACCESS_MASK = 1 << (iota + 16)
	READ_CONTROL
	WRITE_DAC
	WRITE_OWNER
	SYNCHRONIZE
)

// https://docs.microsoft.com/en-ca/windows/win32/winstation/desktop-security-and-access-rights
// https://docs.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights
const (
	GENERIC_READ  = DESKTOP_ENUMERATE | DESKTOP_READOBJECTS | READ_CONTROL
	GENERIC_WRITE = DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
		DESKTOP_HOOKCONTROL | DESKTOP_JOURNALPLAYBACK | DESKTOP_JOURNALRECORD |
		DESKTOP_WRITEOBJECTS | READ_CONTROL
	GENERIC_EXECUTE = DESKTOP_SWITCHDESKTOP | READ_CONTROL
	GENERIC_ALL     = DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
		DESKTOP_ENUMERATE | DESKTOP_HOOKCONTROL | DESKTOP_JOURNALPLAYBACK |
		DESKTOP_JOURNALRECORD | DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP |
		DESKTOP_WRITEOBJECTS | READ_CONTROL | WRITE_DAC | WRITE_OWNER
)

// CreateProcessAsUserW
//https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw

// BOOL CreateProcessAsUserW(
//   HANDLE                hToken,
//   LPCWSTR               lpApplicationName,
//   LPWSTR                lpCommandLine,
//   LPSECURITY_ATTRIBUTES lpProcessAttributes,
//   LPSECURITY_ATTRIBUTES lpThreadAttributes,
//   BOOL                  bInheritHandles,
//   DWORD                 dwCreationFlags,
//   LPVOID                lpEnvironment,
//   LPCWSTR               lpCurrentDirectory,
//   LPSTARTUPINFOW        lpStartupInfo,
//   LPPROCESS_INFORMATION lpProcessInformation
// );
func CreateProcessAsUser(
	token windows.Handle,
	applicationName *uint16,
	commandLine *uint16,
	procSecurity *windows.SecurityAttributes,
	threadSecurity *windows.SecurityAttributes,
	inheritHandles bool,
	creationFlags uint32,
	environment *uint16,
	currentDirectory *uint16,
	startupInfo *windows.StartupInfo,
	processInformation *windows.ProcessInformation) error {
	var p0 uint32
	if inheritHandles {
		p0 = 1
	}
	r1, _, e1 := procCreateProcessAsUserW.Call(
		uintptr(token),
		uintptr(unsafe.Pointer(applicationName)),
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(unsafe.Pointer(procSecurity)),
		uintptr(unsafe.Pointer(threadSecurity)),
		uintptr(uint32(p0)),
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(environment)),
		uintptr(unsafe.Pointer(currentDirectory)),
		uintptr(unsafe.Pointer(startupInfo)),
		uintptr(unsafe.Pointer(processInformation)))
	if int(r1) == 0 {
		return os.NewSyscallError("CreateProcessAsUser", e1)
	}
	return nil
}
