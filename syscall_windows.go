package main

import "golang.org/x/sys/windows"

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

// CreateRestrictedToken Flags
const (
	DISABLE_MAX_PRIVILEGE = 1 << iota
	SANDBOX_INERT
	LUA_TOKEN
	WRITE_RESTRICTED
)

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

type HDESK windows.Handle
type HWINSTA windows.Handle

// Mandatory Level Sids
const (
	SID_SYSTEM_MANDATORY_LEVEL    = "S-1-16-16384"
	SID_HIGH_MANDATORY_LEVEL      = "S-1-16-12288"
	SID_MEDIUM_MANDATORY_LEVEL    = "S-1-16-8192"
	SID_LOW_MANDATORY_LEVEL       = "S-1-16-4096"
	SID_UNTRUSTED_MANDATORY_LEVEL = "S-1-16-0"
)

//sys CreateRestrictedToken(existingToken windows.Token, flags uint32, disableSidCount uint32, sidsToDisable *windows.SIDAndAttributes, deletePrivilegeCount uint32, privilegesToDelete *windows.SIDAndAttributes, restrictedSidCount uint32, sidToRestrict *windows.SIDAndAttributes, newTokenHandle *windows.Token) (err error) = advapi32.CreateRestrictedToken
//sys GetThreadDesktop(threadID uint32) (h HDESK) = user32.GetThreadDesktop
//sys GetProcessWindowStation() (h HWINSTA) = user32.GetProcessWindowStation
//sys CreateDesktop(lpszDesktop *uint16, lpszDevice *uint16, pDevmode uintptr, dwFlags uint32, dwDesiredAccess windows.ACCESS_MASK, lpsa *windows.SecurityAttributes) (h HDESK, err error) = user32.CreateDesktopW
