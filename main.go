package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type JOBOBJECT_ASSOCIATE_COMPLETION_PORT struct {
	CompletionKey  uintptr
	CompletionPort windows.Handle
}

const (
	// https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
	SECURITY_MANDATORY_LOW_RID = windows.WELL_KNOWN_SID_TYPE(0x00001000)
)

// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken
// CreateRestrictedToken

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	user32      = windows.NewLazySystemDLL("user32.dll")

	procCreateRestrictedToken = modadvapi32.NewProc("CreateRestrictedToken")
	procGetThreadDesktop      = user32.NewProc("GetThreadDesktop")
	procCreateDesktopW        = user32.NewProc("CreateDesktopW")
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

func getThreadDesktop(threadID uint32) (h HDESK) {
	r1, _, _ := syscall.Syscall(procGetThreadDesktop.Addr(), 1, uintptr(threadID), 0, 0)
	h = HDESK(r1)
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

func main() {
	// Get policy user
	sid, err := windows.CreateWellKnownSid(SECURITY_MANDATORY_LOW_RID)
	fmt.Println("sid", sid, err)

	// Get group sid
	curProc, err := windows.GetCurrentProcess()
	fmt.Println("curProc", curProc, err)

	// Get current process token
	var token windows.Token
	err = windows.OpenProcessToken(curProc,
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|
			windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ASSIGN_PRIMARY, &token)
	fmt.Println(token, err)

	// Get group Sid
	var l uint32
	var groupSid *windows.SID
	if err := windows.GetTokenInformation(token, windows.TokenGroups, nil, 0, &l); err == windows.ERROR_INSUFFICIENT_BUFFER {
		buf := make([]byte, l)
		windows.GetTokenInformation(token, windows.TokenGroups, &buf[0], l, &l)
		tg := (*windows.Tokengroups)(unsafe.Pointer(&buf[0]))
		for _, info := range tg.AllGroups() {
			if info.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
				groupSid = info.Sid
			}
		}
	}
	fmt.Println(groupSid)

	builtInSid, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	worldSid, err := windows.CreateWellKnownSid(windows.WinWorldSid)

	fmt.Println("sids", builtInSid, worldSid, err)

	var attrs []windows.SIDAndAttributes
	for _, s := range []*windows.SID{groupSid, builtInSid, worldSid} {
		attrs = append(attrs, windows.SIDAndAttributes{Sid: s})
	}

	// create restricted token
	var newToken windows.Token
	err = createRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 0, nil, 0, nil,
		uint32(len(attrs)), &attrs[0], &newToken)
	fmt.Println("restricted token", newToken, err)

	// get current desktop
	curDesk := getThreadDesktop(windows.GetCurrentThreadId())
	fmt.Println("curDesktop:", curDesk)

	// create desktop
	random := make([]byte, 8)
	rand.Read(random)
	name := fmt.Sprintf("winc_%08x_%s", windows.GetCurrentProcessId(), hex.EncodeToString(random))
	nameW := syscall.StringToUTF16Ptr(name)
	deskAccess := DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW |
		DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP |
		READ_CONTROL | WRITE_DAC | WRITE_OWNER
	newDesk, err := createDesktop(nameW, nil, 0, 0, deskAccess, nil)
	fmt.Println("new desktop", newDesk, err)

	// grant access
	sd, err := windows.GetSecurityInfo(windows.Handle(newDesk), windows.SE_WINDOW_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	fmt.Println(sd, err)

	// explicit access
	expAccess := windows.EXPLICIT_ACCESS{
		AccessPermissions: GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
			TrusteeForm:              windows.TRUSTEE_IS_SID,
			TrusteeType:              windows.TRUSTEE_IS_GROUP,
			TrusteeValue:             windows.TrusteeValueFromSID(groupSid),
		},
	}
	oldACL, _, err := sd.DACL()
	newACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{expAccess}, oldACL)
	fmt.Println("new ACL", oldACL, newACL, err)

	// set security info
	windows.SetSecurityInfo(windows.Handle(newDesk), windows.SE_WINDOW_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, newACL, nil)

	// create job object
	hJob, err := windows.CreateJobObject(nil, nil)
	fmt.Println(hJob, err)

	// jobObject limitations
	var limit windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION

	// time limit: 100 * nanosecond
	limit.BasicLimitInformation.PerJobUserTimeLimit = int64(time.Second.Nanoseconds() / 100)
	limit.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_JOB_TIME

	// memory limit: byte
	limit.JobMemoryLimit = 256 << 20 // 256M
	limit.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_JOB_MEMORY

	// additional restrictions
	limit.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION | windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	ret, err := windows.SetInformationJobObject(hJob, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limit)), uint32(unsafe.Sizeof(limit)))
	fmt.Println(ret, err)

	// ui restrictions
	var uiRestriction windows.JOBOBJECT_BASIC_UI_RESTRICTIONS
	uiRestriction.UIRestrictionsClass = windows.JOB_OBJECT_UILIMIT_EXITWINDOWS |
		windows.JOB_OBJECT_UILIMIT_DESKTOP |
		windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
		windows.JOB_OBJECT_UILIMIT_GLOBALATOMS |
		windows.JOB_OBJECT_UILIMIT_HANDLES |
		windows.JOB_OBJECT_UILIMIT_READCLIPBOARD |
		windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
		windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD

	ret, err = windows.SetInformationJobObject(hJob, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&uiRestriction)), uint32(unsafe.Sizeof(uiRestriction)))
	fmt.Println(ret, err)

	// create IOCP
	ioPort, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	fmt.Println(ioPort, err)

	var completePort JOBOBJECT_ASSOCIATE_COMPLETION_PORT
	completePort.CompletionKey = uintptr(hJob)
	completePort.CompletionPort = ioPort

	ret, err = windows.SetInformationJobObject(hJob, windows.JobObjectAssociateCompletionPortInformation, uintptr(unsafe.Pointer(&completePort)), uint32(unsafe.Sizeof(completePort)))
	fmt.Println(ret, err)

	// cpu rate restriction ?

	// create output pipe
	p := make([]windows.Handle, 2)
	err = windows.Pipe(p)
	fmt.Println(p, err)

	err = windows.SetHandleInformation(p[1], windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT)
	fmt.Println(err)

	// create input pipe
	p2 := make([]windows.Handle, 2)
	err = windows.Pipe(p2)
	fmt.Println(p2, err)

	err = windows.SetHandleInformation(p2[0], windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT)
	fmt.Println(err)

	// create pipe mapping
	var startupInfo windows.StartupInfo
	startupInfo.Flags |= windows.STARTF_USESTDHANDLES // STARTF_FORCEOFFFEEDBACK
	startupInfo.StdInput = p2[0]
	startupInfo.StdOutput = p[1]
	startupInfo.StdErr = p[1]

	// process info
	var processInfo windows.ProcessInformation

	argv := syscall.StringToUTF16Ptr("C:\\go\\bin\\go.exe")
	// argv := syscall.StringToUTF16Ptr("c:\\windows\\system32\\calc.exe")
	// argv := syscall.StringToUTF16Ptr("c:\\windows\\system32\\cmd.exe")
	//argv := syscall.StringToUTF16Ptr("c:\\windows\\py.exe -c \"while True: pass\"")
	// argv := syscall.StringToUTF16Ptr("c:\\windows\\system32\\tasklist.exe")
	// argv := syscall.StringToUTF16Ptr("C:\\Program Files\\Git\\usr\\bin\\cat.exe main.go")

	// Create process
	syscall.ForkLock.Lock()
	err = windows.CreateProcess(nil, argv, nil, nil, true,
		windows.CREATE_NEW_PROCESS_GROUP|windows.CREATE_NEW_CONSOLE|windows.CREATE_SUSPENDED,
		nil, nil, &startupInfo, &processInfo)
	syscall.ForkLock.Unlock()
	fmt.Println(err, processInfo)

	// Close used pipes
	windows.CloseHandle(p[1])
	windows.CloseHandle(p2[0])

	// assign process to job object
	err = windows.AssignProcessToJobObject(hJob, windows.Handle(processInfo.Process))
	fmt.Println(err)

	// resume thread
	ret2, err := windows.ResumeThread(processInfo.Thread)
	fmt.Println(ret2, err)

	done := make(chan struct{})

	// collect output
	go func() {
		defer close(done)
		f := os.NewFile(uintptr(p[0]), "output")
		fmt.Println("file", f)

		buf := make([]byte, 2048)
		for {
			n, err := f.Read(buf)
			if err != nil {
				fmt.Println("output2:", err)
				break
			}
			fmt.Println("output2:", n, string(buf[:n]))
		}
	}()

	// terminates job after 1s
	if false {
		time.Sleep(time.Second)
		err = windows.TerminateJobObject(hJob, 0)
		fmt.Println(err)
	}

	// wait on event from IOCP
	if true {
		var qty, key uint32
		var overlapped *windows.Overlapped

		for {
			err = windows.GetQueuedCompletionStatus(ioPort, &qty, &key, &overlapped, windows.INFINITE)
			if err != nil || qty == 4 {
				fmt.Println("io port:", err)
				break
			}
			fmt.Println("io port:", qty, key)
		}
	}

	// wait process to terminate
	event, err := windows.WaitForSingleObject(processInfo.Process, windows.INFINITE)
	fmt.Println(event, err)

	// get process exit code
	var exitCode uint32
	err = windows.GetExitCodeProcess(processInfo.Process, &exitCode)
	fmt.Println(exitCode, err)

	<-done
}

func randomGen() {
	var cryptProv windows.Handle
	const MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0"
	MS_DEF_PROV_W := syscall.StringToUTF16Ptr(MS_DEF_PROV)
	const PROV_RSA_FULL = 1
	const CRYPT_VERIFYCONTEXT = 0xF0000000
	err := windows.CryptAcquireContext(&cryptProv, nil, MS_DEF_PROV_W, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)
	fmt.Println("crypt", cryptProv, err)
}
