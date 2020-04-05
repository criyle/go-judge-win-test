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

func main() {
	// Get group sid
	curProc, err := windows.GetCurrentProcess()
	fmt.Println("curProc", curProc, err)

	// Get current process token
	var token windows.Token
	err = windows.OpenProcessToken(curProc,
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|
			windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ASSIGN_PRIMARY, &token)
	// err = windows.OpenProcessToken(curProc, windows.MAXIMUM_ALLOWED, &token)
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
	for _, s := range []*windows.SID{worldSid} {
		attrs = append(attrs, windows.SIDAndAttributes{Sid: s})
	}
	_ = attrs

	// create restricted token
	var newToken windows.Token
	err = createRestrictedToken(token, DISABLE_MAX_PRIVILEGE,
		0, nil,
		0, nil,
		uint32(len(attrs)), &attrs[0],
		&newToken)
	fmt.Println("restricted token", newToken, err)

	// low privillege token
	var lowToken windows.Token
	err = windows.DuplicateTokenEx(token, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityAnonymous,
		windows.TokenPrimary, &lowToken)
	fmt.Println("duplicated token", lowToken, err)

	// https://support.microsoft.com/en-ca/help/243330/well-known-security-identifiers-in-windows-operating-systems
	lowSidName := "S-1-16-4096" // Low Mandatory Level
	lowSid, err := windows.StringToSid(lowSidName)
	fmt.Println("low sid", lowSid, err)

	tml := windows.Tokenmandatorylabel{
		Label: windows.SIDAndAttributes{
			Sid:        lowSid,
			Attributes: windows.SE_GROUP_INTEGRITY,
		},
	}
	_ = tml

	err = windows.SetTokenInformation(lowToken, syscall.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&tml)), uint32(unsafe.Sizeof(tml))+windows.GetLengthSid(lowSid))
	fmt.Println("low token", lowToken, err)

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
	_ = deskAccess

	// newDesk, err := createDesktop(nameW, nil, 0, 0, deskAccess, nil)
	// allow low integrity to medium / high integrity pipe
	deskSd, err := windows.SecurityDescriptorFromString("S:(ML;;NW;;;LW)D:(A;;0x12019f;;;WD)")
	fmt.Println("deskSa", deskSd, err)

	deskSa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: deskSd,
		InheritHandle:      0,
	}

	newDesk, err := createDesktop(nameW, nil, 0, 0, GENERIC_ALL, &deskSa)
	fmt.Println("new desktop", newDesk, err)

	if false {
		// grant access
		grantAccess(windows.Handle(newDesk), groupSid)

		// win station
		winStation := getProcessWindowStation()
		fmt.Println("win station", winStation)
		grantAccess(windows.Handle(winStation), groupSid)
	}

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

	startupInfo.Desktop = nameW

	// process info
	var processInfo windows.ProcessInformation

	// argv := syscall.StringToUTF16Ptr("C:\\go\\bin\\go.exe")
	// argv := syscall.StringToUTF16Ptr("c:\\windows\\system32\\calc.exe")
	// argv := syscall.StringToUTF16Ptr("c:\\windows\\system32\\cmd.exe")
	//argv := syscall.StringToUTF16Ptr("c:\\windows\\py.exe -c \"while True: pass\"")
	// argv := syscall.StringToUTF16Ptr("c:\\windows\\system32\\tasklist.exe")
	argv := syscall.StringToUTF16Ptr("C:\\Program Files\\Git\\usr\\bin\\cat.exe go.mod")

	// Create process
	syscall.ForkLock.Lock()

	// err = windows.CreateProcess(nil, argv, nil, nil, true,
	// 	windows.CREATE_NEW_PROCESS_GROUP|windows.CREATE_NEW_CONSOLE|windows.CREATE_SUSPENDED,
	// 	nil, nil, &startupInfo, &processInfo)

	// err = CreateProcessAsUser(windows.Handle(newToken), nil, argv, nil, nil, true,
	// 	windows.CREATE_NEW_PROCESS_GROUP|windows.CREATE_NEW_CONSOLE|windows.CREATE_SUSPENDED,
	// 	nil, nil, &startupInfo, &processInfo)

	err = CreateProcessAsUser(windows.Handle(lowToken), nil, argv, nil, nil, true,
		windows.CREATE_NEW_PROCESS_GROUP|windows.CREATE_NEW_CONSOLE|windows.CREATE_SUSPENDED,
		nil, nil, &startupInfo, &processInfo)

	syscall.ForkLock.Unlock()
	fmt.Println("create process as user", err, processInfo)

	// Close used pipes
	windows.CloseHandle(p[1])
	windows.CloseHandle(p2[0])

	// assign process to job object
	err = windows.AssignProcessToJobObject(hJob, windows.Handle(processInfo.Process))
	fmt.Println(err)

	// Disable hard error?

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

func grantAccess(h windows.Handle, groupSid *windows.SID) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_WINDOW_OBJECT,
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
	windows.SetSecurityInfo(h, windows.SE_WINDOW_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, newACL, nil)

	// Get sid
	var nSid *windows.SID
	err = windows.AllocateAndInitializeSid(
		&windows.SECURITY_MANDATORY_LABEL_AUTHORITY,
		1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0, &nSid,
	)
	fmt.Println(nSid, err)

	// SYSTEM_MANDATORY_LABEL_ACE
	/////////////////////////////// leave for now logon.cc: 119 - 147
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
