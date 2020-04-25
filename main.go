package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func createLowMandatoryLevelToken() (token windows.Token, err error) {
	// Get current process token
	var procToken windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ASSIGN_PRIMARY,
		&procToken); err != nil {
		return token, err
	}

	// create restricted token
	if err := CreateRestrictedToken(procToken, DISABLE_MAX_PRIVILEGE, 0, nil, 0, nil, 0, nil, &token); err != nil {
		return token, err
	}
	defer func() {
		if err != nil {
			token.Close()
		}
	}()

	lowSid, err := windows.StringToSid(SID_LOW_MANDATORY_LEVEL)
	if err != nil {
		return token, err
	}
	tml := windows.Tokenmandatorylabel{
		Label: windows.SIDAndAttributes{
			Sid:        lowSid,
			Attributes: windows.SE_GROUP_INTEGRITY,
		},
	}
	if err = windows.SetTokenInformation(token, syscall.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&tml)), uint32(unsafe.Sizeof(tml))); err != nil {
		return token, err
	}
	return token, nil
}

func main() {
	// low integrity security descriptor
	// https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings
	// ML: mandatory level, NW: no write up, LW: low mandatory level
	// A: Allow; .. WD: everyone SID
	sdString := "S:(ML;;NW;;;LW)D:(A;;0x12019f;;;WD)"
	sd, err := windows.SecurityDescriptorFromString(sdString)
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	sacl, _, _ := sd.SACL()

	workDir, err := ioutil.TempDir("", "")
	windows.SetNamedSecurityInfo(workDir, windows.SE_FILE_OBJECT, windows.LABEL_SECURITY_INFORMATION, nil, nil, nil, sacl)
	fmt.Println("workdir:", workDir, err)

	lowToken, err := createLowMandatoryLevelToken()
	fmt.Println(lowToken, err)

	// create desktop
	random := make([]byte, 8)
	rand.Read(random)
	name := fmt.Sprintf("winc_%08x_%s", windows.GetCurrentProcessId(), hex.EncodeToString(random))
	nameW := syscall.StringToUTF16Ptr(name)

	newDesk, err := CreateDesktop(nameW, nil, 0, 0, GENERIC_ALL, &sa)
	fmt.Println("new desktop", newDesk, err)

	// create job object
	hJob, err := windows.CreateJobObject(nil, nil)
	fmt.Println(hJob, err)

	// jobObject limitations
	var limit windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION

	// time limit: 100 * nanosecond
	limit.BasicLimitInformation.PerJobUserTimeLimit = int64(time.Second.Nanoseconds()/100) * 100
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
	err = windows.CreatePipe(&p[0], &p[1], &sa, 0)
	fmt.Println(p, err)

	// create input pipe
	p2 := make([]windows.Handle, 2)
	err = windows.CreatePipe(&p2[0], &p2[1], &sa, 0)
	fmt.Println(p2, err)

	// create input mapping file
	fin, err := createFileMapping([]byte("Test Content"), "input")
	fmt.Println("file mapping", fin, err)

	//argv := syscall.StringToUTF16Ptr("C:\\go\\bin\\go.exe")
	//argv := syscall.StringToUTF16Ptr("c:\\windows\\system32\\calc.exe")
	// argv := syscall.StringToUTF16Ptr("c:\\windows\\system32\\cmd.exe")
	//argv := syscall.StringToUTF16Ptr("c:\\windows\\py.exe -c \"while True: pass\"")
	//argv := syscall.StringToUTF16Ptr("c:\\windows\\system32\\tasklist.exe")
	//argv := syscall.StringToUTF16Ptr("C:\\Program Files\\Git\\usr\\bin\\cat.exe go.mod")
	argv := syscall.StringToUTF16Ptr("C:\\Program Files\\Git\\usr\\bin\\touch.exe 1")
	workDirW := syscall.StringToUTF16Ptr(workDir)

	// create pipe mapping
	var startupInfo syscall.StartupInfo
	startupInfo.Flags |= windows.STARTF_USESTDHANDLES // STARTF_FORCEOFFFEEDBACK
	startupInfo.Desktop = nameW

	// Create process
	// process info
	var processInfo syscall.ProcessInformation
	func() {
		syscall.ForkLock.Lock()
		defer syscall.ForkLock.Unlock()

		var inHandle, outHandle windows.Handle

		err = windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(fin.Fd()), windows.CurrentProcess(), &inHandle, 0, true, syscall.DUPLICATE_SAME_ACCESS)
		defer windows.CloseHandle(inHandle)

		err = windows.DuplicateHandle(windows.CurrentProcess(), p[1], windows.CurrentProcess(), &outHandle, 0, true, syscall.DUPLICATE_SAME_ACCESS)
		defer windows.CloseHandle(outHandle)

		startupInfo.StdInput = syscall.Handle(inHandle)
		startupInfo.StdOutput = syscall.Handle(outHandle)
		startupInfo.StdErr = syscall.Handle(outHandle)

		err = syscall.CreateProcessAsUser(syscall.Token(lowToken), nil, argv, nil, nil, true,
			windows.CREATE_NEW_PROCESS_GROUP|windows.CREATE_NEW_CONSOLE|windows.CREATE_SUSPENDED,
			nil, workDirW, &startupInfo, &processInfo)
	}()
	fmt.Println("create process as user", err, processInfo)

	// Close child pipes
	windows.CloseHandle(p[1])
	windows.CloseHandle(p2[0])

	// assign process to job object
	err = windows.AssignProcessToJobObject(hJob, windows.Handle(processInfo.Process))
	fmt.Println(err)

	// Disable hard error?

	// resume thread
	ret2, err := windows.ResumeThread(windows.Handle(processInfo.Thread))
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
	event, err := windows.WaitForSingleObject(windows.Handle(processInfo.Process), windows.INFINITE)
	fmt.Println(event, err)

	// get process exit code
	var exitCode uint32
	err = windows.GetExitCodeProcess(windows.Handle(processInfo.Process), &exitCode)
	fmt.Println(exitCode, err)

	<-done
	fmt.Scanln()
}

// func grantAccess(h windows.Handle, groupSid *windows.SID) {
// 	sd, err := windows.GetSecurityInfo(h, windows.SE_WINDOW_OBJECT,
// 		windows.DACL_SECURITY_INFORMATION)
// 	fmt.Println(sd, err)

// 	// explicit access
// 	expAccess := windows.EXPLICIT_ACCESS{
// 		AccessPermissions: GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
// 		AccessMode:        windows.GRANT_ACCESS,
// 		Trustee: windows.TRUSTEE{
// 			MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
// 			TrusteeForm:              windows.TRUSTEE_IS_SID,
// 			TrusteeType:              windows.TRUSTEE_IS_GROUP,
// 			TrusteeValue:             windows.TrusteeValueFromSID(groupSid),
// 		},
// 	}
// 	oldACL, _, err := sd.DACL()
// 	newACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{expAccess}, oldACL)
// 	fmt.Println("new ACL", oldACL, newACL, err)

// 	// set security info
// 	windows.SetSecurityInfo(h, windows.SE_WINDOW_OBJECT,
// 		windows.DACL_SECURITY_INFORMATION, nil, nil, newACL, nil)

// 	// Get sid
// 	var nSid *windows.SID
// 	err = windows.AllocateAndInitializeSid(
// 		&windows.SECURITY_MANDATORY_LABEL_AUTHORITY,
// 		1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0, &nSid,
// 	)
// 	fmt.Println(nSid, err)

// 	// SYSTEM_MANDATORY_LABEL_ACE
// 	/////////////////////////////// leave for now logon.cc: 119 - 147
// }
