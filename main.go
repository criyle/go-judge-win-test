package main

import (
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

func main() {
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
	startupInfo.Flags |= windows.STARTF_USESTDHANDLES
	startupInfo.StdInput = p2[0]
	startupInfo.StdOutput = p[1]
	startupInfo.StdErr = p[1]

	// process info
	var processInfo windows.ProcessInformation

	// argv := syscall.StringToUTF16Ptr("C:\\go\\bin\\go.exe")
	// argv := syscall.StringToUTF16Ptr("c:\\windows\\system32\\calc.exe")
	// argv := syscall.StringToUTF16Ptr("c:\\windows\\system32\\cmd.exe")
	argv := syscall.StringToUTF16Ptr("c:\\windows\\py.exe -c \"while True: pass\"")
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
