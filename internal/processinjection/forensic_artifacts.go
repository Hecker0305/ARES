package processinjection

var ForensicArtifactDB = map[string][]ForensicArtifact{
	"F1": {
		{Type: ArtifactEventLog, Description: "Process creation event for target process", Location: "Security EventLog EventID 4688", SysmonEventID: 1, Notes: "Target process must exist for injection"},
		{Type: ArtifactEventLog, Description: "OpenProcess with PROCESS_ALL_ACCESS to non-child process", Location: "Security EventLog EventID 4656", SysmonEventID: 10, Notes: "CrowdStrike/SentinelOne hook kernel32!OpenProcess"},
		{Type: ArtifactEventLog, Description: "CreateRemoteThread detected - canonical detection", Location: "Sysmon EventID 8", SysmonEventID: 8, Notes: "Most EDRs hook CreateRemoteThread in kernel32 or NtCreateThreadEx in ntdll"},
		{Type: ArtifactEventLog, Description: "Image load for injected DLL", Location: "Sysmon EventID 7", SysmonEventID: 7, Notes: "DLL LoadLibrary event captured when DLL loaded in remote process"},
		{Type: ArtifactEventLog, Description: "AMSI scan of PowerShell invoking injection", Location: "AMSI ETW EventID 1105", SysmonEventID: 0, Notes: "Windows Defender AMSI scans PowerShell script content"},
		{Type: ArtifactMemory, Description: "Remote allocated memory with PAGE_EXECUTE_READWRITE protection", Location: "Process memory: VirtualAllocEx allocation", SysmonEventID: 0, Notes: "RWX memory in target process is strong indicator"},
		{Type: ArtifactMemory, Description: "Shellcode present in target process memory", Location: "Target process memory region", SysmonEventID: 0, Notes: "Memory scanning can detect known shellcode patterns"},
		{Type: ArtifactPrefetch, Description: "Prefetch file for injected process", Location: "C:\\Windows\\Prefetch\\*.pf", SysmonEventID: 0, Notes: "Shows process execution time and path"},
	},
	"F2": {
		{Type: ArtifactEventLog, Description: "NtCreateThreadEx call from non-standard caller", Location: "ETW Microsoft-Windows-Kernel-Process", SysmonEventID: 8, Notes: "Sysmon EventID 8 also fires for NtCreateThreadEx"},
		{Type: ArtifactEventLog, Description: "OpenProcess with PROCESS_ALL_ACCESS", Location: "Sysmon EventID 10", SysmonEventID: 10, Notes: "Handle to target process object"},
		{Type: ArtifactEventLog, Description: "Process Creation Event", Location: "Security EventLog EventID 4688", SysmonEventID: 1, Notes: "Target process context"},
		{Type: ArtifactMemory, Description: "RWX memory allocation in remote process", Location: "VirtualAllocEx return region", SysmonEventID: 0, Notes: "Avoided by using PAGE_READWRITE then VirtualProtectEx to PAGE_EXECUTE_READ"},
		{Type: ArtifactRegistry, Description: "BamCache entries for payload if written to disk", Location: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache", SysmonEventID: 0, Notes: "Only if payload touches disk"},
	},
	"F3": {
		{Type: ArtifactEventLog, Description: "QueueUserAPC called on target thread", Location: "ETW kernel APC events", SysmonEventID: 0, Notes: "Sysmon does NOT have an APC-specific event ID - this is why APC injection evades Sysmon EventID 8"},
		{Type: ArtifactEventLog, Description: "OpenProcess with PROCESS_ALL_ACCESS", Location: "Sysmon EventID 10", SysmonEventID: 10, Notes: "Handle to target process"},
		{Type: ArtifactEventLog, Description: "OpenThread with THREAD_ALL_ACCESS", Location: "Sysmon EventID 10", SysmonEventID: 10, Notes: "Handle to target thread"},
		{Type: ArtifactEventLog, Description: "Early Bird: CREATE_SUSPENDED process creation", Location: "Security EventLog EventID 4688 + CREATE_SUSPENDED flag", SysmonEventID: 1, Notes: "CreateProcess with CREATE_SUSPENDED (0x00000004) is suspicious"},
		{Type: ArtifactMemory, Description: "Allocated shellcode in remote process (Early Bird)", Location: "Suspended process memory", SysmonEventID: 0, Notes: "Memory allocated before process resumes"},
		{Type: ArtifactEventLog, Description: "Process resumed after APC queued", Location: "ETW thread resume events", SysmonEventID: 0, Notes: "ResumeThread called after APC queue"},
	},
	"F4": {
		{Type: ArtifactEventLog, Description: "OpenProcess with PROCESS_ALL_ACCESS", Location: "Sysmon EventID 10", SysmonEventID: 10, Notes: "Handle to target process"},
		{Type: ArtifactEventLog, Description: "SuspendThread called on target thread", Location: "ETW kernel thread events", SysmonEventID: 0, Notes: "Not directly logged by Sysmon but EDRs hook SuspendThread"},
		{Type: ArtifactEventLog, Description: "SetThreadContext modified RIP/RAX to allocated memory", Location: "ETW Microsoft-Windows-Kernel-Process", SysmonEventID: 0, Notes: "Key detection: RIP changed to point to non-image memory"},
		{Type: ArtifactEventLog, Description: "ResumeThread after context modification", Location: "ETW kernel thread resume", SysmonEventID: 0, Notes: "ResumeThread following SuspendThread+SetThreadContext chain"},
		{Type: ArtifactMemory, Description: "RWX memory in target process", Location: "Target process memory", SysmonEventID: 0, Notes: "Shellcode allocated with execute permission"},
		{Type: ArtifactEventLog, Description: "WriteProcessMemory to remote process", Location: "ETW kernel memory events", SysmonEventID: 0, Notes: "WriteProcessMemory to non-image region"},
	},
	"F5": {
		{Type: ArtifactEventLog, Description: "Process creation with CREATE_SUSPENDED", Location: "Security EventLog EventID 4688", SysmonEventID: 1, Notes: "Process created in suspended state"},
		{Type: ArtifactEventLog, Description: "NtUnmapViewOfSection called on process image", Location: "ETW kernel memory events", SysmonEventID: 0, Notes: "Original image base unmapped from process"},
		{Type: ArtifactEventLog, Description: "WriteProcessMemory to process base address", Location: "ETW kernel memory events", SysmonEventID: 0, Notes: "Writing PE image to hollowed process"},
		{Type: ArtifactEventLog, Description: "SetThreadContext with modified entry point", Location: "ETW Microsoft-Windows-Kernel-Process", SysmonEventID: 0, Notes: "Rax/Rip set to payload entry point"},
		{Type: ArtifactEventLog, Description: "ResumeThread on hollowed process", Location: "ETW kernel thread resume", SysmonEventID: 0, Notes: "Final step before payload execution"},
		{Type: ArtifactMemory, Description: "PE image mapped in process without corresponding ImageLoad event", Location: "Process memory at original image base", SysmonEventID: 0, Notes: "Key forensic indicator - memory-backed PE without disk mapping"},
		{Type: ArtifactRegistry, Description: "AppCompatCache/Shimcache entry for hollowed process", Location: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache", SysmonEventID: 0, Notes: "Shows execution of the hollow host binary"},
		{Type: ArtifactPrefetch, Description: "Prefetch file for hollowed process", Location: "C:\\Windows\\Prefetch\\*.pf", SysmonEventID: 0, Notes: "Prefetch shows hollow binary ran"},
	},
	"F6": {
		{Type: ArtifactEventLog, Description: "No ImageLoad event for injected DLL - key evasion indicator", Location: "Sysmon EventID 7 - deliberately absent", SysmonEventID: 7, Notes: "Absence of ImageLoad event for executing code is itself a detection signal"},
		{Type: ArtifactEventLog, Description: "CreateRemoteThread or NtCreateThreadEx for loader", Location: "Sysmon EventID 8", SysmonEventID: 8, Notes: "Thread created in target process"},
		{Type: ArtifactEventLog, Description: "OpenProcess with PROCESS_ALL_ACCESS", Location: "Sysmon EventID 10", SysmonEventID: 10, Notes: "Handle to target process"},
		{Type: ArtifactMemory, Description: "PE headers in private memory without backing", Location: "Process memory scan", SysmonEventID: 0, Notes: "MZ/PE signature in non-image memory region"},
		{Type: ArtifactMemory, Description: "Reflective DLL in heap or VirtualAlloc memory", Location: "Target process memory", SysmonEventID: 0, Notes: "DLL present as raw bytes in memory, not loaded via LoadLibrary"},
		{Type: ArtifactEventLog, Description: "Suspicious thread start from unknown memory region", Location: "ETW Microsoft-Windows-Kernel-Process", SysmonEventID: 0, Notes: "Thread starting from allocated rather than image memory"},
		{Type: ArtifactNetwork, Description: "DLL fetched from remote URL if using remote variant", Location: "Outbound HTTP/S connection to DLL URL", SysmonEventID: 22, Notes: "Sysmon EventID 22 for DNS query, EventID 3 for network connection"},
	},
	"F7": {
		{Type: ArtifactEventLog, Description: "VirtualAlloc (not VirtualAllocEx - local process)", Location: "ETW kernel memory events", SysmonEventID: 0, Notes: "Local allocation - less monitored than remote"},
		{Type: ArtifactEventLog, Description: "VirtualProtect changed page to executable", Location: "ETW kernel memory events", SysmonEventID: 0, Notes: "RW -> RX transition suspicious in same process"},
		{Type: ArtifactEventLog, Description: "EnumDesktopsA/SetTimer/CreateThread callback with non-module pointer", Location: "ETW kernel thread/callback events", SysmonEventID: 0, Notes: "Callback function pointer pointing to allocated memory"},
		{Type: ArtifactEventLog, Description: "Thread creation from allocated memory", Location: "ETW Microsoft-Windows-Kernel-Process", SysmonEventID: 8, Notes: "Sysmon EventID 8 if CreateThread is used"},
		{Type: ArtifactMemory, Description: "Shellcode in local process memory", Location: "Current process heap", SysmonEventID: 0, Notes: "Scanning process memory reveals shellcode"},
		{Type: ArtifactEventLog, Description: "AMSI detected PowerShell script loading shellcode", Location: "AMSI ETW EventID 1105", SysmonEventID: 0, Notes: "AMSI scans PowerShell before execution"},
	},
	"F8": {
		{Type: ArtifactEventLog, Description: "GlobalAddAtomA called with hex-encoded data", Location: "ETW kernel atom table events", SysmonEventID: 0, Notes: "Global atom table operations logged if kernel atom table tracing enabled"},
		{Type: ArtifactEventLog, Description: "CallWindowProc/CallWindowProcW with atom-derived pointer", Location: "ETW user32 callbacks", SysmonEventID: 0, Notes: "EDRs monitor for unusual CallWindowProc usage"},
		{Type: ArtifactEventLog, Description: "SetWindowLongPtr with atom ID stored in Extra Window Memory", Location: "ETW user32 window events", SysmonEventID: 0, Notes: "Storing atom IDs in window extra memory"},
		{Type: ArtifactMemory, Description: "No cross-process memory allocation - technique operates within same process", Location: "Same process only", SysmonEventID: 0, Notes: "No VirtualAllocEx/WriteProcessMemory needed - harder to detect"},
		{Type: ArtifactEventLog, Description: "CreateWindowEx call may be logged", Location: "ETW user32 window creation", SysmonEventID: 0, Notes: "Legitimate applications also create windows - high false positive"},
	},
	"F9": {
		{Type: ArtifactEventLog, Description: "Rapid VirtualProtect transitions RW->RX->RW on same region", Location: "ETW kernel memory events", SysmonEventID: 0, Notes: "Memory page permission changes in quick succession"},
		{Type: ArtifactMemory, Description: "Memory at time of scan may show RW (not RX or RWX)", Location: "Process memory during RW phase", SysmonEventID: 0, Notes: "Gargoyle evades memory scanners by flipping permissions back to RW after execution"},
		{Type: ArtifactEventLog, Description: "Timer/callback with non-standard memory target", Location: "ETW kernel timer events", SysmonEventID: 0, Notes: "Timer queue callbacks pointing to allocated memory"},
		{Type: ArtifactEventLog, Description: "No cross-process API calls - purely local", Location: "Absence of OpenProcess/WriteProcessMemory", SysmonEventID: 0, Notes: "No cross-process indicators"},
	},
	"F10": {
		{Type: ArtifactEventLog, Description: "Direct syscall instruction executed from non-ntdll memory", Location: "ETW kernel syscall events", SysmonEventID: 0, Notes: "syscall instruction from non-standard code page"},
		{Type: ArtifactEventLog, Description: "NtAllocateVirtualMemory syscall with custom stub", Location: "Kernel ETW SysCall events", SysmonEventID: 0, Notes: "Kernel sees the syscall but caller address not in ntdll"},
		{Type: ArtifactMemory, Description: "Custom syscall stubs in executable memory", Location: "Allocated memory with syscall gadgets", SysmonEventID: 0, Notes: "Memory scanning can find syscall; ret sequences outside ntdll"},
		{Type: ArtifactEventLog, Description: "No calls to hooked ntdll functions - absence of expected call chain", Location: "ETW ntdll function calls", SysmonEventID: 0, Notes: "EDRs that only hook userland ntdll will miss this entirely"},
		{Type: ArtifactEventLog, Description: "Thread creation from non-image memory", Location: "ETW Microsoft-Windows-Kernel-Process", SysmonEventID: 8, Notes: "Thread start address not in any loaded module"},
	},
	"F11": {
		{Type: ArtifactEventLog, Description: "Process creation with EXTENDED_STARTUPINFO_PRESENT flag", Location: "Security EventLog EventID 4688", SysmonEventID: 1, Notes: "Flag 0x00000100 indicates extended startup info is used"},
		{Type: ArtifactEventLog, Description: "Parent PID does not match expected parent-child relationship", Location: "EventID 4688 CreatorProcessId field", SysmonEventID: 0, Notes: "e.g., notepad.exe showing svchost.exe as parent"},
		{Type: ArtifactEventLog, Description: "OpenProcess to spoofed parent process", Location: "Sysmon EventID 10", SysmonEventID: 10, Notes: "Handle to spoofed parent process"},
		{Type: ArtifactRegistry, Description: "Process creation logged in Shimcache/AppCompatCache", Location: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache", SysmonEventID: 0, Notes: "Spoofed process execution recorded under its own image name"},
		{Type: ArtifactPrefetch, Description: "Prefetch for spoofed child process", Location: "C:\\Windows\\Prefetch\\*.pf", SysmonEventID: 0, Notes: "Prefetch created for executed binary"},
	},
	"F12": {
		{Type: ArtifactEventLog, Description: "WriteProcessMemory to loaded module .text section", Location: "ETW kernel memory events", SysmonEventID: 0, Notes: "Modifying code section of a loaded module is highly anomalous"},
		{Type: ArtifactEventLog, Description: "VirtualProtectEx changing module .text to RWX", Location: "ETW kernel memory events", SysmonEventID: 0, Notes: "Code section permissions changed from RX to RWX"},
		{Type: ArtifactEventLog, Description: "CreateRemoteThread to module code address", Location: "Sysmon EventID 8", SysmonEventID: 8, Notes: "Thread starting at module entry point but code has been replaced"},
		{Type: ArtifactEventLog, Description: "Module integrity check failure (hash mismatch)", Location: "ETW module load events", SysmonEventID: 0, Notes: "Verified signing hash of module does not match known good hash"},
		{Type: ArtifactEventLog, Description: "DLL loaded from unexpected directory (sideloading)", Location: "Sysmon EventID 7", SysmonEventID: 7, Notes: "DLL loaded from C:\\Users\\<user>\\AppData instead of C:\\Windows\\System32"},
		{Type: ArtifactFileSystem, Description: "Malicious DLL planted in search order location", Location: "Application directory or %PATH% directory", SysmonEventID: 11, Notes: "Sysmon EventID 11 for file creation"},
	},
}

func GetAllArtifacts() []ForensicArtifact {
	var all []ForensicArtifact
	for _, artifacts := range ForensicArtifactDB {
		all = append(all, artifacts...)
	}
	return all
}

func GetArtifactsByTechnique(techniqueID string) []ForensicArtifact {
	if artifacts, ok := ForensicArtifactDB[techniqueID]; ok {
		out := make([]ForensicArtifact, len(artifacts))
		copy(out, artifacts)
		return out
	}
	return nil
}

var SysmonEventReference = map[int]string{
	1:  "Process Creation - command line, image, PID, parent PID, hash, user, UTC time",
	2:  "File Creation Time Changed - file was created/modified with different timestamp",
	3:  "Network Connection - source IP/port, destination IP/port, protocol, process",
	4:  "Service State Change - service start/stop events",
	5:  "Process Terminated - process exit with exit code",
	6:  "Driver Loaded - driver image loaded into kernel",
	7:  "Image Loaded - DLL/image loaded into process (module load)",
	8:  "CreateRemoteThread - remote thread creation across processes (KEY for injection detection)",
	9:  "RawAccessRead - drive read with \\\\.\\ handle (indicator of raw disk access)",
	10: "ProcessAccess - handle to process opened (OpenProcess/NtOpenProcess)",
	11: "FileCreate - file created or overwritten",
	12: "RegistryEvent (Object Create/Delete) - registry key/value create/delete",
	13: "RegistryEvent (Value Set) - registry value modification",
	14: "RegistryEvent (Key/Value Rename) - registry rename operations",
	15: "FileCreateStreamHash - NTFS alternate data stream creation",
	16: "ServiceConfigurationChange - service configuration modified",
	17: "PipeEvent - named pipe creation/connection",
	18: "SecurityEvent (ETW) - security-related ETW events",
	19: "WmiEvent - WMI filter/consumer/binding registration",
	20: "WmiEventConsumerActivity - WMI consumer activity",
	21: "WmiEventFilterActivity - WMI filter activity",
	22: "DNSEvent - DNS query by process",
	23: "FileDelete - file deletion with detection of file deletion techniques",
	24: "ClipboardChange - clipboard content change",
	25: "ProcessTampering - process image size/check sum modification (relevant for hollowing)",
	26: "FileDeleteDetected - file deletion logged via Minifilter",
	27: "FileBlockExecutable - executable file blocked from execution",
	28: "FileBlockShredding - file shredding attempt blocked",
	29: "FileExecutableDetected - executable file detected in write location",
	255: "Error - error event with sysmon status",
}

var WindowsEventReference = map[int]string{
	4688: "Process Creation - new process created (includes parent PID, image path, command line, user)",
	4689: "Process Exit - process exited with exit code",
	4656: "Handle to Object - handle requested for object (audits OpenProcess with specific access mask)",
	4658: "Handle to Object Closed - handle to object closed",
	4690: "Handle to Object Duplicated - handle duplicated to another process",
	4691: "Indirect Access to Object - indirect handle request to object",
	1102: "Security Log Cleared - audit log cleared (indicator of forensic anti-forensics)",
	1105: "AMSI ETW event - script content scanned by Windows Defender AMSI (PowerShell/.NET/VBS)",
	7036: "Service State Change - service entered running/stopped state",
	7045: "Service Creation - new service installed",
	8004: "WMI Filter/Consumer - WMI persistence registration",
}
