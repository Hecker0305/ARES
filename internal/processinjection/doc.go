// Package processinjection implements Windows process injection techniques:
// F1: CreateRemoteThread shellcode injection
// F2: Native API injection (NtCreateThreadEx)
// F3: APC injection (QueueUserAPC)
// F4: Thread hijacking (SetThreadContext)
// F5: Process hollowing (RunPE)
// F6: Reflective DLL injection
// F7: Local shellcode injection
// F8: Atom bombing / Extra Window Memory injection
// F9: Gargoyle memory flipping
// F10: D/Invoke indirect syscall injection
// F11: PPID spoofing
// F12: Module stomping / DLL sideloading
//
// Each technique exposes:
//   - Executable PowerShell/CMD/C# command strings
//   - Forensic artifact documentation (Event IDs, Sysmon IDs, registry, files, network, memory)
//   - API-level descriptions of how each technique works internally
//   - Go-callable functions via the InjectionEngine orchestrator
package processinjection
