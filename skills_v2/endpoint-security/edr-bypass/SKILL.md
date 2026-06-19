---
name: edr-bypass
description: >-
  EDR bypass and evasion techniques for red team operations covering process injection, direct syscalls,
  ETW patching, AMSI bypass, DLL sideloading, and memory-only payload execution.
domain: endpoint-security
subdomain: edr-bypass
tags: [edr-bypass, evasion, red-team, process-injection, syscalls, amsi-bypass, etw-patching]
mitre_attack: [T1055, T1059, T1562, T1027, T1036, T1056, T1070, T1140, T1197, T1202, T1480, T1497, T1505, T1518, T1543, T1550, T1564, T1574]
nist_csf: [DE.CM-1, DE.CM-4, DE.CM-7, PR.PT-1, PR.PT-3]
d3fend: [D3-EDR, D3-HID, D3-SD, D3-AMSI]
nist_ai_rmf: [DETECT-1.1, MEASURE-1.2, MAP-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during red team operations requiring EDR avoidance, for testing EDR detection capabilities, when developing C2 framework evasion techniques, and for purple team exercises focused on detection bypass.

## Prerequisites

- C2 framework (Cobalt Strike, Brute Ratel, Sliver, Mythic)
- Visual Studio or MinGW for compiling evasive loaders
- Windows 10/11 or Server 2019+ test environment
- Syswhispers2 or Hell's Gate for direct syscall generation
- Sgn or similar shellcode encoders
- Understanding of Windows internals: kernel32, ntdll, PEB, process structures, ETW, AMSI

## Workflow

1. Bypass AMSI: Patch amsi.dll!AmsiScanBuffer at runtime, use hardware breakpoints, or use PowerShell reflection to patch AMSI internals
2. Patch ETW: Disable Event Tracing for Windows by patching ntdll!EtwEventWrite to prevent telemetry collection
3. Implement direct syscalls: Use Syswhispers2 to generate assembly stubs that bypass userland hooks (ntdll.dll hooks placed by EDR)
4. Execute shellcode in memory: Use indirect syscalls or hellgate/halosgate techniques to execute payload without alerting EDR userland hooks
5. Implement process injection: Use callback-based injection (SetThreadContext, User APC, ThreadHijack) or transacted hollowing
6. Use delayed execution: Implement sleep masking, Ekko/Callstack spoofing, or Timer-APC based delayed execution to evade behavioral detection
7. Obfuscate C2 traffic: Use traffic encryption (not just base64), domain fronting, C2 over legitimate services (SaaS, CDN)
8. Disable event logging: Clear or suspend Windows Event Log service, manipulate ETW providers, disable PowerShell logging
9. Implement callback hell: Chain API calls through callbacks to break the call stack and evade EDR detection
10. Test against EDR: Execute evasive payload against target EDR in test environment to verify detection

## Verification

- AMSI scan does not flag malicious PowerShell or .NET assemblies
- ETW events are not generated for malicious activity
- Direct syscalls bypass NTDLL userland hooks
- EDR does not detect shellcode execution in memory
- C2 traffic appears as legitimate HTTPS to allowed domains
- Event logs show no anomalous entries from bypassed detection mechanisms
- Full operational chain (execution → persistence → C2) completes without EDR detection
