---
name: memory-forensics
description: >-
  Volatile memory acquisition and analysis using Volatility 3 and Rekall for detecting rootkits,
  injected code, hidden processes, network connections, encryption keys, and user artifacts.
domain: digital-forensics
subdomain: memory-forensics
tags: [memory-forensics, volatility, ram, forensics, rootkit, process-injection]
mitre_attack: [T1003, T1012, T1055, T1057, T1070, T1485]
nist_csf: [DE.AE-2, DE.CM-1, ID.SC-2, PR.DS-1, RS.AN-1]
d3fend: [D3-MF, D3-VM, D3-EDR]
nist_ai_rmf: [MEASURE-2.1, MAP-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during incident response to find evidence not written to disk, when investigating fileless malware, for detecting process injection and kernel rootkits, and when analyzing live system state during a security incident.

## Prerequisites

- Memory acquisition tool (FTK Imager, DumpIt, WinPmem, LiME, AVML)
- Volatility 3+ installed with plugins
- Python 3.10+ with volatility3 libraries
- Target system memory dump from Windows, Linux, or macOS
- OS profile/kernel info database for symbol resolution
- Sufficient storage (RAM dump size is typically RAM + 10%)

## Workflow

1. Acquire memory: Capture RAM using appropriate tool (WinPmem for Windows, LiME for Linux, AVML for OS X)
2. Verify acquisition: Hash the memory dump and validate integrity using SHA-256
3. Identify OS profile: Use `windows.info`, `linux.info`, or `mac.info` to determine OS version and kernel
4. Scan for malicious processes: `windows.pslist`, `windows.psscan`, `windows.psxview` for hidden/injected processes
5. Analyze process tree: `windows.pstree` to understand parent-child relationships and anomalous chains
6. Dump process memory: `windows.memmap`, `windows.dumpfiles` to extract specific process memory
7. Extract network evidence: `windows.netscan` for active connections, listening ports, and associated processes
8. Scan for injected code: `windows.malfind` to detect executable code in non-executable memory regions
9. Extract kernel objects: `windows.modscan`, `windows.driverscan` to find kernel-level implants
10. Create forensic timeline: `windows.timeliner` to build chronological event timeline for reporting

## Verification

- Memory dump hash verified (matches original acquisition hash)
- All hidden processes identified (cross-reference pslist, psscan, psxview)
- Process injection confirmed with malfind results showing executable code
- Network connections correlated with processes and command-line arguments
- User activity timeline reconstructed with file access, registry, and process evidence
- Kernel rootkit anomalies documented (hooks, driver signatures)
