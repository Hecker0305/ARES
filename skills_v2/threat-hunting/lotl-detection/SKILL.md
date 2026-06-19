---
name: lotl-detection
description: >-
  Detection and analysis of Living-off-the-Land (LotL) binary abuse across Windows, Linux, and macOS environments.
  Covers LOLBins, LOLScripts, and LOLlibs used by adversaries for fileless execution, lateral movement, and defense evasion.
domain: threat-hunting
subdomain: lotl-detection
tags: [lotl, lolbins, fileless, windows, linux, macros, powershell, wmi, defense-evasion]
mitre_attack: [T1059, T1218, T1047, T1003, T1053, T1086, T1175, T1191, T1197, T1202, T1216, T1220, T1497]
nist_csf: [DE.AE-3, DE.CM-1, DE.CM-4, DE.CM-7, PR.PT-1, PR.PT-3]
d3fend: [D3-EDR, D3-PSL, D3-SD, D3-PA, D3-CA]
nist_ai_rmf: [MEASURE-1.3, MEASURE-3.1, DETECT-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when hunting for fileless malware and living-off-the-land techniques, during incident response where traditional malware is not found but suspicious behavior is present, when monitoring for LOLBin usage in critical servers, and during red team exercises to identify gaps in LotL detection coverage.

## Prerequisites

- EDR platform with process command-line logging enabled (CrowdStrike, Defender ATP, SentinelOne)
- Sysmon installed on Windows endpoints with proper configuration
- PowerShell script block logging (Event ID 4104) enabled via GPO
- Windows Event Log forwarding to SIEM for security auditing
- Python 3.10+ with pandas for log analysis
- Access to LOLBAS project database (https://lolbas-project.github.io)

## Workflow

1. Inventory LOLBins in environment: Baseline common administrative usage of certutil, wmic, cscript, mshta, regsvr32, msiexec, rundll32, powershell, bitsadmin
2. Enable maximum logging: Ensure Sysmon Event IDs 1, 3, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18 are collected; enable PowerShell Module Logging and Script Block Logging
3. Hunt for suspicious certutil usage: `certutil -urlcache -split -f http://<url> <file>` for file download and `certutil -decode` for payload decoding
4. Detect mshta abuse: Monitor for mshta.exe executing JavaScript/VBScript from remote URLs or inline scripts
5. Monitor regsvr32: Detect regsvr32.exe with scrobj.dll for COM scriptlet execution (Squiblydoo technique)
6. Analyze wmic usage: Hunt for wmic process call create for lateral movement and wmic /node for remote execution
7. Track rundll32: Monitor for rundll32.exe calling JavaScript or executing DLLs from suspicious paths
8. Detect PowerShell without -WindowsStyle Hidden: Identify base64-encoded commands and PowerShell direct to .NET
9. Hunt for BITSAdmin: Monitor BITS job creation for data exfiltration or payload staging
10. Cross-reference with threat intelligence: Match observed LOLBin usage with known adversary TTPs

## Verification

- All high-value systems have Sysmon deployed with current configuration
- PowerShell script block logging is enabled on 100% of domain-joined Windows systems
- Alerting is configured for the top 10 LOLBin abuse techniques
- Baseline of normal administrative usage is established for each LOLBin
- Detection rules exist for regsvr32 remote COM execution, certutil web downloads, and mshta inline script execution
- False positive tuning is in place with allow-lists for approved administrative tasks
