---
name: lotl-hunting
description: >-
  Hunting for Living-off-the-Land (LotL) abuse in enterprise environments covering LOLBin detection,
  anomalous parent-child process chains, unsigned script execution, and hidden application execution.
domain: endpoint-security
subdomain: lotl-hunting
tags: [lotl, lolbins, hunting, endpoint-detection, process-chain, unsigned-scripts]
mitre_attack: [T1059, T1047, T1218, T1086, T1197, T1202, T1216, T1220]
nist_csf: [DE.AE-2, DE.AE-3, DE.CM-1, DE.CM-4, DE.CM-7]
d3fend: [D3-EDR, D3-PSL, D3-SD, D3-SIEM]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, MEASURE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during proactive threat hunting for LOLBin abuse, when investigating anomalous endpoint behavior, for detection engineering focusing on fileless malware, and during EDR deployment validation.

## Prerequisites

- EDR platform with process execution logging (CrowdStrike, Defender, SentinelOne)
- Sysmon with SwiftOnSecurity configuration on all endpoints
- SIEM with process creation and command-line ingestion
- LOLBAS project reference (lolbas-project.github.io)
- Python 3.10+ for behavioral analytics and threshold calculation
- Baseline of normal administrative tool usage

## Workflow

1. Baseline normal LOLBin usage: Profile typical certutil, mshta, regsvr32, wmic, cscript, and powershell usage across the environment
2. Hunt for abnormal certutil: Detect certutil.exe with URL download (`-urlcache`, `-split`, `-f`), decode (`-decode`), or encode operations from non-IT users
3. Detect regsvr32 abuse: Hunt for regsvr32.exe with scrobj.dll for COM scriptlet execution (Squiblydoo)
4. Monitor mshta: Identify mshta.exe execution from Office applications (Word, Excel spawning mshta with JavaScript)
5. Find PowerShell anomalies: Detect base64-encoded PowerShell, PowerShell with hidden window, obfuscated parameters, and execution from Office apps
6. Discover wmic abuse: Hunt for `wmic process call create` for lateral movement and remote command execution
7. Track rundll32: Identify rundll32.exe loading DLLs from non-system paths, AppData, Temp, or user Downloads
8. Hunt for BITSAdmin: Detect BITS job creation for file transfer (staging or exfiltration)
9. Identify LOLBin chains: Correlate process creation chains: Office → CMD → PowerShell → Net.WebClient
10. Create alert rules: Develop EDR detection rules for observed anomalous LOLBin patterns with FP tuning

## Verification

- Baseline covers 30+ days of normal LOLBin usage across all departments
- Anomalous certutil downloads trigger alerts with user and process context
- Office application spawning LOLBins are detected and alerted
- Hidden PowerShell execution (WindowStyle Hidden, EncodedCommand) triggers immediate alert
- wmic remote execution is detected (wmic /NODE) from non-admin workstations
- New LOLBin variants are mapped to MITRE ATT&CK techniques
- Detection false positive rate is < 2% after tuning
