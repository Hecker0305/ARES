---
name: windows-event-hunting
description: >-
  Advanced Windows Event Log analysis for threat detection and forensic investigation.
  Covers Security, System, Application, PowerShell, Sysmon, and Active Directory event logs.
domain: threat-hunting
subdomain: windows-event-hunting
tags: [windows, event-log, sysmon, security, ad, forensics, threat-hunting]
mitre_attack: [T1003, T1007, T1018, T1021, T1035, T1036, T1049, T1053, T1055, T1057, T1059, T1070, T1078, T1087, T1098, T1105, T1110, T1122, T1134, T1136, T1140, T1175, T1190, T1197, T1207, T1218, T1482, T1484, T1485, T1497, T1505, T1518, T1526, T1529, T1543, T1546, T1547, T1548, T1550, T1552, T1555, T1556, T1558, T1562, T1569, T1574]
nist_csf: [DE.AE-2, DE.AE-3, DE.CM-1, DE.CM-3, DE.CM-4, DE.CM-7, DE.DP-3]
d3fend: [D3-EDR, D3-SIEM, D3-NDR, D3-PSL, D3-CDR]
nist_ai_rmf: [MEASURE-1.3, DETECT-1.1, DETECT-2.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during Windows security incident investigation, proactive threat hunting across Windows endpoints, Active Directory compromise assessment, lateral movement detection, and forensic analysis of compromised Windows systems.

## Prerequisites

- Windows Event Log forwarding to SIEM or centralized log collector
- Sysmon installed on target systems with SwiftOnSecurity configuration
- PowerShell 5.1+ for log querying via Get-WinEvent
- Access to Windows Event Viewer or wevtutil on endpoints
- Python 3.10+ with python-evtx for offline log parsing
- Splunk, Elastic, or Sentinel access for log correlation
- Understanding of Windows Event ID mapping to security events

## Workflow

1. Establish log source integrity: Verify all domain controllers, critical servers, and workstations forward required event logs
2. Configure log collection: Enable PowerShell Script Block Logging (4104), Command Line logging (4688 with command line), and Sysmon
3. Query for credential access: Search Event ID 4624 (Logon), 4648 (Explicit Credential), and 4672 (Admin Logon) for anomalies
4. Hunt for lateral movement: Analyze Event ID 4624 (Network logon type 3) and 4648 for pass-the-hash and RDP abuse
5. Detect privilege escalation: Monitor Event ID 4672, 4673, 4703 (Token manipulation), and 5136 (AD modification)
6. Identify persistence mechanisms: Check Event ID 4697 (Service install), 7045 (Service creation), and 9624 (Scheduled task)
7. Analyze forensic timeline: Correlate Event IDs 1102 (Log clear), 104 (Log start), and 7036 (Service state change)
8. Detect defense evasion: Monitor Event ID 4688 with process names matching LOLBins and Event ID 4657 (Registry modification)
9. Investigate Active Directory compromise: Analyze Event IDs 4742, 4738, 4720, 4726 for account modifications
10. Generate threat hunting report with event pattern analysis and timeline reconstruction

## Verification

- All critical Windows systems forward Event IDs 1-20 (Sysmon), 4624-4779 (Security), and 4104 (PowerShell)
- Log size and retention policies maintain at least 90 days of event history
- Correlation rules are in place for the top 20 suspicious event sequences
- Baseline of normal event volume and patterns is established for each server role
- Event log tampering alerts (Event ID 1102, 104) trigger immediate investigation
- Historical log analysis can reconstruct incident timelines within 5-minute accuracy
