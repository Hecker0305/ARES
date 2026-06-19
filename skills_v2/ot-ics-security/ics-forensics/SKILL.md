---
name: ics-forensics
description: >-
  Industrial control system forensic investigation methodology covering PLC/RTU program extraction,
  historian data analysis, engineering workstation forensics, and OT network traffic reconstruction.
domain: ot-ics-security
subdomain: ics-forensics
tags: [ics-forensics, ot-forensics, plc-analysis, historian, scada, industrial-incident-response]
mitre_attack: [T0811, T0816, T0822, T0835, T0839, T0883]
nist_csf: [DE.AE-2, ID.SC-2, PR.DS-1, RS.AN-1, RS.AN-5]
d3fend: [D3-DF, D3-CDR, D3-PCA]
nist_ai_rmf: [MEASURE-2.1, MAP-1.2, RESPOND-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during OT/ICS incident response, when investigating PLC logic manipulation, for forensic analysis of engineering station compromise, after detection of unauthorized SCADA commands, and during post-incident reconstruction of OT attack sequences.

## Prerequisites

- OT network access with forensically sound data acquisition tools
- Vendor-specific software for PLC program upload (RSLogix, TIA Portal, Automation Studio)
- Historian database access (OSIsoft PI, GE iHistorian, Canary Labs)
- Python 3.10+ with protocol parsing libraries (pymodbus, opendnp3, BACpypes)
- Forensic workstation isolated from OT network
- Non-volatile storage for evidence collection
- Understanding of OT protocols and PLC programming (Ladder Logic, Structured Text, FBD)

## Workflow

1. Preserve OT state: Immediately capture network traffic, running processes, and active connections on all OT systems
2. Document affected devices: Record PLC/RTU model, firmware version, program name, and last modified timestamps
3. Upload PLC program: Upload current running program from PLC for offline analysis (compare with backup)
4. Compare with backups: Compare current PLC program against last known good backup for unauthorized modifications
5. Analyze historian data: Query OSIsoft PI or other historians for anomaly periods, alarm data, and process values
6. Review engineering logs: Examine engineering workstation event logs for program download events and unauthorized access
7. Extract HMI screens: Capture current HMI screenshots and compare with baseline for manipulation detection
8. Reconstruct network timeline: Correlate OT network traffic with historian data to build attack sequence
9. Check for backdoors: Look for hidden network connections, unauthenticated webservers, or unauthorized VPN users
10. Document findings: Create forensic report with timeline, affected devices, attacker actions, and system impact

## Verification

- PLC program is uploaded with hash verification (SHA-256)
- Running program is compared byte-by-byte with last known good backup
- Historian data shows exact second-by-second process behavior during incident
- Engineering workstation logs show all user actions during incident window
- Network timeline correlates PLC commands with process value changes
- Root cause of OT incident is identified (malicious vs accidental)
- Remediation steps are verified before returning system to service
