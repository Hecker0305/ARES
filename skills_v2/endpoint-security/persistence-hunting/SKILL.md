---
name: persistence-hunting
description: >-
  Endpoint persistence hunting across Windows, Linux, and macOS covering registry, scheduled tasks, services,
  launch agents, kernel modules, bootkits, and user-level and system-level persistence mechanisms.
domain: endpoint-security
subdomain: persistence-hunting
tags: [persistence, hunting, endpoint, registry, scheduled-tasks, services, launch-agents, bootkits]
mitre_attack: [T1053, T1068, T1098, T1136, T1505, T1543, T1546, T1547, T1548, T1554, T1574]
nist_csf: [DE.AE-2, DE.CM-1, DE.CM-3, DE.CM-4, DE.CM-7]
d3fend: [D3-EDR, D3-PED, D3-HID, D3-AUDIT]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, MEASURE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during endpoint compromise investigations to ensure all persistence mechanisms are identified, for proactive threat hunting across the environment, during post-exploitation cleanup verification, and when detecting advanced adversary persistence.

## Prerequisites

- EDR with persistent mechanism detection capability
- Sysmon configuration enabling registry event monitoring (Event IDs 12, 13, 14)
- PowerShell for Windows persistence enumeration
- Bash/Zsh for Linux/macOS persistence hunting
- Volatility 3 for kernel-level persistence detection
- Authentication logging for service/account persistence detection

## Workflow

1. Enumerate auto-start extensibility points (ASEPs): Check user/system Run keys, Startup folders, and Winlogon shell replacements
2. Audit scheduled tasks: Enumerate all scheduled tasks for suspicious triggers, actions, and user contexts
3. Review Windows services: Check for services with non-Microsoft paths, services loading from user-writable paths, or unsigned binaries
4. Detect WMI persistence: Evaluate permanent WMI event consumers (EventFilter + EventConsumer) for persistence
5. Check image hijacks: Audit Image File Execution Options (IFEO), silent process exit, and DLL search order hijacking
6. Detect bootkits: Check MBR/VBR, EFI partition, driver load order, and early boot drivers for modifications
7. Linux/macOS persistence: Check cron jobs, systemd services, launch daemons, kernel modules, LD_PRELOAD, and profile scripts
8. Analyze browser extensions: Review Chrome, Firefox, and Edge extensions for suspicious content modification
9. Review account modifications: Check for new user accounts, group membership changes, and disabled/enabled accounts
10. Cross-reference with baseline: Compare current ASEP state against known-good baseline to identify new entries

## Verification

- All auto-start extensibility points are enumerated and documented
- Scheduled tasks with SYSTEM-level privileges from non-Microsoft publishers are identified
- WMI consumers are documented with their associated filters and scripts
- Bootkits are detected via comparison of MBR/EFI hash with known-good
- Linux/macOS cron, systemd, and launchd entries are verified against administrative baseline
- Browser extensions with persistence capabilities are reviewed
- New user accounts and group changes are correlated with authorized change management
- Persistence cleanup is verified by re-scanning after removal
