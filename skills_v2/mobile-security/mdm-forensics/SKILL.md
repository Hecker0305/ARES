---
name: mdm-forensics
description: >-
  Mobile Device Management forensic investigation methodology covering device enrollment logs, policy compliance,
  MDM agent analysis, managed certificate extraction, and corporate data isolation assessment.
domain: mobile-security
subdomain: mdm-forensics
tags: [mdm, mobile-device-management, forensics, device-enrollment, compliance, jamf, intune, workspace-one]
mitre_attack: [T1418, T1525]
nist_csf: [PR.AC-1, PR.DS-1, de.cm-1, de.cm-4]
d3fend: [D3-MDM, D3-DPC, D3-IAM]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during mobile device forensic investigations involving corporate MDM-managed devices, for MDM configuration review and compliance assessment, when investigating data leakage via mobile devices, and during insider threat investigations involving mobile devices.

## Prerequisites

- MDM console access (JAMF Pro, Microsoft Intune, VMware Workspace ONE, MobiControl)
- Mobile device for forensic acquisition (Android or iOS)
- Forensic tools for mobile device analysis (Cellebrite, Oxygen Forensics, Magnet AXIOM)
- Python 3.10+ for MDM log parsing and analysis
- Understanding of MDM profiles, configuration payloads, and managed app configuration
- Device passcode/bypass capabilities for forensic access

## Workflow

1. Preserve MDM state: Capture MDM console information for the target device (enrollment status, compliance, policies, apps, certificates)
2. Extract device enrollment logs: Retrieve enrollment logs from device (iOS MDM enrollment logs, Android Device Policy logs)
3. Review MDM policies: Analyze applied configuration profiles (restrictions, passcode policy, VPN, Wi-Fi, email, certificate payloads)
4. Extract managed certificates: Retrieve certificates pushed by MDM (SCEP, identity certs, Wi-Fi certs, VPN certs)
5. Check compliance history: Review compliance policy status history (pass/fail transitions, reason codes, user-initiated compliance checks)
6. Analyze managed apps: Review corporate app inventory, app configuration settings, and managed app data containers
7. Assess data protection: Verify if corporate data is containerized (iOS Managed Open In, Android Work Profile)
8. Review remote commands: Audit MDM remote commands history (lock, wipe, unenroll, app install/remove) for anomaly
9. Check for configuration drift: Compare current device configuration against last known compliant state
10. Correlate with device forensics: Cross-reference MDM data with device forensic extraction for complete timeline

## Verification

- Device enrollment status is confirmed (MDM agent active, compliance status)
- Configuration profiles are documented with all payload settings
- Managed certificates are extracted and their trust chains verified
- Compliance history shows when device was last fully compliant
- Remote wipe/lock commands have documented authorization and timestamps
- Corporate data containerization is verified with no data leakage to personal container
- MDM console logs confirm no unauthorized configuration changes
- Device forensic extraction is cross-referenced with MDM data for evidence validation
