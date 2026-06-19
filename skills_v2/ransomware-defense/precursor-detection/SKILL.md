---
name: precursor-detection
description: >-
  Ransomware precursor detection methodology identifying pre-encryption activities including C2 beaconing,
  credential harvesting, privilege escalation, lateral movement, and data staging before ransomware deployment.
domain: ransomware-defense
subdomain: precursor-detection
tags: [ransomware, precursor-detection, pre-encryption, c2-beaconing, credential-theft, lateral-movement]
mitre_attack: [T1486, T1490, T1003, T1059, T1078, T1110, T1133, T1190, T1204, T1485, T1505, T1569]
nist_csf: [DE.AE-2, DE.CM-1, DE.CM-4, DE.CM-7, PR.DS-1, RS.AN-1, RS.MI-1]
d3fend: [D3-EDR, D3-NDR, D3-BA, D3-UEBA, D3-SIEM]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, MEASURE-2.1, RESPOND-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill for proactive ransomware detection before encryption occurs, during hunting for ransomware infection chains, when deploying detection rules for ransomware precursors, and for monitoring critical infrastructure against ransomware attacks.

## Prerequisites

- EDR platform with behavioral detection and rollback capability
- SIEM with correlation rules for multi-stage attack detection
- Network detection (NDR) for C2 beaconing and lateral movement detection
- UEBA for anomalous user behavior detection
- Threat intelligence for ransomware group TTPs (LockBit, BlackCat, CLOP, BlackBasta)
- Python 3.10+ for custom detection rule development

## Workflow

1. Analyze ransomware TTPs: Research current ransomware group behaviors (C2 frameworks, initial access, privilege escalation, lateral movement tools)
2. Detect initial access: Monitor for RDP brute force, VPN vulnerability exploitation, phishing with QakBot/Emotet precursors
3. Hunt for C2 beaconing: Detect periodic beaconing to ransomware C2 infrastructure using network traffic analysis
4. Monitor credential theft: Alert on LSASS access, SAM registry access, ntds.dit access, and DCSync patterns
5. Detect lateral movement: Monitor for PsExec, WMI, SMB/WMI, RDP, and remote service creation for ransomware deployment
6. Identify data staging: Detect large file reads, compression, and archive creation before exfiltration or encryption
7. Watch for defense evasion: Alert on security tool termination (EDR, AV), service shutdown, log clearing, shadow copy deletion
8. Deploy decoy triggers: Place honey tokens, decoy databases, and fake file shares to detect ransomware staging activity
9. Automate response thresholds: Define alert thresholds for precursor detection (trigger incident response before encryption)
10. Create ransomware playbook: Develop incident response playbook specific to ransomware precursor detection

## Verification

- C2 beaconing detection identifies ransomware command and control before encryption
- Credential access detection (LSASS, SAM) alerts before privilege escalation
- Lateral movement detection blocks ransomware spread between systems
- Shadow copy deletion is blocked/alarmed before encryption
- Security tool termination triggers immediate incident response escalation
- Ransomware deployment is detected at a precursor stage (not after encryption)
- Mean time to detect ransomware precursors is under 30 minutes
- Decoy/honey tokens trigger immediate alerts on access
