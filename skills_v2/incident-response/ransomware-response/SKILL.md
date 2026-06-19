---
name: ransomware-response
description: >-
  Ransomware incident response methodology covering containment, propagation prevention, root cause analysis,
  recovery planning, decryption options, and communication strategy during ransomware attacks.
domain: incident-response
subdomain: ransomware-response
tags: [ransomware, incident-response, recovery, decryption, encryption, containment]
mitre_attack: [T1486, T1490, T1485, T1078, T1110, T1204]
nist_csf: [DE.AE-2, DE.CM-1, DE.CM-4, PR.DS-1, PR.IP-4, RS.AN-1, RS.MI-1, RS.MI-2, RS.MI-3, RS.RP-1]
d3fend: [D3-ISL, D3-EDR, D3-REC, D3-BU]
nist_ai_rmf: [RESPOND-1.1, RESPOND-2.2, GOVERN-2.1, MEASURE-3.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during active ransomware incidents, when encryption alarms are triggered, during ransomware recovery operations, for ransom negotiation decision support, and when restoring from backup after ransomware.

## Prerequisites

- EDR platform with ransomware detection capabilities
- Backup system with immutable/offline backups (pre-infected)
- Network isolation capability (firewall, NAC, EDR isolation)
- Ransom note analysis tools (ransomware identification, decryptor lookup)
- Ransomware decryptor databases (No More Ransom, Avast, Kaspersky)
- Legal counsel for ransom payment considerations
- Cyber insurance policy and claims contact

## Workflow

1. Immediate containment: Isolate all affected systems using EDR quarantine (do NOT power off - memory evidence)
2. Identify ransomware variant: Analyze ransom note, encrypted file extension, and dropped README file for variant identification
3. Check for decryptors: Search No More Ransom and vendor databases for free decryptor availability
4. Assess propagation method: Determine initial access vector (RDP, phishing, VPN, software vulnerability)
5. Contain lateral movement: Block ransomware propagation channels (SMB, RDP, PowerShell, PsExec) at firewall
6. Identify backup status: Verify backup integrity and determine if backup data is encrypted or clean
7. Recover from clean backup: If backup is clean, begin recovery process after attacker access is sealed
8. For recovery: Wipe and rebuild affected systems from known-good images, NOT from encrypted systems
9. Preserve evidence: Keep encrypted systems offline for forensic analysis (do not decrypted affected machines)
10. Post-incident: Determine root cause, improve detection/prevention, update backup procedures, and document lessons learned

## Verification

- Ransomware spread is fully contained (no new encryptions in last 2 hours)
- Ransomware variant is identified with known TTPs and decryption options
- Backups are verified as clean and available for recovery
- Initial access vector is identified and access is blocked
- Recovery plan is approved by management with timeline and rollback plan
- All evidence is preserved for law enforcement and insurance claims
- No ransom payment is made without legal and insurance consultation
