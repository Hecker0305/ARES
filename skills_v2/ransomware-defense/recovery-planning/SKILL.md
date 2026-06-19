---
name: recovery-planning
description: >-
  Ransomware recovery planning covering backup restoration procedures, system rebuild priorities,
  data validation, business continuity operations, and post-recovery verification methodology.
domain: ransomware-defense
subdomain: recovery-planning
tags: [ransomware, recovery, backup-restoration, business-continuity, disaster-recovery]
mitre_attack: [T1486, T1490]
nist_csf: [PR.IP-4, PR.IP-5, ID.SC-1, RS.AN-1, RS.MI-1, RS.MI-2, RS.RP-1]
d3fend: [D3-BU, D3-REC, D3-ISL]
nist_ai_rmf: [GOVERN-1.1, RESPOND-1.2, MANAGE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during ransomware recovery operations, for backup restoration planning and execution, when prioritizing system recovery after encryption, and during business continuity activation following ransomware incidents.

## Prerequisites

- Backup system with immutable/offline copies (pre-dating infection)
- Disaster recovery plan documentation for all critical systems
- System baseline configurations and build documentation
- Server/application restore runbooks
- Communication templates for stakeholder updates
- Hardware/spare capacity for restore operations
- Cyber insurance claim documentation requirements

## Workflow

1. Assess backup health: Verify backup integrity, restore test files from backup to confirm clean data, identify last clean backup timestamp
2. Prioritize system recovery: Classify systems by criticality (Tier 1: revenue, customer-facing; Tier 2: internal ops; Tier 3: non-critical)
3. Clean restore environment: Deploy clean infrastructure (fresh OS, updated patches, hardened config) - NEVER restore to compromised system
4. Restore Tier 1 systems: Rebuild servers from known-good source, restore data from clean backup, validate application functionality
5. Secure restored environment: Apply security patches, update antivirus/EDR, change all passwords, rotate certificates/keys
6. Restore data integrity verification: Validate restored data (row counts, file counts, checksums, application-level validation)
7. Test restored applications: Run functionality tests, performance validation, and security scans on restored systems
8. Implement additional security: Deploy enhanced monitoring, additional network segmentation, and preventive controls based on root cause
9. Restore Tier 2 and 3 systems: Continue restoration of remaining systems using validated procedure from Tier 1
10. Document and validate: Maintain restore log with timestamps, create post-recovery test report, validate with business owners

## Verification

- All critical systems are restored and operational within SLA (Tier 1: 24 hours, Tier 2: 72 hours, Tier 3: 7 days)
- Restored data integrity is validated (checksums match, database records consistent, file counts correct)
- No malware remnants are detected on restored systems (100% clean scan)
- All passwords, API keys, and certificates are rotated post-recovery
- Root cause of ransomware infection is addressed before production return
- Backup system integrity is verified (clean backup available for future recovery)
- Recovery objective (RTO/RPO) metrics are met
- Post-recovery monitoring shows no re-infection for 72 hours
