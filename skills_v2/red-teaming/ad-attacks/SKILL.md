---
name: ad-attacks
description: >-
  Active Directory attack simulation covering Kerberoasting, AS-REP roasting, DCSync, ACL abuse,
  delegation attacks, SMB relay, and domain dominance techniques for red team operations.
domain: red-teaming
subdomain: ad-attacks
tags: [active-directory, kerberos, kerberoasting, dcsync, domain-dominance, red-team]
mitre_attack: [T1003, T1047, T1059, T1068, T1069, T1078, T1087, T1098, T1134, T1185, T1207, T1484, T1485, T1550, T1552, T1556, T1558, T1559, T1569, T1574]
nist_csf: [DE.AE-2, DE.CM-1, DE.CM-3, DE.CM-4, PR.AC-1, PR.AC-3, PR.AC-4]
d3fend: [D3-EDR, D3-SIEM, D3-AUDIT, D3-IAM]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, MEASURE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during red team operations targeting Active Directory, during AD security assessments, for testing AD detection capabilities, and when performing adversary emulation for AD-focused threat groups.

## Prerequisites

- Kali Linux or C2 framework with AD attack tools (Impacket, BloodHound, CrackMapExec, Mimikatz)
- Domain user credentials (low-privileged) or foothold on domain-joined system
- Network access to domain controllers
- BloodHound for AD relationship mapping and privilege escalation path analysis
- Python 3.10+ with Impacket library
- Understanding of Kerberos, NTLM, LDAP protocols

## Workflow

1. Enumerate AD environment: Run BloodHound collector to map users, groups, computers, GPOs, ACLs, trusts, and sessions
2. Analyze attack paths: Use BloodHound to identify shortest paths to domain admin, analyzing ACL abuse, group membership, and constrained delegation
3. Perform initial credential access: Attempt Kerberoasting (extract service account hashes), AS-REP roasting (find Kerberos pre-auth disabled accounts)
4. Escalate privileges: Abuse ACLs (ForceChangePassword, GenericAll, WriteOwner, WriteDACL), exploit constrained/unconstrained delegation
5. Perform lateral movement: Use PSRemoting, WMI, SMB, and DCOM to move laterally with harvested credentials
6. Achieve domain dominance: Execute DCSync attack to extract all domain password hashes from domain controller
7. Abuse trusts: Exploit intra-domain and inter-domain trusts for cross-forest movement using SIDHistory and Kerberos referral tickets
8. Install persistence: Create Golden Ticket, Silver Ticket, Skeleton Key, or DSRM admin backdoor
9. Execute final objective: Achieve goal (data exfiltration, system manipulation, or domain compromise documentation)
10. Cleanup: Remove tools, restore modified ACLs, delete created accounts, and revert group memberships

## Verification

- BloodHound shows domain admin access achieved within operational constraints
- Kerberoasting successfully extracts at least one service account hash
- DCSync extracts valid domain password hashes
- All attack steps are logged with timestamps for purple team review
- Detection coverage is documented (which steps triggered alerts vs. flew under the radar)
- Cleanup operations are verified (no artifacts remain in the target environment)
