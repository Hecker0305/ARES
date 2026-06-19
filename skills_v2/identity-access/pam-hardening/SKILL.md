---
name: pam-hardening
description: >-
  Privileged Access Management hardening covering PAM deployment, privileged session recording,
  credential vaulting, just-in-time access, service account management, and privilege escalation controls.
domain: identity-access
subdomain: pam-hardening
tags: [pam, privileged-access, credentials, vaulting, session-management, just-in-time]
mitre_attack: [T1068, T1078, T1098, T1134, T1548, T1550]
nist_csf: [PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-5, PR.AC-6, PR.AC-7, DE.CM-3, DE.CM-7]
d3fend: [D3-PAM, D3-PIM, D3-CV, D3-JIT, D3-SM, D3-IAM]
nist_ai_rmf: [GOVERN-1.1, GOVERN-2.3, MEASURE-1.2, MAP-2.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when deploying or auditing a PAM solution, during privileged access reviews, when implementing just-in-time access for critical systems, for service account credential rotation, and during compliance audits for privileged access controls.

## Prerequisites

- PAM platform (CyberArk, BeyondTrust, Delinea, Azure PIM, Okta PAM)
- Domain admin or equivalent access for PAM deployment
- Understanding of privileged credential workflows
- Service account inventory and dependency mapping
- Session recording storage for compliance evidence
- Python 3.10+ for PAM automation and reporting

## Workflow

1. Inventory privileged accounts: List all local admin, domain admin, root, service accounts, and application accounts
2. Categorize by risk: Classify accounts (local admin, domain admin, emergency, application, service, shared)
3. Onboard to vault: Store credentials in PAM vault with automatic rotation policy
4. Implement JIT access: Replace standing admin privileges with time-bound, approval-based privilege elevation
5. Configure session management: Enable session recording and keystroke logging for all privileged sessions
6. Set up credential rotation: Configure automatic password rotation after each use or scheduled (e.g., daily for admin accounts)
7. Create approval workflows: Define approval chains for privileged access requests based on system criticality
8. Audit privileged usage: Review privileged session recordings, commands executed, and access patterns
9. Manage service accounts: Replace hardcoded credentials with application identities or managed identities (Azure)
10. Monitor PAM health: Track vault status, credential rotation success, pending requests, and session recording storage

## Verification

- 100% of privileged accounts are vaulted with automatic rotation
- Standing admin access is eliminated; all privileged access is JIT with approval
- All privileged sessions are recorded and auditable
- Credential rotation happens automatically after each use (check-in/check-out)
- Service accounts use managed identities or rotating secrets
- Emergency break-glass accounts use multi-person approval with immediate notification
- PAM solution is highly available with failover tested
