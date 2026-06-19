---
name: beyondcorp-implementation
description: >-
  Google BeyondCorp zero trust implementation methodology covering device inventory, user authentication,
  access proxy deployment, context-aware access policies, and continuous verification architecture.
domain: zero-trust
subdomain: beyondcorp-implementation
tags: [zero-trust, beyondcorp, iam, access-proxy, context-aware, device-trust, identity-aware-proxy]
mitre_attack: [T1078, T1098, T1133, T1550]
nist_csf: [PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-6, PR.AC-7, de.cm-1, de.cm-3, de.cm-7]
d3fend: [D3-ZTA, D3-IAM, D3-CA, D3-IAP, D3-DPC]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2, DETECT-2.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when implementing zero trust access architecture, during migration from VPN-based to identity-aware proxy access, for BeyondCorp Enterprise or IAP deployment, and when establishing context-aware access policies.

## Prerequisites

- Identity provider (Google Workspace, Azure AD, Okta) for user authentication
- Device management (JAMF, Intune, Fleet) for device inventory and compliance
- Identity-Aware Proxy or access proxy (Google IAP, Cloudflare Access, Pomerium, Tailscale)
- Certificate authority for short-lived device certificates
- SIEM/BigQuery for access log analysis
- Zero trust architecture understanding (BeyondCorp whitepapers, NIST SP 800-207)

## Workflow

1. Inventory resources: Catalog all internal applications and services, classify by criticality and access requirements
2. Register devices: Enroll all managed devices in device management system with compliance policies (OS version, encryption, patch level)
3. Deploy device certificate authority: Issue short-lived TLS client certificates verifying device identity and compliance
4. Configure identity provider: Set up Google Workspace or Azure AD as identity source with SSO and MFA enforcement
5. Deploy identity-aware proxy: Place IAP in front of all internal applications (not publicly accessible directly)
6. Define access policies: Create context-aware access rules based on: user identity, group membership, device compliance, device OS, location, and access time
7. Implement just-in-time access: Grant temporary access tokens with short TTL, require continuous re-authorization for sessions
8. Remove VPN dependency: Migrate applications from VPN-based access to direct IAP-based access with TLS
9. Enable access logging: Log all access attempts (allowed/denied) with user, device, resource, and context attributes
10. Monitor and audit: Continuously verify access patterns, review denied access attempts, and refine policies

## Verification

- All internal applications are accessed through IAP (no direct network access)
- VPN is decommissioned or only used for legacy non-HTTP applications
- Access policies consider device compliance (OS version, encryption, patch level, managed status)
- User identity + device trust + context are evaluated before access is granted
- Session tokens are short-lived (under 1 hour) and require continuous refresh
- Denied access attempts are logged and reviewed for unauthorized access patterns
- Zero standing privileges: all access is granted based on real-time need
- Onboarding a new device shows proper certificate enrollment and policy application
