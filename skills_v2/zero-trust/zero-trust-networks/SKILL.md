---
name: zero-trust-networks
description: >-
  Zero Trust Network Access implementation covering ZTNA architecture, software-defined perimeter,
  encrypted tunnels, identity-aware routing, and network-level trust evaluation.
domain: zero-trust
subdomain: zero-trust-networks
tags: [ztna, zero-trust, sdp, software-defined-perimeter, network-access, identity-aware]
mitre_attack: [T1048, T1090, T1557]
nist_csf: [PR.AC-4, PR.AC-5, PR.PT-3, de.cm-1, de.cm-4]
d3fend: [D3-ZTA, D3-SDP, D3-MICRO, D3-FW]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when replacing VPN with ZTNA solutions, during software-defined perimeter deployment, for identity-aware network access implementation, and when migrating to zero trust network architecture.

## Prerequisites

- ZTNA platform (Cloudflare Access, Zscaler ZPA, Tailscale, Twingate, Perimeter 81)
- Identity provider for user authentication (Google Workspace, Azure AD, Okta)
- Device management system for device posture checking
- Network infrastructure understanding (DNS, routing, firewalls, proxies)
- Application inventory and access requirements documentation
- Python 3.10+ for ZTNA configuration automation

## Workflow

1. Assess current network access: Document all current remote access methods (VPN, RDP gateways, jump boxes), user access patterns, and application access requirements
2. Define ZTNA architecture: Design identity-aware access model based on zero trust principles - no implicit trust based on network location
3. Deploy ZTNA connector: Install ZTNA connector/agent on each application server or use cloud connector for SaaS applications
4. Configure identity provider integration: Connect ZTNA to SSO provider for user authentication with MFA
5. Set up device posture checks: Integrate with MDM/UEM for device compliance verification during access requests
6. Define access policies: Create application-specific access rules based on user identity, group membership, device compliance, location, and time
7. Deploy ZTNA client: Deploy ZTNA client software to user devices for encrypted tunnel creation
8. Migrate applications: Move applications from VPN-based access to ZTNA one by one, starting with less critical apps
9. Decommission VPN: After all applications migrated, remove VPN infrastructure
10. Monitor and refine: Analyze access logs for unusual patterns, adjust policies, and expand coverage

## Verification

- Users can access applications without VPN (direct ZTNA connectivity)
- Access is denied when user is not authenticated, device is non-compliant, or MFA is not completed
- Application servers are not visible to the internet (no open ports, no public IP)
- ZTNA provides encrypted tunnel between user and application (no split tunneling concerns)
- Access policies follow least privilege (user/app-specific, not network segment-wide)
- VPN decommission is complete with no remaining VPN access
- Access logs show all connection attempts (allowed and denied) for audit
- Latency impact is measured (ZTNA overhead < 10ms)
