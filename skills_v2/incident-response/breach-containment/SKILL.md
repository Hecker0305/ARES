---
name: breach-containment
description: >-
  Rapid breach containment methodology covering network isolation, endpoint quarantine, credential revocation,
  firewall blocking, and evidence preservation while minimizing business disruption during active incidents.
domain: incident-response
subdomain: breach-containment
tags: [breach-containment, incident-response, isolation, quarantine, credential-revocation, ir]
mitre_attack: [T1078, T1110, T1190, T1204, T1485, T1490, T1531]
nist_csf: [RS.AN-1, RS.AN-5, RS.CO-1, RS.CO-2, RS.MI-1, RS.MI-2, RS.MI-3, RS.RP-1]
d3fend: [D3-ISL, D3-EDR, D3-FW, D3-ORC, D3-CRED]
nist_ai_rmf: [RESPOND-1.1, RESPOND-2.2, GOVERN-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during active security incidents requiring immediate containment actions, when unauthorized access is detected, during ransomware outbreaks requiring propagation prevention, and when compromised credentials require emergency revocation.

## Prerequisites

- EDR platform access (CrowdStrike, Defender, SentinelOne) for endpoint isolation
- Firewall management console for IP/domain blocking
- Identity provider (Azure AD, Okta) for credential revocation
- SOAR platform for orchestrated containment actions
- Incident response runbook for the specific scenario
- Communication channels (Slack, Teams, PagerDuty) for coordination
- Legal/compliance team contact for containment authorization

## Workflow

1. Assess incident scope: Determine affected systems, users, data, and attacker access level based on initial findings
2. Isolate critical systems: Disconnect compromised endpoints from network using EDR isolation feature
3. Revoke compromised credentials: Immediately invalidate any affected passwords, sessions, tokens, and API keys
4. Block C2 infrastructure: Add attacker IPs, domains, and URLs to firewall/proxy/DNS blocklists
5. Disable compromised accounts: If user account is compromised, disable it in identity provider and reset sessions
6. Secure perimeter: Adjust firewall rules to block known attacker infrastructure and communication channels
7. Preserve evidence: Create forensic images of compromised systems before cleanup (snapshot, memory dump)
8. Maintain business continuity: Implement manual/alternate processes for affected critical services
9. Document containment actions: Record all containment steps with timestamps, decisions, and authorization
10. Monitor for re-infection: After containment, monitor for persistence mechanisms or secondary access channels

## Verification

- All confirmed compromised endpoints are isolated (network disconnected, EDR quarantine active)
- Compromised credentials are revoked and sessions terminated
- Attacker infrastructure is blocked at multiple network layers
- Evidence is preserved with chain of custody before any cleanup
- Business-critical processes continue with manual fallback procedures
- Monitoring detects any reconnection attempts from attacker infrastructure
- Containment actions are documented with timestamps and authorization records
