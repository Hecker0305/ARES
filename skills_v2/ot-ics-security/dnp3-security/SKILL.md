---
name: dnp3-security
description: >-
  DNP3 protocol security assessment for electrical substations, SCADA, and industrial control systems.
  Covers application layer analysis, object header inspection, fragmentation handling, and secure authentication.
domain: ot-ics-security
subdomain: dnp3-security
tags: [dnp3, ot-security, ics, scada, substation, protocol-security, electric-grid]
mitre_attack: [T0811, T0816, T0822, T0835, T0839, T0883]
nist_csf: [PR.AC-4, PR.AC-5, PR.PT-1, de.cm-1, de.cm-4, de.cm-7]
d3fend: [D3-IDS, D3-PCA, D3-FW, D3-NIDS]
nist_ai_rmf: [GOVERN-1.2, MEASURE-2.1, MAP-1.3]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during OT network assessments in electric utility environments, DNP3 protocol security audits, substation automation system reviews, SCADA security assessments, and when implementing secure DNP3 (SAv5).

## Prerequisites

- Network access to substation LAN or simulated DNP3 environment
- Wireshark with DNP3 dissector for packet analysis
- DNP3 testing tools (dnp3-simulator, libdnp3, opendnp3)
- Python 3.10+ with pydnp3 or custom DNP3 parser
- SAv5 cryptographic keys for secure authentication testing
- Understanding of DNP3 application layer, transport, and data link layers

## Workflow

1. Discover DNP3 devices: Scan for DNP3 on TCP port 20000 using nmap DNP3 NSE scripts
2. Analyze data link layer: Check for source/destination addresses in use, verify addressing scheme
3. Capture unsolicited responses: Monitor for unsolicited responses that indicate alarm conditions
4. Enumerate object variations: Identify all DNP3 point types (binary input, analog input, counter, control, setpoint)
5. Test SCADA authentication: If SAv5 is deployed, verify secure authentication is required for all control operations
6. Check for cleartext commands: Verify direct operate (0x05) and select/operate (0x04) require authentication
7. Analyze fragmentation: Check for abnormal fragment sizes or sequence numbers (potential injection)
8. Monitor time synchronization: Verify DNP3 time sync (0x18) comes from authorized NTP sources only
9. Test for replay attacks: Capture valid control commands and replay to verify SAv5 sequence numbers
10. Implement segmentation: Ensure DNP3 traffic is segregated to substation network only with firewall rules

## Verification

- DNP3 SAv5 secure authentication is enforced for all control operations
- DNP3 traffic is restricted to authorized master-outstation pairs only
- Direct operate commands trigger authentication failures without valid SAv5 session
- Time synchronization is from authorized sources only (no Rogue Time Master)
- Firewall rules block DNP3 from corporate IT networks
- Anomalous DNP3 message patterns (unexpected function codes, malformed headers) trigger IDS alerts
