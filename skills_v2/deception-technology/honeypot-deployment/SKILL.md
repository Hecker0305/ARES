---
name: honeypot-deployment
description: >-
  Honeypot deployment strategy covering low-interaction and high-interaction honeypot configuration,
  decoy network design, traffic capture, alerting, and threat intelligence generation from attacker interactions.
domain: deception-technology
subdomain: honeypot-deployment
tags: [honeypot, deception, decoy, threat-intelligence, attacker-behavior, trapping]
mitre_attack: [T1043, T1046, T1082, T1090, T1105, T1133, T1190]
nist_csf: [DE.CM-1, DE.CM-4, DE.CM-7, DE.DP-1, RS.AN-1]
d3fend: [D3-HN, D3-DEC, D3-HP, D3-CDR]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, MEASURE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when deploying honeypots for threat detection and attacker intelligence, for early warning system implementation in high-value networks, during threat hunting operations to detect lateral movement, and for gathering threat intelligence on attacker tools and techniques.

## Prerequisites

- Honeypot platform (T-Pot, Cowrie, Dionaea, Honeyd, Modern Honey Network)
- Isolated network segment or VLAN for honeypot deployment
- Traffic capture and analysis tools (Suricata, Zeek, Wireshark)
- SIEM integration for honeypot alert correlation
- Threat intelligence platform for IOC ingestion
- Python 3.10+ for custom honeypot services and log analysis
- Rules of Engagement clearly defining honeypot boundaries and data capture limits

## Workflow

1. Design honeypot architecture: Define deployment strategy (internal vs external, low vs high interaction, which services to emulate)
2. Deploy low-interaction honeypots: Set up Cowrie (SSH/Telnet), Dionaea (SMB, HTTP, FTP, MSSQL), and Honeyd (service emulation)
3. Deploy high-interaction honeypots: Deploy T-Pot with full interaction honeypots (Conpot for ICS, ElasticPot, Glutton) in isolated environment
4. Configure logging and capture: Enable full packet capture, keystroke logging, and file download capture on honeypots
5. Deploy decoy assets: Place decoy credentials, configuration files, and data files on honeypots as bait
6. Integrate with SIEM: Forward honeypot alerts to SIEM with specific rules for honeypot-triggered incidents
7. Monitor attacker behavior: Analyze attacker commands, tools uploaded, and techniques observed across honeypots
8. Generate threat intelligence: Extract IOCs from attacker interactions (IPs, hashes, domains, C2 addresses)
9. Create detection rules: Develop EDR/network rules based on attacker behavior observed in honeypots
10. Report and tune: Document attacker TTPs, adjust honeypot configuration, and improve bait effectiveness

## Verification

- Honeypots are reachable from target network segments and showing expected service banners
- Legitimate users/tools are whitelisted to avoid false positives
- All attacker interactions are logged with full command/tool capture
- Honeypot does not serve as a pivot point into real infrastructure (proper isolation verified)
- Alerting is functional and triggers on any honeypot interaction
- Threat intelligence feeds from honeypot interactions are enriching TI platform
- Honeypot activity is reviewed at least daily for emerging threats
- Decoy credentials/files are periodically checked for exfiltration attempts
