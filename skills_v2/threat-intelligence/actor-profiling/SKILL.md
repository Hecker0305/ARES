---
name: actor-profiling
description: >-
  Structured threat actor profiling methodology using the Diamond Model, MITRE ATT&CK, and intelligence requirements.
  Analyzes adversary capabilities, infrastructure, targeting patterns, and operational security.
domain: threat-intelligence
subdomain: actor-profiling
tags: [threat-intelligence, actor-profiling, threat-actor, targeting, ttp, attribution, diamond-model]
mitre_attack: [T1587, T1588, T1592, T1593, T1595, T1596]
nist_csf: [ID.RA-1, ID.RA-2, ID.RA-3, ID.RA-4, ID.SC-2, DE.AE-2, DE.AE-3]
d3fend: [D3-TIP, D3-CTI, D3-SIEM]
nist_ai_rmf: [GOVERN-1.1, GOVERN-2.3, MAP-1.1, MAP-2.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during targeted threat intelligence analysis, after incident response to attribute attacker activity, when producing threat actor reports for executive stakeholders, during competitive intelligence analysis, and for building adversary playbooks for purple team exercises.

## Prerequisites

- Access to threat intelligence platform (MISP, ThreatConnect, Anomali)
- MITRE ATT&CK framework knowledge and Navigator access
- OSINT tools for infrastructure analysis (Shodan, Censys, VirusTotal, PassiveTotal)
- Python 3.10+ with pandas, networkx for analysis
- Diamond Model and Cyber Kill Chain familiarity
- Intel requirements to guide analytical scope

## Workflow

1. Identify the threat actor: Collect all available data points (IOCs, TTPs, malware, infrastructure, targeting) from internal and external sources
2. Apply Diamond Model: Map the event across Adversary, Capability, Infrastructure, and Victim vertices
3. Profile adversary capabilities: List malware families, exploits, C2 frameworks, and tooling used by the actor
4. Map infrastructure: Identify IP addresses, domains, hosting providers, TLS certs, and CDN providers with first-seen/last-seen dates
5. Analyze targeting: Identify victim sectors, geographies, technology stacks, and access vectors
6. Determine TTPs: Map observed behaviors to MITRE ATT&CK techniques with frequency and confidence scores
7. Identify attribution clues: Analyze code similarities, infrastructure overlaps, TTP patterns, language artifacts, and operational timing
8. Produce adversary profile: Create structured profile with capabilities, limitations, motivation, and confidence level
9. Build detection playbook: Create TTP-based detection rules and hunting queries for SIEM/EDR
10. Share intelligence: Package profile for sharing (TLP-AMBER) with trusted communities

## Verification

- All Diamond Model vertices are populated with at least one data point
- MITRE ATT&CK mapping covers all observed TTPs with supporting evidence
- Infrastructure pivot analysis shows at least one connection not previously known
- Threat actor report is peer-reviewed for analytic rigor and confidence scoring
- Detection playbook covers the top 5 most impactful TTPs with SIEM rules
- Attribution confidence level is documented with supporting evidence chain
- Profile is published to MISP or TIP for community sharing
