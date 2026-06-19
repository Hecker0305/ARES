---
name: ids-ips-analysis
description: >-
  Intrusion detection and prevention system analysis methodology covering signature tuning, false positive reduction,
  rule creation for Snort/Suricata, alert correlation, and network threat hunting.
domain: network-security
subdomain: ids-ips-analysis
tags: [ids, ips, snort, suricata, network-security, intrusion-detection, signatures]
mitre_attack: [T1043, T1048, T1071, T1095, T1102, T1105, T1205, T1219, T1571, T1572]
nist_csf: [DE.CM-1, DE.CM-3, DE.CM-4, DE.CM-5, DE.CM-7, DE.AE-1, DE.AE-2, DE.DP-1]
d3fend: [D3-IDS, D3-IPS, D3-NDR, D3-SIEM, D3-HN]
nist_ai_rmf: [DETECT-1.2, DETECT-2.1, MEASURE-1.1, MONITOR-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during IDS/IPS deployment tuning, after new threat intelligence is received, during network security assessments, for rule performance optimization, and when investigating alerts with high false positive rates.

## Prerequisites

- Access to IDS/IPS management console (Snort, Suricata, Zeek)
- PCAP file access for rule testing and validation
- Python 3.10+ with scapy for packet analysis
- Rule management tools (PulledPork, Oinkmaster)
- Elasticsearch/Splunk for alert analysis and trending
- Network topology documentation

## Workflow

1. Baseline network traffic: Profile normal traffic patterns (protocols, ports, bandwidth, timing) over 7-30 days
2. Review alert volume: Categorize alerts by severity, signature ID, source/destination IP, and protocol
3. Identify false positive patterns: Correlate alerts with known good traffic patterns and whitelist sources
4. Tune existing rules: Modify thresholds, whitelist IPs, adjust content matches to reduce false positives
5. Create custom rules: Write Snort/Suricata rules for emerging threats from threat intelligence
6. Test rules offline: Validate new rules against PCAPs before production deployment
7. Deploy rules in test mode: Enable rules in alert-only mode for 7 days before blocking
8. Create correlation rules: Link IDS alerts with other log sources (firewall, DNS, proxy) in SIEM
9. Monitor performance: Track CPU/memory usage, packet loss, and alerts per second across sensors
10. Document and iterate: Maintain rule documentation with sources, false positive rates, and tuning history

## Verification

- Alert volume is reduced by >= 50% after initial tuning
- False positive rate per rule is <= 5% after tuning
- Custom rules detect emerging threats without increasing FP rate
- CPU usage on sensors remains below 60% during peak traffic
- All critical severity alerts have correlation rules in SIEM
- Rule changes are documented with change control and rollback plan
