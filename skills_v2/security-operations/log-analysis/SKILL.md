---
name: log-analysis
description: >-
  Centralized log analysis methodology for security operations covering log collection, normalization,
  parsing, and analysis across Windows, Linux, network devices, cloud services, and applications.
domain: security-operations
subdomain: log-analysis
tags: [log-analysis, siem, log-management, normalization, splunk, elastic, windows, linux]
mitre_attack: [T1070, T1562]
nist_csf: [DE.AE-1, DE.AE-2, DE.CM-1, DE.CM-3, DE.CM-4, DE.DP-1, DE.DP-2, DE.DP-3, DE.DP-4]
d3fend: [D3-SIEM, D3-LM, D3-CDR, D3-EDR]
nist_ai_rmf: [DETECT-1.1, DETECT-2.2, MONITOR-1.1, MONITOR-2.1, MEASURE-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during log source onboarding to SIEM, when troubleshooting log parsing issues, during log quality assessments, for developing custom log parsers, and when investigating security events using log data.

## Prerequisites

- Log aggregator/SIEM (Splunk, ELK Stack, Graylog, Sentinel)
- Log shippers (Universal Forwarder, Winlogbeat, Filebeat, syslog-ng, rsyslog)
- Python 3.10+ for custom log parsing (re, json, xml libraries)
- Understanding of common log formats (CEF, LEEF, Syslog RFC 3164/5424, JSON)
- Log storage with sufficient capacity and retention
- Access to log source configurations (GPO for Windows, rsyslog for Linux, SNMP for network)

## Workflow

1. Discover log sources: Inventory all systems that generate security-relevant logs (workstations, servers, network, cloud)
2. Verify log generation: Ensure all critical systems produce required logs at appropriate verbosity
3. Configure log shipping: Deploy forwarders/agents to ship logs to central aggregator
4. Normalize log formats: Parse heterogeneous log formats into common schema (timestamp, host, event type, severity)
5. Validate log integrity: Check for gaps in log timeliness, missing fields, and malformed entries
6. Establish baselines: Profile normal log volume per source, log type distribution, and peak times
7. Create dashboards: Build operational dashboards for log source health, volume trends, and error rates
8. Develop analytical queries: Create saved searches for common investigations (auth failures, admin activity, network changes)
9. Automate log retention: Implement tiered storage (hot/warm/cold) with compliance-aligned retention policies
10. Monitor log health: Set alerts for log source downtime, volume anomalies, and parsing failures

## Verification

- All critical systems have log forwarding configured and verified
- Log volume for each source is within expected baseline (+/- 20%)
- Parsing accuracy is >= 99% with clear error handling for unparsed logs
- Log retention meets compliance requirements (PCI DSS: 1 year, SOC 2: 6 months minimum)
- Search performance is acceptable (queries complete within 30 seconds over 30-day window)
- Dashboards and alerts are tested and functional for log health monitoring
