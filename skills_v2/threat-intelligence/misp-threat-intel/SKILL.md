---
name: misp-threat-intel
description: >-
  Malware Information Sharing Platform (MISP) threat intelligence operations including event creation,
  attribute management, correlation analysis, feed sharing, and integration with detection infrastructure.
domain: threat-intelligence
subdomain: misp-threat-intel
tags: [misp, threat-intelligence, sharing, correlation, ioc, malware, feed]
mitre_attack: [T1587, T1588, T1593]
nist_csf: [DE.AE-2, DE.AE-3, DE.CM-4, ID.RA-2, ID.RA-3, RS.AN-1]
d3fend: [D3-TIP, D3-IOC, D3-CTI]
nist_ai_rmf: [GOVERN-2.2, MAP-1.3, MANAGE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when operating a MISP instance for threat intelligence sharing, during incident response to publish indicators of compromise, when subscribing to external MISP communities, for integrating MISP with SIEM/SOAR platforms, and during threat intelligence lifecycle management.

## Prerequisites

- MISP instance URL and API key (user with appropriate permissions)
- Python 3.10+ with pymisp library installed
- Access to MISP sync users for community/external feed connections
- SIEM or SOAR platform for automated indicator consumption
- RabbitMQ or ZeroMQ for real-time event publishing
- TLS certificate for MISP HTTPS access

## Workflow

1. Authenticate to MISP API: Validate API key and retrieve user role, org info, and server capabilities
2. Search for existing events: Query by date range, tags, org, or threat level to understand current data
3. Create new event: Define event info, threat level (1-4), analysis stage (0-2), and distribution scope
4. Add attributes: Add IOCs as attributes (IP, domain, hash, URL, email, YARA, pattern-in-file) with category and type
5. Enrich with context: Tag attributes with TLP:AMBER/GREEN/RED, kill chain phase, confidence, and source reliability
6. Run correlation: Execute MISP correlation engine to link attributes across events and orgs
7. Create object templates: Use standard templates (file, email, URL, domain-ip) for structured data
8. Publish event: Set event to publish state to trigger feed distribution and ZMQ notification
9. Push to external feeds: Configure feed outputs to push to TAXII servers, CSV feeds, and REST endpoints
10. Integrate with detection: Set up MISP module to push to SIEM, firewall blocklists, and DNS sinkhole

## Verification

- MISP event contains all required attributes with correct category/type mapping
- TLP classification is applied correctly to all events and attributes
- Correlation graph shows cross-referenced attributes and linked events
- Event distribution follows org policy (inherit, org, connected, community, all)
- Feed publishing delivers events within 5 minutes of publication
- SIEM integration shows new indicators within the polling interval
- MISP warning lists are updated for validation against known legitimate services
