---
name: ssrf-testing
description: >-
  Server-Side Request Forgery testing methodology covering URL validation bypass, cloud metadata access,
  internal network scanning, and protocol smuggling for SSRF exploitation.
domain: web-security
subdomain: ssrf-testing
tags: [ssrf, server-side-request-forgery, web-security, cloud-metadata, internal-network]
mitre_attack: [T1190, T1499, T1595]
nist_csf: [PR.AC-4, PR.DS-2, DE.CM-4, RS.MI-3]
d3fend: [D3-WAF, D3-FW, D3-ALR]
nist_ai_rmf: [DETECT-1.2, MEASURE-2.3]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during web application testing where the application fetches external resources (URLs, files, images), during cloud security assessments, when testing integration with third-party APIs, and for internal network reconnaissance via SSRF.

## Prerequisites

- Burp Suite with Collaborator client for out-of-band detection
- Python 3.10+ with Flask for local HTTP callback server
- Cloud metadata endpoints knowledge (AWS: 169.254.169.254, Azure: 169.254.169.254, GCP: metadata.google.internal)
- HTTP request bin service (webhook.site, Burp Collaborator, interactsh)
- Redirect service (urldecoder.io, custom domain with 302 redirect)
- gopher, dict, file protocol support knowledge

## Workflow

1. Identify SSRF entry points: Find all features that fetch external resources (file downloads, webhooks, avatar URLs, API integrations, document rendering)
2. Test basic URL fetching: Submit your callback URL (webhook.site) and verify the server hits your endpoint
3. Bypass blocklists: Try DNS rebinding, URL encoding, octal IP, IPv6 mapped IPv4, redirect bypass, and alternative localhost representations
4. Access cloud metadata: Test cloud provider metadata endpoints to retrieve IAM credentials, instance identity documents, and user data
5. Scan internal network: Probe RFC 1918 addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) on common ports
6. Exploit protocol smuggling: Use gopher://, dict://, file://, ftp:// protocols to interact with internal services
7. Blind SSRF detection: Use callback services to confirm outbound requests even when response is not visible
8. Access internal services: Target Redis, Memcached, Elasticsearch, database ports, and container orchestration APIs
9. Document SSRF impact: Demonstrate credential access, internal service interaction, or data exfiltration
10. Report findings: Include entry point, bypass technique, internal hosts discovered, and data accessed

## Verification

- SSRF is confirmed by callback to controlled endpoint from target server
- Cloud metadata access is confirmed by retrieving instance metadata document
- At least one internal host responds to SSRF probe on non-HTTP port
- Protocol smuggling demonstrates access to internal service
- All bypass techniques attempted on the identified entry points
- Impact assessment includes data accessed and internal systems reached
