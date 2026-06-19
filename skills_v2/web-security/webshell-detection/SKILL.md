---
name: webshell-detection
description: >-
  Webshell detection methodology covering signature-based matching, Shannon entropy analysis,
  behavioral indicators, network-side detection, and known hash verification for web shells.
domain: web-security
subdomain: webshell-detection
tags: [webshell, malware, post-exploitation, file-upload, persistence]
mitre_attack: [T1505.003, T1190, T1505]
nist_csf: [PR.AC-4, PR.DS-2, DE.CM-4, RS.MI-3]
d3fend: [D3-FCD, D3-ALTH, D3-HRD]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during post-exploitation phases after file upload vulnerabilities are confirmed, during incident response web root scanning, when periodic web integrity checks are required, and for forensic analysis of compromised web servers.

## Prerequisites

- Access to web root directories (e.g., `/var/www/html`, `C:\inetpub\wwwroot`)
- Upload directory listing (e.g., `/uploads/`, `/files/`, `/images/`)
- Python 3.10+ for entropy analysis and hash verification scripts
- Known webshell hash database (SHA-256) for b374k, c99, r57, WSO, China Chopper, Weevely
- Network monitor or proxy logs for POST-to-static-file heuristics

## Workflow

1. Identify web roots and upload directories: Locate all web-accessible and upload directories on the target
2. Signature matching: Scan files for known webshell patterns (45+ PHP/ASP/JSP/Python/Perl signatures) including eval(base64_decode), system($_GET), shell_exec, and obfuscated variants
3. Entropy analysis: Calculate Shannon entropy for each file; flag files exceeding configurable threshold (default 5.0 bits) as high-entropy indicators
4. Behavioral detection: Check for double extensions (e.g., image.php.jpg), executable permissions on script files, recent modification timestamps, and file location in upload directories
5. Hash verification: Compute SHA-256 hash of each file and compare against known webshell hash database (b374k, c99, r57, WSO, China Chopper, Weevely, one-liners)
6. Network-side detection: Analyze HTTP traffic patterns — POST requests to static-file extensions (.jpg, .png, .css), MIME type mismatches, OS command output in responses
7. Consolidate findings: Combine all detection methods into a unified result with detection method tags, severity ratings, and confidence scores
8. Report findings: Include file path, matched signatures, entropy score, hash match, behavioral indicators, and network detection evidence

## Detection Methods

- Signature matching: 45 regex patterns across 5 languages (PHP, ASP, JSP, Python, Perl, generic)
- Shannon entropy: Configurable threshold, per-byte frequency analysis
- Behavioral: Double extension, executable perms, recent modification, upload dir location
- Network: POST-to-static heuristic, MIME mismatch, OS command patterns
- Hash DB: SHA-256 lookup against 20+ known webshell variants

## Verification

- At least one signature match or hash match is required for confirmed webshell
- High-entropy file alone with no other indicators is suspicious (requires manual review)
- Network-side detection is corroborating evidence only (not standalone confirmation)
- All findings include detection method and confidence score for triage

## Tools Included

- Go internal/webshell package — integrated ARES engine detection
- Shannon entropy calculator (configurable threshold)
- SHA-256 hash compute and lookup
- Upload directory scanner with recursive traversal
- Network log analyzer for POST-to-static heuristic
