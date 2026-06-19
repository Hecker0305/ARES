---
name: browser-forensics
description: >-
  Forensic analysis of web browser artifacts including history, downloads, cache, cookies, passwords,
  extensions, and session data from Chrome, Firefox, Edge, and Safari for user activity reconstruction.
domain: digital-forensics
subdomain: browser-forensics
tags: [browser-forensics, chrome, firefox, edge, safari, web-history, digital-forensics]
mitre_attack: [T1005, T1012, T1070, T1114, T1204, T1534, T1560]
nist_csf: [DE.AE-2, DE.CM-1, ID.SC-2, RS.AN-1]
d3fend: [D3-BF, D3-DF, D3-CDR]
nist_ai_rmf: [MEASURE-2.2, MAP-1.3]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during digital forensics investigations to determine web-based activity, when investigating phishing attacks (tracking clicked URLs), for insider threat investigations (browsing patterns), and during malware analysis (identifying download sources and C2 web panels).

## Prerequisites

- Forensic image or live system with browser data accessible
- Browser forensic tools: Hindsight (Chrome), Dumpzilla (Firefox), BrowserHistoryViewer
- SQLite browser (DB Browser for SQLite, sqlite3 CLI) for database analysis
- Python 3.10+ with sqlite3, json, and browser-specific parsing libraries
- Understanding of browser database schemas (Chrome: History/WebKit, Firefox: places.sqlite)
- Timeline analysis tool for event correlation

## Workflow

1. Identify browser type and location: Locate browser profile directories per common paths based on OS and browser variant
2. Extract history database: Collect key files: History (Chrome), places.sqlite (Firefox), WebCache (Edge); verify SQLite integrity
3. Parse browsing history: Extract URLs, titles, visit times, visit counts, transition types (typed, link, auto-complete)
4. Analyze downloads: Export download records with filenames, source URLs, target paths, file sizes, timestamps
5. Recover cache artifacts: Extract cached web content, images, scripts for reconstructing viewed pages
6. Examine cookies: Extract cookie databases for session analysis, tracking domains, and third-party interactions
7. Recover deleted entries: Analyze free pages and unallocated space in SQLite databases for deleted history
8. Analyze autofill and passwords: Extract saved credentials, search terms, and form data (may require decryption)
9. Process extension data: Examine browser extensions for data theft, adware, or suspicious behavior logging
10. Correlate with timeline: Map browser activity to system events (MFT timestamps, registry activity)

## Verification

- Browser history database integrity is verified (SQLite integrity check)
- Deleted history records are recovered from unallocated database pages
- Download records match file system MFT entries for downloaded files
- Bookmarks and saved passwords are extracted if not encrypted
- Cross-browser activity is correlated for users with multiple browsers
- All URLs are checked against threat intelligence for malicious categorization
