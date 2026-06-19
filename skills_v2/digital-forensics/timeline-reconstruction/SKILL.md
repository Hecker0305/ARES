---
name: timeline-reconstruction
description: >-
  Forensic timeline reconstruction using Plaso (log2timeline), MFT, registry, event logs, USN journal,
  prefetch, shellbags, and browser history correlated into a unified chronological event sequence.
domain: digital-forensics
subdomain: timeline-reconstruction
tags: [timeline, forensics, plase, mft, registry, event-logs, prefetch, shellbags]
mitre_attack: [T1003, T1012, T1027, T1070, T1485]
nist_csf: [DE.AE-2, DE.CM-1, ID.SC-2, RS.AN-1, RS.AN-5]
d3fend: [D3-TL, D3-DF, D3-CDR]
nist_ai_rmf: [MEASURE-2.1, MAP-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during incident response to determine the sequence of attacker actions, for reconstructing the forensic timeline of a compromise, when correlating multiple evidence sources, and for identifying the initial compromise vector and time.

## Prerequisites

- Acquired forensic image or live system access (not ideal)
- Plaso (log2timeline) installed for timeline generation
- Python 3.10+ with pandas for timeline analysis
- Forensic tools for artifact extraction (MFT, registry, event logs)
- Timeline analysis tools (Timesketch, Elastic Stack)
- Understanding of Windows forensic artifacts and timestamps

## Workflow

1. Collect timeline artifacts: Extract MFT, USN Journal, registry hives, event logs, prefetch, shellbags, browser history, SRUM, and Amcache
2. Run Plaso ingestion: `log2timeline.py --storage timeline.plaso /evidence/` to process artifacts into timeline
3. Parse timeline: `psort.py -o json timeline.plaso > timeline.json` for programmatic analysis
4. Categorize events: Tag events by type (file, registry, network, process, user activity) and source artifact
5. Identify key events: Mark Initial Compromise (IC), lateral movement, privilege escalation, data exfiltration, and cleanup markers
6. Correlate evidence: Cross-reference events across multiple artifacts (MFT + event log + prefetch) for validation
7. Fill timeline gaps: Identify gaps where attacker activity is indicated but not captured by available artifacts
8. Validate timestamps: Normalize time zones, check for timestamp anti-forensics (timestomping via MFT comparison)
9. Build narrative: Construct the attacker kill chain timeline with supporting evidence for each step
10. Document timeline: Create report with chronological event sequence, source artifacts, and confidence levels

## Verification

- Timeline contains events from all relevant forensic artifacts
- Timestamp consistency is verified across multiple evidence sources
- Initial compromise timestamp is identified to within 5-minute accuracy
- All significant attacker actions are represented in timeline (no major gaps)
- Confidence levels are assigned to each timeline entry based on artifact reliability
- Timeline is reviewed by second analyst for completeness and accuracy
