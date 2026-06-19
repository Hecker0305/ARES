---
name: disk-imaging
description: >-
  Forensic disk imaging methodology using hardware and software write-blockers, DD/DC3DD/E01 acquisition,
  hash verification, and evidence packaging for court-admissible forensic duplicate creation.
domain: digital-forensics
subdomain: disk-imaging
tags: [disk-imaging, forensics, dd, ewf, data-acquisition, write-blocker, evidence]
mitre_attack: [T1005, T1070]
nist_csf: [DE.AE-2, ID.SC-2, PR.DS-1, PR.DS-6, RS.AN-1]
d3fend: [D3-DI, D3-DF, D3-CDR]
nist_ai_rmf: [GOVERN-2.1, MEASURE-1.3]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during incident response to acquire forensic images of compromised systems, during e-discovery and legal investigations, for data recovery from damaged media, and when creating forensic duplicates for analysis.

## Prerequisites

- Hardware write-blocker (Tableau, WiebeTech) or verified software write-blocker
- Target storage media with sufficient space (minimum 1.5x source capacity)
- Forensic imaging tools: dd, dc3dd, FTK Imager, Guymager
- Hashing tools for evidence integrity
- Chain of custody documentation forms
- Anti-static bags and handling equipment
- Clean forensic workstation in controlled environment

## Workflow

1. Document evidence: Photograph device (model, serial, connections), handle with anti-static precautions
2. Apply write-blocker: Connect hardware write-blocker between source and acquisition workstation
3. Verify write protection: Confirm source media is mounted read-only (kernel messages, physical indicator)
4. Select acquisition method: Choose logical (files only) vs physical (bit-for-bit) imaging based on requirements
5. Configure imaging parameters: Determine compression (EWF), split size (2GB for portability), block size (default 512)
6. Execute acquisition: Run imaging tool with hash computation (`dc3dd if=/dev/sda hash=sha256 of=image.dd`)
7. Verify acquisition hash: Compare source hash vs image hash (must match for forensic soundness)
8. Handle bad sectors: Document any bad sectors encountered; use `ddrescue` for failing drives
9. Package evidence: Store image with hash manifest, acquisition log, and chain of custody documentation
10. Secure storage: Store master image in write-protected evidence repository with access logging

## Verification

- Source media write-blocker is tested and verified before acquisition
- Acquisition hash matches source hash (SHA-256 + MD5 verification)
- Bad sector count is zero or documented with verified replacement data
- Image file is readable and mountable for forensic analysis
- Chain of custody documentation is complete with timestamps and signatures
- Image stored with verified integrity in secure evidence repository
