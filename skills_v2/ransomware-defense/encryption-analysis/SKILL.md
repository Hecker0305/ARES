---
name: encryption-analysis
description: >-
  Ransomware encryption behavior analysis covering encryption algorithm identification, key management analysis,
  file header inspection, partial encryption detection, and decryptor feasibility assessment.
domain: ransomware-defense
subdomain: encryption-analysis
tags: [ransomware, encryption-analysis, file-encryption, key-management, decryptor, crypto-analysis]
mitre_attack: [T1486]
nist_csf: [DE.AE-2, DE.CM-1, PR.DS-1, RS.AN-1]
d3fend: [D3-DF, D3-IAV, D3-REC]
nist_ai_rmf: [MEASURE-2.1, MAP-1.1, RESPOND-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during ransomware incident analysis to understand encryption methodology, when assessing decryptor availability, for ransomware variant identification based on encryption patterns, and when evaluating recovery options beyond backup restoration.

## Prerequisites

- Encrypted file samples from ransomware attack (at least 3+ different file types)
- Original unencrypted files for comparison (if available)
- Hex editor (010 Editor, HxD) for binary analysis
- Python 3.10+ with Cryptography library for algorithm testing
- Entropy analysis tools (binwalk, custom entropy calculator)
- Understanding of symmetric vs asymmetric encryption, CBC/GCM/XTS modes, RSA/AES/ChaCha algorithms
- Ransomware note file for variant identification

## Workflow

1. Collect encrypted samples: Gather encrypted files and ransom note from affected systems; capture original unencrypted files if available
2. Analyze file structure: Compare original and encrypted file headers; identify encryption mode (full vs partial vs header-only)
3. Identify encryption algorithm: Analyze entropy distribution (AES-CTR vs ChaCha), check for known patterns/Magic bytes in encrypted output
4. Look for embedded keys: Search encrypted files and ransom note for embedded RSA public key, AES IV, or key material
5. Determine key exchange: Analyze if ransomware uses embedded public key (asymmetric) or session key encrypted with RSA (hybrid)
6. Assess partial encryption: Check if ransomware encrypts only file header (first 512 bytes to 1MB) for faster encryption
7. Check for decryptor availability: Search No More Ransom, Avast, Kaspersky, Emsisoft decryptor databases using file extension/note hash
8. Test offline key recovery: If ransomware has flawed key generation (predictable RNG, static keys), attempt key recovery
9. Document encryption profile: Record: algorithm, mode, key size, IV handling, encrypted regions, file extension appended, ransom note format
10. Provide recovery guidance: Determine if decryption is feasible (key available, decryptor exists, backup recovery, or hybrid approach)

## Verification

- Encryption algorithm is identified (AES, ChaCha, RSA, or hybrid) with evidence from file analysis
- Encryption mode is determined (CBC, GCM, CTR, XTS) with IV handling documented
- Key exchange mechanism is understood (embedded RSA key, KMS, session key encryption)
- Partial vs full encryption is determined (file header only vs full content)
- Decryptor availability is checked (No More Ransom, vendor databases)
- Random number generator quality is assessed if custom encryption is used
- Ransomware variant is identified with confidence (family, version, builder)
- Recovery recommendation is based on technical analysis (decryptor available, key available, backup restore)
