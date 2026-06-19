---
name: key-management
description: >-
  Cryptographic key management lifecycle covering key generation, storage, rotation, escrow, revocation,
  and destruction. Includes HSM integration, cloud KMS, and compliance with key management standards.
domain: cryptography
subdomain: key-management
tags: [key-management, hsm, kms, encryption-keys, pki, key-rotation, key-escrow]
mitre_attack: [T1553, T1583]
nist_csf: [PR.DS-1, PR.DS-2, PR.AC-1, PR.AC-4, de.cm-1, de.cm-4]
d3fend: [D3-KM, D3-KMS, D3-HSM, D3-ENC]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2, MANAGE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during key management policy development, for cloud KMS deployment and migration, during HSMC audit and deployment, for key rotation automation, and when establishing key escrow and recovery procedures.

## Prerequisites

- Key management system (AWS KMS, Azure Key Vault, GCP Cloud KSM, HashiCorp Vault, Thales HSM)
- HSM (Hardware Security Module) for root/master key storage (FIPS 140-2 Level 3)
- Key management policy documentation
- Python 3.10+ with cloud-specific KMS SDKs
- Understanding of key types (symmetric, asymmetric - RSA, ECC, PGP)
- NIST SP 800-57 key management guidance

## Workflow

1. Classify keys by type and sensitivity: Identify all key types (SSL/TLS, code signing, SSH, database encryption, API keys, JWT signing) and classify by risk level
2. Deploy KMS/HSM: Set up cloud KMS or on-premises HSM with proper access controls, auditing, and backup
3. Establish key generation policy: Generate keys within HSM or KMS (never outside), use appropriate key sizes (AES-256, RSA-3072+, ECDSA P-384)
4. Configure key rotation: Enable automatic key rotation (CMK: yearly, data keys: per-encryption operation), set rotation window alerts
5. Implement key hierarchy: Use master keys (HSM-protected) to encrypt data keys, apply envelope encryption for performance
6. Create key escrow: Establish secure key escrow procedure with dual-control (M of N) for disaster recovery
7. Configure access controls: Apply least-privilege key access policies (IAM for KMS), separate key administrators from key users
8. Enable key auditing: Log all key management operations (create, encrypt, decrypt, rotate, delete) for compliance
9. Establish key destruction: Define key destruction procedures (crypto-shredding for cloud KMS, zeroization for HSM)
10. Document key lifecycle: Create key inventory with lifecycle status, rotation schedules, and compliance requirements

## Verification

- All cryptographic keys are stored in approved KMS/HSM (not in config files, code, or environment variables)
- Key rotation is automated and occurs within defined intervals
- Key access follows least privilege with separation of duties
- Key escrow procedure is documented and tested annually
- Key destruction is verifiable (keys are cryptographically destroyed, not just deleted)
- Audit log captures all key management operations with user identity and timestamp
- Key inventory is maintained with status and lifecycle tracking
- Compliance with NIST SP 800-57 key management guidelines
