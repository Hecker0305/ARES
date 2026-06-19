---
name: code-signing
description: >-
  Code signing security methodology covering certificate management, signing infrastructure protection,
  timestamp authority, signature validation, and CI/CD integration for build integrity.
domain: devsecops
subdomain: code-signing
tags: [code-signing, certificates, authenticode, signing-infrastructure, build-integrity]
mitre_attack: [T1195, T1553, T1574]
nist_csf: [PR.DS-6, PR.IP-3, de.cm-1, de.cm-4]
d3fend: [D3-CS, D3-SBOM, D3-IAV]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during code signing infrastructure deployment, certificate management audits, CI/CD signing pipeline configuration, and when verifying software supply chain integrity.

## Prerequisites

- Code signing certificates (EV, standard, or self-signed for CI)
- Hardware Security Module (HSM) or cloud key vault for private key storage
- Signing tools (signtool, gpg, cosign, JSign)
- CI/CD pipeline with access to signing infrastructure
- Timestamp authority server for long-lived signatures
- PKI infrastructure understanding (X.509, certificate chains)

## Workflow

1. Deploy signing infrastructure: Set up HSM or cloud key vault with code signing certificates, configure access policies
2. Implement secure signing pipeline: Integrate signing into CI/CD build process after successful security scans
3. Verify certificate chain: Ensure all intermediate CAs are trusted by target platforms, validate CRL/OCSP availability
4. Use timestamp authority: Configure timestamp server to ensure signatures remain valid after certificate expiry
5. Test signature validation: Verify signatures on all platforms (Windows Authenticode, macOS Gatekeeper, Linux RPM/DEB)
6. Implement hardware key protection: Store private keys in FIPS 140-2 Level 3 HSM, never in CI/CD environment variables
7. Automate key rotation: Set up certificate renewal automation with overlap period to avoid expiry gaps
8. Sign all artifacts: Ensure all distribution artifacts (EXE, MSI, DLL, DMG, DEB, RPM, container images) are signed
9. Verify container signing: Use cosign for container image signing with keyless signing via OIDC
10. Audit signing operations: Log all signing events with artifact hash, certificate used, and pipeline reference

## Verification

- All production build artifacts are digitally signed before distribution
- Private keys are stored in HSM/key vault with no plaintext access
- Signatures validate against trusted root CAs on all target platforms
- Timestamp authority ensures signature validity beyond certificate expiry
- Container images are signed with cosign and verified before deployment
- Signing audit log shows complete record of all signed artifacts
- Certificate revocation check (CRL/OCSP) is functional
