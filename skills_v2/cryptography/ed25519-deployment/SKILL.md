---
name: ed25519-deployment
description: >-
  Ed25519 elliptic curve deployment and migration planning covering key generation, comparison with RSA/ECDSA,
  performance benchmarks, compatibility testing, and phased rollout for SSH, TLS, code signing, and DNSSEC.
domain: cryptography
subdomain: ed25519-deployment
tags: [ed25519, elliptic-curve, cryptography, key-migration, performance, ssh, tls]
mitre_attack: [T1553]
nist_csf: [PR.DS-1, PR.DS-2, de.cm-1]
d3fend: [D3-KM, D3-ENC, D3-CERT]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when planning migration from RSA to Ed25519 for cryptographic operations, during performance optimization of signing operations, for SSH key modernization, and when deploying FIPS 140-3 compliant Ed25519 implementations.

## Prerequisites

- OpenSSL 1.1.1+ or LibreSSL for Ed25519 key generation
- SSH client/server supporting Ed25519 (OpenSSH 6.5+)
- TLS libraries supporting Ed25519 (BoringSSL, OpenSSL 1.1.1+, NSS)
- DNSSEC with Ed25519 algorithm support (BIND 9.16+, Unbound 1.12+)
- Python 3.10+ with cryptography library (Ed25519 support)
- Performance benchmarking tools (openssl speed, ssh-keygen benchmark)

## Workflow

1. Evaluate Ed25519 compatibility: Check all systems and libraries for Ed25519 support (RHEL 9+, Ubuntu 22.04+, Windows 2022+, macOS 11+)
2. Generate Ed25519 keys: Use `ssh-keygen -t ed25519 -a 100` for SSH keys, `openssl genpkey -algorithm ed25519` for TLS/application keys
3. Benchmark performance: Compare Ed25519 vs RSA-2048/3072 for signing speed, verification speed, and key size:
   - Signing: Ed25519 is 20-50x faster than RSA-2048
   - Verification: Ed25519 is 2-5x faster than RSA-2048
   - Key size: 32 bytes (Ed25519) vs 256+ bytes (RSA-2048)
4. Migrate SSH keys: Generate Ed25519 SSH host keys and user keys, update `authorized_keys` and SSH config
5. Update TLS certificates: Request Ed25519 TLS certificates from CAs supporting Ed25519 (Let's Encrypt, DigiCert, Sectigo)
6. Configure performance: Tune Ed25519 for optimal performance (especially on constrained devices with limited CPU)
7. Update DNSSEC: Generate Ed25519 ZSK/KSK for DNSSEC (algorithm 15 or 16) for smaller DNS responses
8. Deprecate RSA keys: Phase out RSA keys in favor of Ed25519, maintain compatibility during transition
9. Document key strengths: Record Ed25519 security level (128-bit) equivalent to RSA-3072 or ECDSA P-256
10. Monitor for issues: Track SSH authentication failures due to key changes, TLS handshake failures, compatibility reports

## Verification

- Ed25519 key generation completes successfully on all target systems
- SSH connections using Ed25519 keys authenticate correctly with all target servers
- TLS handshake with Ed25519 certificate succeeds in all target browsers and clients
- Signing performance benchmark shows >= 10x improvement over RSA-2048 for signing operations
- Key size reduction is verified (Ed25519: 32 bytes public key vs RSA-2048: 256+ bytes)
- No compatibility issues with Ed25519-only configuration (no fallback to RSA)
- DNS response size reduction measured for Ed25519 DNSSEC (RRSIG ~60 bytes vs RSA ~512 bytes)
- Migration plan covers phased rollout with rollback procedures documented
