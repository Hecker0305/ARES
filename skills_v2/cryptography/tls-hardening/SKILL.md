---
name: tls-hardening
description: >-
  TLS/SSL hardening methodology covering protocol version enforcement, cipher suite configuration,
  certificate management, HSTS deployment, certificate transparency monitoring, and TLS scanning.
domain: cryptography
subdomain: tls-hardening
tags: [tls, ssl, hardening, certificates, cipher-suites, hsts, certificate-transparency]
mitre_attack: [T1573]
nist_csf: [PR.DS-1, PR.DS-2, de.cm-1, de.cm-4]
d3fend: [D3-TLS, D3-HSTS, D3-CT, D3-CERT]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, MAP-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during TLS configuration audits, when deploying new TLS services, for SSL/TLS vulnerability assessments, when implementing HTTPS-Only standards, and during certificate lifecycle management reviews.

## Prerequisites

- TLS scanning tools (testssl.sh, SSL Labs, Nmap SSL scripts, sslyze)
- Web server configuration access (Nginx, Apache, IIS, HAProxy, Cloudflare)
- Certificate management tools (ACME/certbot, cert-manager)
- Understanding of TLS 1.2/1.3, cipher suites, ECDHE, PFS, and certificate chains
- Python 3.10+ with cryptography library for configuration verification
- HSTS preload list registration knowledge

## Workflow

1. Discover TLS endpoints: Scan all public and internal TLS endpoints (domains, subdomains, IPs) on port 443 and other TLS ports
2. Test protocol support: Verify only TLS 1.2 and 1.3 are supported; disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1
3. Audit cipher suites: Validate strong cipher configuration (ECDHE-RSA-AES256-GCM, preferably TLS_AES_256_GCM_SHA384 for TLS 1.3)
4. Check key exchange: Ensure ECDHE or DHE is used for forward secrecy; disable static RSA key exchange
5. Verify certificate chain: Ensure complete certificate chain (leaf + intermediates) is served, chain is valid, not expired or revoked
6. Test certificate parameters: Verify key size (RSA >= 2048 or ECDSA P-256+), signature algorithm (SHA-256+), and SAN coverage
7. Deploy HSTS: Add `Strict-Transport-Security` header with max-age >= 31536000, includeSubDomains, and preload for all HTTPS sites
8. Enable OCSP stapling: Configure OCSP stapling to improve certificate revocation checking performance and privacy
9. Monitor certificate transparency: Set up CT log monitoring (certificate.transparency.dev) to detect unauthorized certificate issuance
10. Configure TLS reports: Set up TLS report endpoint for TLS negotiation failure reporting (TLS-RPT)

## Verification

- TLS scan (testssl.sh) shows A or A+ rating, no weak ciphers or protocols
- Only TLS 1.2 and TLS 1.3 are enabled; all legacy versions disabled
- Certificate chain is complete and valid for all endpoints
- HSTS header is present with max-age >= 1 year, includeSubDomains, preload
- OCSP stapling is enabled and functional
- Private keys are >= 2048-bit RSA or P-256 ECDSA, stored securely
- Certificate transparency monitoring detects unauthorized certificate issuance within 24 hours
- TLS-RPT receives reports and detects failed TLS connections
