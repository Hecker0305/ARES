---
name: jwt-attacks
description: >-
  JWT security attack and testing methodology covering algorithm confusion, key cracking, sensitive data exposure,
  token manipulation, and signature bypass techniques across JWT, JWE, and JWK implementations.
domain: api-security
subdomain: jwt-attacks
tags: [jwt, token, authentication, jwt-attacks, algorithm-confusion, key-cracking, signature-bypass]
mitre_attack: [T1525, T1550, T1556, T1606]
nist_csf: [PR.AC-1, PR.AC-3, PR.AC-4, PR.DS-2, de.cm-1]
d3fend: [D3-JWT, D3-AUTH, D3-IAM]
nist_ai_rmf: [GOVERN-1.1, MEASURE-2.1, DETECT-2.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during API authentication security testing, when JWT-based APIs are discovered, during token validation security reviews, for identity provider security assessments, and when auditing OAuth 2.0/OIDC implementations.

## Prerequisites

- JWT tokens from target application (from Authorization headers, cookies, or request bodies)
- jwt.io or PyJWT for token decode and signature verification
- Python 3.10+ with PyJWT, jwcrypto libraries
- jwt_tool (GitHub: ticarpi/jwt_tool) for automated testing
- Burp Suite JWT extension for in-scope testing
- Understanding of JWT structure, algorithms, and security considerations

## Workflow

1. Decode JWT: Parse the token header, payload, and signature using base64url decoding
2. Analyze header: Check algorithm (alg), key ID (kid), token type (typ), key URL (jku), key set URL (jku)
3. Test algorithm confusion: Modify `alg` from RS256 to HS256 and sign with the public key (if available)
4. Test `none` algorithm: Change `alg` to `none`, `None`, `NONE`, `nOnE` and remove signature
5. Crack weak secret: Use jwt_tool or hashcat to brute-force weak HMAC secrets from intercepted tokens
6. Manipulate payload: Change claims (sub, role, admin, exp, iat) and sign with known/guessed key
7. Test JWK injection: Add `jwk` header with attacker-controlled public key if server accepts embedded keys
8. Check kid injection: Test SQLi and path traversal in `kid` header for key retrieval bypass
9. Validate key confusion: If both RS256 and HS256 are accepted, test cross-signing attacks
10. Check token storage: Verify tokens aren't logged, sent in URLs, or stored insecurely on client

## Verification

- Server rejects tokens with `alg: none` regardless of token content
- Algorithm confusion attack fails (server validates algorithm matches expected)
- HMAC secret from cracking is validated against the server
- Token manipulation (changed sub/role claims) is rejected or detected
- JWK and JKU header injection attempts are rejected
- Kid injection (SQLi, path traversal) attempts fail
- Tokens are stored securely (HTTPOnly cookies, secure storage, not in local storage)
- Token expiry is enforced and revoked tokens are rejected
