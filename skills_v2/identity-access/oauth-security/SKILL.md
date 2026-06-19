---
name: oauth-security
description: >-
  OAuth 2.0 and OpenID Connect security assessment covering authorization code flow, implicit flow,
  client credential security, redirect URI validation, PKCE enforcement, and token validation.
domain: identity-access
subdomain: oauth-security
tags: [oauth, oidc, openid-connect, authorization, tokens, jwt, pkce, authentication]
mitre_attack: [T1525, T1550, T1556, T1606]
nist_csf: [PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-6, PR.DS-2]
d3fend: [D3-OAUTH, D3-JWT, D3-PKCE, D3-IAM, D3-AUTH]
nist_ai_rmf: [GOVERN-1.2, MEASURE-2.1, MAP-1.3]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during OAuth/OIDC provider deployment, API authentication review, third-party OAuth integration security assessment, token validation configuration, and during identity federation security audits.

## Prerequisites

- OAuth 2.0 authorization server configuration access (IdentityServer, Okta, Azure AD, Auth0)
- JWT token debugging tools (jwt.io, jwt_tool)
- Python 3.10+ with OAuth libraries (oauthlib, requests-oauthlib, PyJWT)
- Burp Suite or proxy for intercepting OAuth flows
- Understanding of OAuth grant types and OIDC flows
- API gateway or reverse proxy with OAuth validation capabilities

## Workflow

1. Document OAuth flows: Identify all grant types in use (authorization code, client credentials, implicit, device code, refresh token)
2. Validate redirect URIs: Check authorization callback URLs for open redirect vulnerabilities, wildcard patterns, or path confusion
3. Test CSRF protection: Verify state parameter is random, unique, and validated on callback for authorization code flow
4. Verify PKCE enforcement: Confirm Proof Key for Code Exchange is enforced for all authorization code flows targeting mobile/public clients
5. Audit client credentials: Review client secrets, certificate-based authentication, and client authentication methods
6. Analyze token lifetimes: Review access token TTL, refresh token rotation, and ID token expiration
7. Validate token signatures: Verify RS256/ES256 signature validation, check for algorithm confusion (none, HS256)
8. Check scope validation: Ensure authorization server validates requested scopes against allowed scopes for each client
9. Test privilege escalation: Attempt to modify token claims or exchange authorization code for tokens with elevated scopes
10. Review federation trusts: Audit third-party IdP trust relationships and token exchange configurations

## Verification

- Authorization code flow uses PKCE with S256 challenge method for all public clients
- Redirect URIs are exact-match validated (no wildcards, no open redirect bypass)
- State parameter is cryptographically random and validated on callback
- Token signatures are validated using RS256/ES256 (no `alg: none` accepted)
- Client credentials are stored securely (not in source code, browser, or mobile app)
- Access tokens are short-lived (15-60 minutes) with rotating refresh tokens
- Scopes follow least privilege (no wildcard scopes like `*` or `admin:*`)
