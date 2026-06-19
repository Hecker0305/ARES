---
name: mobile-api-testing
description: >-
  Mobile application backend API security testing covering mobile-specific API vulnerabilities,
  authentication and session management, binary API analysis, protocol buffer inspection, and app-specific API attack vectors.
domain: mobile-security
subdomain: mobile-api-testing
tags: [mobile-api, api-security, rest-api, graphql, protobuf, mobile-application, backend-testing]
mitre_attack: [T1190, T1210, T1525, T1550]
nist_csf: [PR.AC-1, PR.AC-4, PR.DS-2, de.cm-1, de.cm-4]
d3fend: [D3-WAF, D3-IAM, D3-ALR, D3-AUTH]
nist_ai_rmf: [DETECT-1.2, MEASURE-2.1, MAP-1.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during mobile application API security testing, for mobile app backend assessment, when testing mobile-specific API authentication and authorization, and during API binary protocol analysis.

## Prerequisites

- Burp Suite for API traffic interception on mobile device
- Mobile app installed on test device or emulator
- API reverse engineering tools (MobSF, jadx, Frida)
- Protocol buffer tools (protoc, protobuf-inspector) for protobuf APIs
- Python 3.10+ for custom API test automation
- Understanding of mobile API patterns (REST, GraphQL, Protobuf, gRPC, WebSocket)

## Workflow

1. Intercept mobile API traffic: Configure Burp Suite as proxy on mobile device, capture all API calls during app usage
2. Analyze API endpoints: Map all discovered endpoints (REST, GraphQL, Protobuf, WebSocket), document authentication methods
3. Test mobile authentication: Verify session tokens, OAuth flows, biometric authentication, fingerprint tokens, and device-specific auth
4. Check authorization controls: Test IDOR by modifying user/device identifiers, test vertical privilege escalation by manipulating role claims
5. Analyze binary protocols: For protobuf/gRPC APIs, decompile protobuf definitions from binary, craft custom messages
6. Test API parameter manipulation: Modify device ID, app version, platform identifier, and other device-specific parameters
7. Assess session management: Verify token expiration, refresh token rotation, concurrent session limits, and token invalidation on logout
8. Test rate limiting: Submit rapid requests to check per-device and per-user rate limits (especially auth and OTP endpoints)
9. Analyze custom protocols: Reverse engineer any proprietary or encrypted API protocols with Frida/runtime hooks
10. Document findings: Provide API-specific vulnerability findings with request/response evidence and mobile-specific impact

## Verification

- All mobile API endpoints are documented with request/response schemas
- API authentication cannot be bypassed by modifying device ID, version, or platform headers
- API tokens are short-lived and properly invalidated on logout
- Protobuf/gRPC APIs are properly decompiled and fuzzed for vulnerabilities
- Rate limiting is device-aware (not just IP-based) for mobile endpoints
- API responses do not expose excessive data (PII, internal IDs, tokens)
- Authorization checks are performed server-side (not relying on client-side enforcement)
- API sessions are bound to the device (device fingerprint, token binding)
