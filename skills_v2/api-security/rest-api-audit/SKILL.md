---
name: rest-api-audit
description: >-
  REST API security audit covering HTTP method enforcement, authentication checks, input validation,
  response header security, CORS configuration, rate limiting, and API versioning security.
domain: api-security
subdomain: rest-api-audit
tags: [rest-api, audit, http-methods, authentication, cors, rate-limiting, input-validation]
mitre_attack: [T1190, T1210, T1595]
nist_csf: [PR.AC-1, PR.AC-4, PR.AC-6, PR.DS-2, de.cm-1]
d3fend: [D3-WAF, D3-IAM, D3-ALR, D3-AUTH]
nist_ai_rmf: [GOVERN-1.2, MEASURE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during API security assessments, before API version deployment, for OpenAPI/Swagger specification review, when auditing REST API compliance with OWASP REST Security recommendations.

## Prerequisites

- OpenAPI/Swagger specification for the API
- Burp Suite or OWASP ZAP for traffic interception
- Python 3.10+ with requests and OpenAPI parser libraries
- API keys or OAuth tokens for authenticated testing
- cURL/Postman for manual endpoint testing

## Workflow

1. Analyze OpenAPI spec: Parse API specification for security definitions, endpoint catalog, parameter schemas, and response codes
2. Test HTTP methods: Verify endpoints only accept required methods (GET/POST/PUT/DELETE), reject others with 405
3. Validate authentication: Test endpoints without auth header, with expired tokens, and with invalid tokens
4. Check response headers: Verify security headers: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options
5. Audit CORS: Check Access-Control-Allow-Origin header for wildcard or overly permissive origins
6. Test input validation: Submit invalid data types, oversized payloads, malformed JSON, and special characters
7. Verify content type: Test that API validates Content-Type header and rejects incorrect content types
8. Check rate limiting: Test both IP-based and user-based rate limiting with burst requests
9. Review pagination: Test pagination parameters for data exposure (limit, offset, cursor manipulation)
10. Analyze error messages: Check that error responses do not leak stack traces, internal paths, or database structure

## Verification

- Endpoints reject methods not defined in OpenAPI spec with 405 Method Not Allowed
- Authenticated endpoints return 401/403 for unauthenticated/invalid token requests
- Security headers are present on all API responses
- CORS restricts origins to specific, approved domains
- Invalid input returns clear 400 errors without internal information disclosure
- Rate limiting is enforced with 429 responses
- Error responses hide internal implementation details
