---
name: api-security-testing
description: >-
  Comprehensive REST and GraphQL API security testing methodology covering authentication, authorization, injection,
  rate limiting, mass assignment, IDOR, and business logic flaws in API endpoints.
domain: web-security
subdomain: api-security-testing
tags: [api-security, rest-api, graphql, authentication, authorization, idor, owasp-api-top-10]
mitre_attack: [T1190, T1210, T1550, T1595]
nist_csf: [PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-6, PR.DS-2, DE.CM-4, DE.CM-8]
d3fend: [D3-WAF, D3-IAM, D3-ALR, D3-RL, D3-AUTH]
nist_ai_rmf: [DETECT-1.1, MEASURE-2.2, GOVERN-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during API security assessments for both REST and GraphQL APIs, during CI/CD security testing of microservices, when auditing API gateway configurations, and during OAuth/OIDC security reviews.

## Prerequisites

- Burp Suite or OWASP ZAP with API scanning extensions
- Postman or Insomnia for manual API testing with collections
- Python 3.10+ with requests, httpx, and graphql-client libraries
- JWT debugging tools (jwt.io, jwt_tool)
- API documentation (OpenAPI/Swagger spec or GraphQL introspection)
- Authentication tokens for authorized testing
- Rate limiting testing tools (wrk, siege, or custom scripts)

## Workflow

1. Document API surface: Import OpenAPI spec, enumerate all endpoints (GET, POST, PUT, DELETE, PATCH), and document authentication requirements
2. Test authentication: Check for anonymous access, weak JWT secrets, token leakage in URLs, missing token expiry, and improper logout
3. Test authorization: Test IDOR by modifying object IDs in requests, test role escalation by modifying user roles in tokens
4. Test injection points: Test API parameters for SQLi, NoSQLi, XSS, SSTI, XXE, and command injection
5. Test mass assignment: Submit unexpected fields in JSON body to modify properties not intended for client modification
6. Test rate limiting: Send rapid requests to check for proper rate limiting on authentication, data extraction, and critical operations
7. Test pagination: Manipulate page size and offset parameters to extract data beyond intended scope
8. Test GraphQL introspection: Query `__schema` to discover all types, queries, mutations, and subscriptions
9. Test for excessive data exposure: Check responses for sensitive data (PII, tokens, internal IDs) not required for client operation
10. Test business logic: Manipulate workflows, skip steps, replay transactions, and abuse discount/promotion logic

## Verification

- Authentication is required for all endpoints that handle sensitive data
- IDOR vulnerability is confirmed by accessing another user's resource
- Rate limiting returns 429 Too Many Requests after threshold
- SQL/NoSQL injection causes detectable behavior change
- JWT signing algorithm cannot be changed to `none`
- GraphQL introspection is disabled in production
- API returns only required fields (no excessive data exposure)
- Mass assignment modifies fields that should be server-controlled
