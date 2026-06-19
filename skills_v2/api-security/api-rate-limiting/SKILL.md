---
name: api-rate-limiting
description: >-
  API rate limiting security assessment covering bypass techniques, distributed brute-force detection,
  throttle configuration review, and rate limiting implementation best practices.
domain: api-security
subdomain: api-rate-limiting
tags: [api, rate-limiting, throttling, brute-force, dos, security-testing]
mitre_attack: [T1110, T1499]
nist_csf: [PR.AC-6, PR.DS-2, de.cm-1, de.cm-7]
d3fend: [D3-RL, D3-ALR, D3-WAF, D3-IAM]
nist_ai_rmf: [DETECT-1.2, MEASURE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during API security testing for authentication endpoints, when evaluating protection against brute-force and credential stuffing attacks, during rate limiting policy configuration, and during load testing for availability.

## Prerequisites

- API endpoint list with authentication and sensitive operations identified
- Rate limiting testing tools (wrk, hey, custom Python scripts)
- Python 3.10+ with aiohttp for concurrent request testing
- Proxy rotation services or VPN for distributed origin testing
- Understanding of rate limiting techniques (token bucket, leaky bucket, sliding window)
- API usage quotas and throttling documentation

## Workflow

1. Identify rate-limited endpoints: Test each endpoint with increasing request frequency to detect rate limits
2. Measure baseline limits: Determine exact thresholds (X requests per Y seconds) for each endpoint and user
3. Bypass via headers: Test X-Forwarded-For, X-Real-IP, X-Originating-IP, and X-Client-IP header spoofing for identity bypass
4. Bypass via batch operations: Test batch GraphQL queries, JSON arrays, and multipart requests to execute many operations in one HTTP request
5. Bypass via distributed requests: Test with multiple unique sessions, API keys, or IPs to distribute attack across rate limit buckets
6. Test resource-intensive queries: Send complex queries (deep GraphQL, large payloads, slow loris) that consume server resources
7. Evaluate burst allowance: Test short bursts that stay within per-second limits but exceed per-minute limits
8. Check reset behavior: Verify rate limit counter resets correctly (sliding window) and doesn't reset at predictable intervals
9. Test authenticated vs unauthenticated: Compare rate limits for authenticated vs anonymous access
10. Validate response headers: Check for `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` headers

## Verification

- Hard rate limits prevent brute-force attacks beyond threshold (e.g., 10 attempts per minute per user)
- Header spoofing (X-Forwarded-For) does not bypass rate limits
- Batch operations are counted as individual requests for rate limiting purposes
- Rate limiting is applied per-user (not per-IP) for authenticated endpoints
- Rate limit headers are present and accurately reflect remaining quota
- Rate limits cannot be reset by cycling tokens or re-authenticating
- Server returns 429 Too Many Requests with Retry-After header when exceeded
