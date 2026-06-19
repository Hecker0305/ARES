---
name: graphql-testing
description: >-
  GraphQL API security testing covering introspection queries, query depth analysis, authorization testing,
  batching attacks (batch-query), injection testing, and rate limiting evaluation.
domain: api-security
subdomain: graphql-testing
tags: [graphql, api-security, introspection, query-depth, batching, injection]
mitre_attack: [T1190, T1210, T1595]
nist_csf: [PR.AC-1, PR.AC-4, de.cm-1, de.cm-4]
d3fend: [D3-WAF, D3-IAM, D3-ALR]
nist_ai_rmf: [DETECT-1.2, MEASURE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during GraphQL API security reviews, when deploying new GraphQL endpoints, for testing authorization controls in GraphQL resolvers, and when evaluating rate limiting and depth limiting configurations.

## Prerequisites

- GraphQL endpoint URL (identifiable by /graphql or POST with application/json)
- GraphQL introspection query access to discover schema
- GraphiQL, Altair, or Insomnia for query exploration
- Python 3.10+ with graphql-core and aiohttp for automated testing
- InQL Burp plugin or graphql-ide for schema mapping
- Understanding of GraphQL resolvers, mutations, subscriptions, and data loaders

## Workflow

1. Test introspection: Run `query { __schema { types { name fields { name type { name } } } } }` to discover full schema
2. Map all queries and mutations: Document every available query, mutation, subscription with input/output types
3. Test authentication: Verify all sensitive queries/mutations require valid auth tokens
4. Test authorization: Try to access data from other users by modifying input arguments (IDOR via GraphQL)
5. Perform batching attack: Use `[{"query": "..."}, {"query": "..."}]` to bypass rate limits with batch queries
6. Test query depth: Send deeply nested query (10+ levels) to check for depth limiting
7. Test query complexity: Send queries with many aliases/fields to check for complexity analysis
8. Inject through arguments: Test GraphQL arguments for SQLi, NoSQLi, XSS, and command injection
9. Test field suggestion: Send partial field names to check if query suggestions leak schema info
10. Test persisted queries: Verify persisted query queries bypass authentication and validation controls

## Verification

- Introspection is disabled in production (or restricted to authorized clients)
- Authorization checks are implemented in resolvers (not relying on API gateway alone)
- Query depth is limited to reasonable levels (e.g., max 7 levels)
- Query complexity analysis prevents resource exhaustion
- Batching is limited to reasonable concurrent query count
- Rate limiting is enforced per user/token (not just per IP)
- Injection attempts return sanitization errors or authorization failures
