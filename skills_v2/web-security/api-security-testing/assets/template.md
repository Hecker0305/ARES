# API Security Assessment Report

## Target Information
- **Base URL**: {{base_url}}
- **API Version**: {{api_version}}
- **Authentication**: {{auth_type}}
- **Assessor**: {{assessor}}
- **Date**: {{date}}

## Summary
| Risk Category | Critical | High | Medium | Low |
|---------------|----------|------|--------|-----|
| Authentication | {{auth_critical}} | {{auth_high}} | {{auth_medium}} | {{auth_low}} |
| Authorization | {{authz_critical}} | {{authz_high}} | {{authz_medium}} | {{authz_low}} |
| Injection | {{inj_critical}} | {{inj_high}} | {{inj_medium}} | {{inj_low}} |
| Rate Limiting | {{rl_critical}} | {{rl_high}} | {{rl_medium}} | {{rl_low}} |
| Configuration | {{config_critical}} | {{config_high}} | {{config_medium}} | {{config_low}} |

## Key Findings

### IDOR - {{idor_endpoint}}
- **Severity**: Critical
- **Description**: Object ID enumeration allowed access to unauthorized resources
- **Proof**: `GET {{idor_url}}`
- **Impact**: Unauthorized access to {{idor_data_type}}

### Broken Authentication - {{auth_endpoint}}
- **Severity**: High
- **Finding**: {{auth_finding}}
- **Proof**: {{auth_proof}}

### Rate Limiting - {{ratelimit_endpoint}}
- **Severity**: {{ratelimit_severity}}
- **Current Limit**: None detected
- **Test**: {{ratelimit_count}} requests in {{ratelimit_time}}s without 429

## GraphQL Analysis
- Introspection enabled: {{gql_introspection}}
- Depth limit: {{gql_depth}}
- Query cost analysis: {{gql_cost}}
- Batching enabled: {{gql_batching}}

## Remediation
1. Implement proper object-level authorization checks on all endpoints
2. Enforce rate limiting with per-user and per-IP quotas
3. Disable GraphQL introspection in production
4. Implement JWT with strong signing keys and short expiration
5. Apply input validation and parameterized queries to prevent injection
6. Use API gateway for centralized security policy enforcement
