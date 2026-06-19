# Standards Reference

## OWASP API Security Top 10
| Risk | Description |
|------|-------------|
| API1 | Broken Object Level Authorization |
| API2 | Broken Authentication |
| API3 | Broken Object Property Level Authorization |
| API4 | Unrestricted Resource Consumption |
| API5 | Broken Function Level Authorization |
| API6 | Unrestricted Access to Sensitive Business Flows |
| API7 | Server Side Request Forgery |
| API8 | Security Misconfiguration |
| API9 | Improper Inventory Management |
| API10 | Unsafe Consumption of APIs |

## Common API Vulnerabilities
| Vulnerability | Example |
|---------------|---------|
| IDOR | GET /api/users/1234 -> can change 1234 to 5678 |
| Mass Assignment | {"name":"test","role":"admin"} where role is server-managed |
| JWT None Attack | {"alg":"none","typ":"JWT"} signed with empty signature |
| GraphQL Introspection | query { __schema { types { name } } } |
| Rate Limiting Bypass | X-Forwarded-For header spoofing |
| Pagination Abuse | page=1&limit=10000 returning all records |

## API Security Testing Tools
- **Burp Suite**: ActiveScan++, Autorize, AuthMatrix
- **Postman**: Collection runner, Newman CLI
- **GraphQL**: GraphQL Voyager, GraphiQL, InQL Scanner
- **JWT**: jwt_tool, jwt.io, John the Ripper for JWT cracking
- **Rate Limiting**: wrk, siege, vegeta, Hey

## References
- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- OWASP REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- GraphQL Security: https://github.com/doyensec/awesome-graphql-security
