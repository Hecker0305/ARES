---
name: sqli-detection
description: >-
  Manual and automated SQL injection vulnerability detection using time-based, boolean-based, error-based, and out-of-band techniques.
  Covers database fingerprinting, injection point discovery, evasion, and exploitation.
domain: web-security
subdomain: sqli-detection
tags: [sqli, sql-injection, web-security, database, penetration-testing, owasp-top-10]
mitre_attack: [T1190, T1213, T1505]
nist_csf: [PR.AC-4, PR.DS-2, DE.CM-4, RS.MI-3]
d3fend: [D3-WAF, D3-IAM, D3-SIEM, D3-SDI]
nist_ai_rmf: [MEASURE-2.2, DETECT-1.3]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during web application security assessments, penetration tests targeting database-backed applications, after discovering SQLi via automated scanners (sqlmap, Burp), or during secure code review of database queries.

## Prerequisites

- Burp Suite Professional or OWASP ZAP for proxy interception
- sqlmap installed with Python 3.10+ for automated detection and exploitation
- Browser with developer tools for manual testing
- Python 3.10+ with requests library for custom payload crafting
- Database-specific tools (mysql, psql, sqlcmd) for extraction verification
- Understanding of SQL syntax for MySQL, PostgreSQL, MSSQL, and Oracle

## Workflow

1. Map injection surface: Identify all user input vectors (GET/POST parameters, cookies, headers, JSON body) that interact with database queries
2. Test for basic injection: Insert single quote `'`, double quote `"`, and closing brackets `)` to trigger database errors
3. Detect error-based SQLi: Look for database error messages revealing query structure, column count, or data type information
4. Confirm boolean-based blind: Use `AND 1=1` vs `AND 1=2` to observe response differences
5. Verify time-based blind: Inject `SLEEP(5)`, `WAITFOR DELAY '0:0:5'`, or `pg_sleep(5)` to confirm time delay
6. Enumerate database: Determine DBMS type and version via banner grabbing or function calls (version(), @@version)
7. Extract column count: Use `ORDER BY N--` to determine the number of columns in the result set
8. Determine UNION injection: Match column data types using NULL values and convert to string if needed
9. Extract data: Retrieve table names, column names, and data from system tables (information_schema)
10. Document findings: Record exact injection point, payload, DBMS version, and extracted data samples

## Verification

- Injection point is confirmed with at least two different detection techniques (error + blind, or time + boolean)
- Database fingerprint correctly identifies DBMS, version, and user privileges
- UNION-based extraction successfully retrieves at least one table's data
- Payload bypasses any WAF/input filtering for the confirmed injection point
- Automated tools (sqlmap) can replicate and fully exploit the vulnerability
- All extracted data is documented with the exact payload used
- Remediation recommendation includes parameterized queries and input validation
