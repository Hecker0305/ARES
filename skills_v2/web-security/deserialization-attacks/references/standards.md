# Standards Reference

## Serialization Format Detection
| Language | Format | Magic Bytes/Signature |
|----------|--------|----------------------|
| Java | Native Serialization | `aced0005` (hex) |
| Java | JSON (Jackson) | `@class` or `@type` |
| PHP | PHP Serialization | `O:8:"ClassName":` |
| Python | Pickle | `(dp0` or `\x80\x04` |
| Python | PyYAML | `!!python/object:` |
| .NET | BinaryFormatter | `\x00\x01\x00\x00\x00` |
| Ruby | Marshal | `\x04\x08o:` |
| Node.js | node-serialize | `_$$ND_FUNC$$_` |

## Common Java Gadget Chains
| Library | ysoserial Payload | Versions |
|---------|------------------|----------|
| CommonsCollections1 | CommonsCollections1 | 3.1 |
| CommonsCollections2 | CommonsCollections2 | 4.0 |
| CommonsCollections3 | CommonsCollections3 | 3.1 |
| CommonsCollections4 | CommonsCollections4 | 4.0 |
| Spring | Spring1 | 4.x |
| Jackson | Jackson | 2.x |
| Fastjson | Fastjson | 1.2.x |
| Hibernate | Hibernate1 | 3.x, 4.x, 5.x |

## PHPGGC Chains
| Framework | Chain | Impact |
|-----------|-------|--------|
| Laravel | RCE | Code execution |
| Symfony | RCE | Code execution |
| CodeIgniter | RCE | Code execution |
| Doctrine | SQLI | SQL Injection |
| SwiftMailer | RCE/FI | File inclusion |

## References
- ysoserial: https://github.com/frohoff/ysoserial
- ysoserial.net: https://github.com/pwntester/ysoserial.net
- PHPGGC: https://github.com/ambionics/phpggc
- OWASP Deserialization: https://owasp.org/www-project-cheat-sheets/cheatsheets/Deserialization_Cheat_Sheet
