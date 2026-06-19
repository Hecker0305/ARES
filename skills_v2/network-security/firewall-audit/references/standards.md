# Standards Reference

## Firewall Rule Classification
| Issue | Description | Risk |
|-------|-------------|------|
| Shadowing | Rule never reached due to preceding broader rule | High |
| Redundancy | Multiple rules with identical match conditions | Medium |
| Gap | Missing rule to cover legitimate traffic | Medium |
| Overly Permissive | `any/any` source or destination | High |
| Orphaned | Rule referencing deleted/unused objects | Medium |
| Stale | No hits in 90+ days | Low |

## Compliance Requirements
| Standard | Firewall Requirement |
|----------|---------------------|
| PCI DSS 4.0 | Requirement 1: Firewall configuration review every 6 months |
| SOC 2 | CC6.1: Firewall rule approval and review process |
| NIST 800-53 | SC-7: Boundary protection and rule review |
| ISO 27001 | A.13.1: Network security and firewall management |

## Best Practice Rule Ordering
```
1. Antispoofing rules (block RFC 1918 on external interfaces)
2. Explicit deny rules for known-bad IPs/domains
3. Infrastructure services (DNS, NTP, VPN)
4. Business application rules (ordered by criticality)
5. User access rules (least privilege)
6. Logging and monitoring rules
7. Default deny at the end of each rule base section
```

## References
- NIST SP 800-41 Rev 1: Guidelines on Firewalls and Firewall Policy
- PCI DSS 4.0 Requirement 1: https://listings.pcisecuritystandards.org/documents/PCI-DSS-v4_0_1.pdf
- SANS Firewall Rule Review: https://www.sans.org/white-papers/33007/
