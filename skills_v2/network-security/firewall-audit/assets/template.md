# Firewall Rule Base Audit Report

## Device Information
- **Firewall**: {{firewall_model}}
- **Rule Base Name**: {{rule_base}}
- **Audit Date**: {{audit_date}}
- **Auditor**: {{auditor}}
- **Rule Count**: {{rule_count}}

## Summary
| Category | Count |
|----------|-------|
| Total Rules | {{total_rules}} |
| Critical Issues | {{critical_count}} |
| High Issues | {{high_count}} |
| Medium Issues | {{medium_count}} |
| Low Issues | {{low_count}} |

## Issue Breakdown
| Issue Type | Count | Action |
|------------|-------|--------|
| Shadowed Rules | {{shadowed}} | Remove shadowed rules |
| Redundant Rules | {{redundant}} | Consolidate identical rules |
| Overly Permissive | {{overly_permissive}} | Restrict to specific sources |
| Unused Rules (90d) | {{unused}} | Remove/archive unused rules |
| Orphaned Objects | {{orphaned}} | Clean up unused objects |

## Overly Permissive Rules (any/any)
| # | Rule Name | Source | Destination | Service | Last Hit |
|---|-----------|--------|-------------|---------|----------|
| {{op_rule_1}} | {{op_name_1}} | {{op_src_1}} | {{op_dst_1}} | {{op_svc_1}} | {{op_hit_1}} |
| {{op_rule_2}} | {{op_name_2}} | {{op_src_2}} | {{op_dst_2}} | {{op_svc_2}} | {{op_hit_2}} |

## Compliance Status
| Standard | Status | Notes |
|----------|--------|-------|
| PCI DSS 4.0 Req 1 | {{pci_status}} | {{pci_notes}} |
| SOC 2 CC6.1 | {{soc2_status}} | {{soc2_notes}} |
| NIST SP 800-53 SC-7 | {{nist_status}} | {{nist_notes}} |

## Cleaned Up Rules
| Action | Rule # | Name | Change Ticket |
|--------|--------|------|---------------|
| {{change_1}} | {{rule_1}} | {{name_1}} | {{ticket_1}} |
| {{change_2}} | {{rule_2}} | {{name_2}} | {{ticket_2}} |

## Recommendations
1. Review and remove shadowed rules identified in section 3
2. Consolidate redundant rules to reduce rule base size
3. Implement quarterly rule review process
4. Enable logging on all allow rules for audit purposes
