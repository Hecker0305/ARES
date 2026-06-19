# Insecure Deserialization Assessment Report

## Target Information
- **Application**: {{application}}
- **Endpoint**: {{endpoint}}
- **Parameter**: {{parameter}}
- **Assessor**: {{assessor}}
- **Date**: {{date}}

## Findings Summary
| Finding | Severity | Confirmed |
|---------|----------|-----------|
| Java Deserialization | {{java_severity}} | {{java_confirmed}} |
| PHP Deserialization | {{php_severity}} | {{php_confirmed}} |
| Python Pickle | {{python_severity}} | {{python_confirmed}} |
| .NET Deserialization | {{dotnet_severity}} | {{dotnet_confirmed}} |
| YAML/XML Deserialization | {{yaml_severity}} | {{yaml_confirmed}} |

## Detailed Findings

### Finding DES-01: Java Deserialization in {{param_name}}
- **Format**: Java Native Serialization
- **Magic Bytes**: aced0005
- **Gadget Chain**: {{gadget_chain}}
- **Library**: {{library}}
- **Payload**: {{payload}}
- **OOB Confirmed**: {{oob_confirmed}}

### Finding DES-02: {{finding_type}}
- **Format**: {{format}}
- **Entry Point**: {{entry_point}}
- **Technique**: {{technique}}
- **Impact**: {{impact}}

## Entry Points Identified
| # | Parameter | Location | Format | Status |
|---|-----------|----------|--------|--------|
| 1 | {{ep_1}} | {{location_1}} | {{format_1}} | {{status_1}} |
| 2 | {{ep_2}} | {{location_2}} | {{format_2}} | {{status_2}} |

## Exploitation Results
- RCE achieved: {{rce_achieved}}
- Command executed: {{command}}
- Output: {{output}}
- Webshell deployed: {{webshell}}

## Impact Assessment
- **CVSS Score**: {{cvss_score}}
- **Risk**: {{risk}}
- **Compromised Hosts**: {{hosts}}
- **Data Exposed**: {{data_exposed}}

## Remediation
1. Avoid deserialization of untrusted data entirely
2. Implement integrity checks (HMAC) on serialized data
3. Use safe serialization formats (JSON with type validation)
4. Implement allowlist-based deserialization
5. Run deserialization in sandboxed environment with limited privileges
6. Keep serialization libraries updated to patched versions
