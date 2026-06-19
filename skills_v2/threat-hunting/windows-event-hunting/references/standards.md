# Standards Reference

## Critical Windows Event IDs

| Event ID | Source | Description | ATT&CK |
|----------|--------|-------------|--------|
| 4624 | Security | Account Logon | T1078 |
| 4625 | Security | Account Logon Failure | T1110 |
| 4648 | Security | Explicit Credential Use | T1021, T1550 |
| 4672 | Security | Admin Logon (Special Privileges) | T1068, T1548 |
| 4688 | Security | Process Creation | T1059 |
| 4697 | Security | Service Installation | T1543 |
| 4703 | Security | Token Manipulation | T1134 |
| 4720 | Security | User Account Created | T1136 |
| 4738 | Security | User Account Changed | T1098 |
| 4742 | Security | Computer Account Changed | T1098 |
| 5136 | Security | AD Object Modified | T1484 |
| 1102 | Security | Audit Log Cleared | T1070 |
| 4104 | PowerShell | Script Block Logging | T1059.001 |
| 1 | Sysmon | Process Creation | All |
| 3 | Sysmon | Network Connection | T1049 |
| 7 | Sysmon | Image Loaded | T1055 |
| 8 | Sysmon | CreateRemoteThread | T1055 |
| 10 | Sysmon | ProcessAccess | T1003 |
| 11 | Sysmon | FileCreate | T1105 |
| 12-14 | Sysmon | Registry Events | T1546, T1547 |
| 15 | Sysmon | FileCreateStreamHash | T1564 |
