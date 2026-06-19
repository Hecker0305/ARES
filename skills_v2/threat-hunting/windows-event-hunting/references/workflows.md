# Deep Technical Procedures

## Active Directory Compromise Detection

### Kerberoasting Detection (Event ID 4769)
```spl
index=windows EventCode=4769
| search TicketOptions=0x40810000 TicketEncryptionType=0x17
| eval is_kerberoast = if(TicketEncryptionType=0x17 AND ServiceName!="krbtgt/*", "SUSPICIOUS", "NORMAL")
| where is_kerberoast="SUSPICIOUS"
| stats count by AccountName, ServiceName, ClientAddress, _time
| where count > 5
```

### DCSync Detection (Event ID 4662)
```spl
index=windows EventCode=4662
| search AccessMask=0x100 PropertyGUID!="00000000-0000-0000-0000-000000000000"
| lookup domain-objects.csv ObjectDN as ObjectName OUTPUT ObjectType
| where ObjectType="domain" AND AccessMask="0x100"
| table _time, SubjectUserName, ObjectName, AccessMask
```

### Pass-the-Hash Detection
```spl
index=windows EventCode=4624 LogonType=3
| search AccountName!="ANONYMOUS LOGON" AND AccountName!="SYSTEM"
| join type=left AccountName [search index=windows EventCode=4624 LogonType=2 | dedup AccountName | table AccountName, WorkstationName]
| where LogonProcessName="NtLmSsp" OR LogonProcessName="Kerberos"
| table _time, AccountName, SourceWorkstation, WorkstationName, LogonProcessName
```

## PowerShell Hunting

```powershell
# Find encoded PowerShell commands
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |
  Where-Object { $_.Message -match '-enc' -or $_.Message -match '\[Convert\]::FromBase64String' -or $_.Message.Length -gt 2000 } |
  Select-Object TimeCreated, UserID, Message

# Detect PowerShell download cradle
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |
  Where-Object { $_.Message -match 'System.Net.WebClient' -or $_.Message -match 'Invoke-WebRequest' -or $_.Message -match 'Invoke-RestMethod' } |
  Select-Object TimeCreated, UserID, Message
```

## Sysmon Process Tree Analysis

```xml
<!-- Detect anomalous process chains -->
<RuleGroup name="Suspicious Process Chains">
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">rundll32.exe</CommandLine>
    <ParentImage condition="contains">winword.exe</ParentImage>
  </ProcessCreate>
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">powershell.exe</CommandLine>
    <ParentImage condition="contains">excel.exe</ParentImage>
  </ProcessCreate>
</RuleGroup>
```
