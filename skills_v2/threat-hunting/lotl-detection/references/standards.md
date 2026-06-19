# Standards Reference

## MITRE ATT&CK Techniques
- T1059.003: Windows Command Shell - cmd.exe script execution
- T1059.001: PowerShell - Fileless script execution
- T1218.005: Mshta - HTML Application execution
- T1218.010: Regsvr32 - COM scriptlet execution
- T1218.011: Rundll32 - DLL execution from suspicious locations
- T1047: WMI - Windows Management Instrumentation for execution
- T1197: BITS Jobs - Background Intelligent Transfer Service abuse

## LOLBins Database References
- LOLBAS Project: https://lolbas-project.github.io
- GTFOBins (Linux): https://gtfobins.github.io
- LOLDrivers: https://www.loldrivers.io

## Common LOLBins
| Binary | ATT&CK | Use Case | Detection |
|--------|--------|----------|-----------|
| certutil.exe | T1140 | File download/decode | Command-line URL patterns |
| mshta.exe | T1218.005 | HTA script execution | Child process from Office |
| regsvr32.exe | T1218.010 | COM scriptlet execution | Command-line scrobj.dll |
| rundll32.exe | T1218.011 | JS execution, DLL load | Suspicious DLL paths |
| wmic.exe | T1047 | Process create, lateral | Remote WMI queries |
| bitsadmin.exe | T1197 | File download, upload | BITS job creation |
