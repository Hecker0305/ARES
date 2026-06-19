# Standards Reference

## Volatility 3 Plugins
| Plugin | Purpose | Key Output |
|--------|---------|------------|
| windows.pslist | List active processes | PID, PPID, name, create time |
| windows.psscan | Scan for hidden processes | Offset, PID, name |
| windows.psxview | Cross-reference process lists | PIDs in each list |
| windows.pstree | Process tree visualization | Hierarchy with indentation |
| windows.netscan | Network connections | Local/remote IP:port, PID, protocol |
| windows.malfind | Detect injected code | VAD tag, hex dump, disassembly |
| windows.dumpfiles | Extract files from memory | File contents as binary |
| windows.modscan | Kernel modules | Base address, name, size |
| windows.cmdline | Process command lines | Full command-line arguments |
| windows.envars | Environment variables | All process environment vars |
| windows.registry | Registry hive analysis | Hive paths, keys |
| windows.timeliner | Timeline creation | All events sorted by time |

## Memory Artifact Locations
| Evidence Type | Windows Location | Volatility Plugin |
|---------------|-----------------|-------------------|
| Prefetch files | C:\Windows\Prefetch | windows.filescan |
| UserAssist | NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist | windows.registry |
| Shimcache | SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache | windows.registry |
| Amcache | C:\Windows\AppCompat\Programs\Amcache.hve | windows.registry |
| MFT | $MFT file | windows.mftscan |
| Event Logs | C:\Windows\System32\winevt\Logs | windows.evtx |

## Memory Acquisition Tools
| Tool | Platform | Format | Notes |
|------|----------|--------|-------|
| WinPmem | Windows | AFF4, raw | Open source, kernel driver |
| DumpIt | Windows | raw | Simple usage, no install |
| FTK Imager | Windows | E01, raw | Commercial, GUI |
| LiME | Linux | lime, raw | Loadable kernel module |
| AVML | Linux | raw | Chrome OS tool |
| macOS PMap | macOS | raw | Built-in, root required |

## References
- Volatility 3: https://github.com/volatilityfoundation/volatility3
- Volatility Workbench: https://www.osforensics.com/tools/volatility-workbench.html
- SANS Memory Forensics: https://www.sans.org/cyber-security-courses/memory-forensics/
- The Art of Memory Forensics (Wiley, 2016)
