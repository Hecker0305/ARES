# Standards Reference

## Snort/Suricata Rule Structure
```
action proto src_ip src_port direction dst_ip dst_port (msg:"Message"; sid:XXXXX; rev:1; classtype:xxx; priority:x; content:"pattern"; reference:url,xxx;)
```

## Common Rule Actions
| Action | Description |
|--------|-------------|
| alert | Generate alert, don't block |
| drop | Block and alert |
| reject | Send RST/ICMP unreachable |
| pass | Ignore traffic matching rule |
| sdrop | Drop silently without alert |

## Rule Categories
| Category | Rule Groups | Example SID Range |
|----------|-------------|-------------------|
| Emerging Threats | ET-compromised, ET-malware | 2800000-2899999 |
| Emerging Threats Pro | ETPRO malware, phishing | 2840000-2849999 |
| Community Rules | community-web, community-exploit | 1000000-1999999 |
| Custom Rules | local rules | 1000000-1000999 |

## Performance Tuning KPIs
- Alerts per second (APS): < 1000/s per sensor
- Packet loss: < 0.01%
- Rule match rate: < 1% for informational, < 5% for medium
- False positive rate: < 2% for high/critical rules
- Sensor CPU: < 60% average, < 80% peak

## References
- Snort Documentation: https://www.snort.org/documents
- Suricata Documentation: https://suricata.readthedocs.io
- Emerging Threats Rules: https://rules.emergingthreats.net
- Zeek Security: https://zeek.org
