# Standards Reference

## IOC Types and Formats
| Type | Format | Example |
|------|--------|---------|
| IPv4 | dotted decimal | 192.0.2.1 |
| IPv6 | RFC 5952 | 2001:db8::1 |
| Domain | FQDN | evil.example.com |
| URL | RFC 3986 | https://evil.example.com/payload.exe |
| MD5 | 32 hex | d41d8cd98f00b204e9800998ecf8427e |
| SHA1 | 40 hex | da39a3ee5e6b4b0d3255bfef95601890afd80709 |
| SHA256 | 64 hex | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| Email | RFC 5322 | phish@evil.com |
| File Path | Absolute | C:\Windows\system32\evil.dll |

## Enrichment Sources
| Source | Rate Limit | Coverage | Cost |
|--------|------------|----------|------|
| VirusTotal | 4 req/min (free) | IP, Domain, URL, Hash, File | Freemium |
| AlienVault OTK | 50k req/day | IP, Domain, Hash, URL | Free |
| Shodan | 50 req/sec (free) | IP, Ports, Services | Freemium |
| AbuseIPDB | 1000 req/day | IP reputation | Free |
| URLScan | 100 req/min | Domain, URL | Free |
| IBM X-Force | 5000 req/day | IP, Domain, Hash | API key |

## Scoring Methodology
- **Malicious**: >= 2 high-confidence source detections
- **Suspicious**: 1 high-confidence source detection or >=2 medium
- **Unknown**: No source detections or insufficient data
- **Benign**: Listed in known legitimate database (Whitelist, Alexa, MISP Warninglist)
