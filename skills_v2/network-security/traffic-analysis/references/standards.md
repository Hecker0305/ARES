# Standards Reference

## Zeek Log Types
| Log File | Description | Key Fields |
|----------|-------------|------------|
| conn.log | Connection summary | src_ip, dst_ip, proto, service, duration, bytes |
| dns.log | DNS queries/responses | query, qtype, answers, rcode |
| http.log | HTTP requests | method, host, uri, user_agent, status_code |
| ssl.log | TLS handshake | server_name, version, cipher, certificate |
| smtp.log | Email transactions | mailfrom, rcptto, subject |
| files.log | File extraction | filename, mime_type, md5, sha1 |

## Wireshark Display Filters
| Filter | Description |
|--------|-------------|
| `tcp.port == 443` | HTTPS traffic only |
| `tcp.flags.syn == 1 and tcp.flags.ack == 0` | New TCP connections |
| `http.request` | All HTTP requests |
| `dns.qry.name contains ".xyz"` | Suspicious TLD queries |
| `tls.handshake.type == 1` | TLS Client Hello messages |
| `ip.src == 10.0.0.0/8` | Traffic from internal network |
| `tcp.analysis.retransmission` | TCP retransmissions |

## Beacon Detection Metrics
- **Periodicity**: Standard deviation of inter-packet arrival < 1s
- **Payload Size**: Consistent payload size (+/- 10%)
- **Duration**: Connection duration consistently < 5s
- **Volume**: Low number of bytes per connection (< 1KB)
- **Timing**: Connections at regular intervals (e.g., every 60s)

## References
- Zeek Documentation: https://docs.zeek.org
- Wireshark Display Filters: https://www.wireshark.org/docs/dfref/
- SANS Network Forensics: https://www.sans.org/cyber-security-courses/network-forensics/
- Netscout Security: https://www.netscout.com/security
