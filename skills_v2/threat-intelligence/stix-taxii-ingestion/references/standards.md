# Standards Reference

## STIX 2.1 Domain Objects
- **Indicator**: Observable patterns with confidence, valid_from/until
- **Attack Pattern**: TTPs mapped to MITRE ATT&CK
- **Malware**: Malware families with capabilities
- **Campaign**: Adversary campaigns
- **Intrusion Set**: Advanced persistent threat groups
- **Relationship**: Links between STIX objects (uses, indicates, targets)
- **Observed Data**: Raw observables with timestamps

## TAXII 2.1 API Endpoints
- `GET /taxii2/` - API Root discovery
- `GET /{api-root}/collections/` - Collection listing
- `GET /{api-root}/collections/{id}/objects/` - Object polling
- `POST /{api-root}/collections/{id}/objects/` - Object publishing
- `GET /{api-root}/collections/{id}/manifest/` - Object manifest

## STIX Indicator Types
| Type | Pattern | Example |
|------|---------|---------|
| File Hash | [file:hashes.MD5 = '...'] | Indicator based on file hash |
| IP Address | [ipv4-addr:value = '1.2.3.4'] | IPv4 indicator |
| Domain | [domain-name:value = 'evil.com'] | Domain indicator |
| URL | [url:value = 'http://evil.com/'] | URL indicator |
| Email | [email-addr:value = 'phish@evil.com'] | Email indicator |

## References
- STIX 2.1 Specification: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- TAXII 2.1 Specification: https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html
- MITRE CTI: https://mitre-engenuity.org/cyber-analytics/center-for-threat-intelligence/
