# Deep Technical Procedures

## Diamond Model Analysis

```python
class DiamondModel:
    def __init__(self, event_data):
        self.adversary = {}
        self.capabilities = []
        self.infrastructure = []
        self.victims = []
        self.relationships = []

    def add_capability(self, name, malware_type, techniques, confidence):
        cap = {
            'name': name,
            'type': malware_type,
            'techniques': techniques,
            'confidence': confidence
        }
        self.capabilities.append(cap)

    def add_infrastructure(self, indicator_type, value, provider, first_seen, last_seen):
        infra = {
            'type': indicator_type,
            'value': value,
            'provider': provider,
            'first_seen': first_seen,
            'last_seen': last_seen
        }
        self.infrastructure.append(infra)

    def calculate_confidence(self):
        scores = []
        if self.capabilities:
            scores.append(sum(c['confidence'] for c in self.capabilities) / len(self.capabilities))
        if self.infrastructure:
            unique_infra = len(set(i['provider'] for i in self.infrastructure))
            scores.append(min(unique_infra / 3, 1.0) * 0.8)
        return sum(scores) / len(scores) if scores else 0.0
```

## Infrastructure Pivoting

```python
import requests

class InfrastructureAnalysis:
    def __init__(self, api_keys):
        self.api_keys = api_keys

    def pivot_on_ip(self, ip_address):
        """Pivot analysis from known IOC to discover related infrastructure"""
        results = {'ip': ip_address, 'passive_dns': [], 'ssl_certs': [], 'asn': None}

        # Query VirusTotal passive DNS
        vt_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/resolutions'
        headers = {'x-apikey': self.api_keys.get('virustotal')}
        try:
            response = requests.get(vt_url, headers=headers, timeout=10)
            for item in response.json().get('data', []):
                results['passive_dns'].append(item['attributes']['host_name'])
        except:
            pass

        # Query Shodan for services and SSL certs
        shodan_url = f'https://api.shodan.io/shodan/host/{ip_address}?key={self.api_keys.get("shodan")}'
        try:
            response = requests.get(shodan_url, timeout=10)
            data = response.json()
            results['asn'] = data.get('asn')
            results['ports'] = data.get('ports', [])
        except:
            pass

        return results
```

## TTP Mapping Matrix

```python
def map_ttp_to_mitre(ttp_observations):
    """Map observed TTPs to MITRE ATT&CK techniques with frequency"""
    mapping = {}
    for obs in ttp_observations:
        technique_id = obs.get('technique_id')
        if not technique_id:
            continue
        if technique_id not in mapping:
            mapping[technique_id] = {
                'count': 0,
                'sources': set(),
                'first_seen': None,
                'last_seen': None
            }
        mapping[technique_id]['count'] += 1
        mapping[technique_id]['sources'].add(obs.get('source', 'unknown'))
    return mapping
```
