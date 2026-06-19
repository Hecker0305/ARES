# Deep Technical Procedures

## TAXII Discovery and Polling

### Discover API Root
```python
from taxii2client.v21 import Server

server = Server('https://taxii.example.com/taxii2/')
api_root = server.api_roots[0]
print(f"Title: {api_root.title}")
print(f"Description: {api_root.description}")
print(f"Collections: {len(api_root.collections)}")

for collection in api_root.collections:
    print(f"  - {collection.id}: {collection.title} ({len(collection.objects())} objects)")
```

### Poll Indicators with Added_After
```python
from taxii2client.v21 import Collection
from datetime import datetime, timedelta

collection = Collection('https://taxii.example.com/taxii2/collections/{id}/')
last_poll = datetime.utcnow() - timedelta(hours=1)

# Incremental poll
bundle = collection.get_objects(added_after=last_poll)
for obj in bundle.get('objects', []):
    if obj['type'] == 'indicator':
        process_indicator(obj)
    elif obj['type'] == 'relationship':
        process_relationship(obj)
```

## Indicator Processing Pipeline

```python
import stix2
import json
from datetime import datetime

class StixProcessor:
    def __init__(self, cache_ttl=3600):
        self.seen_hashes = set()
        self.cache_ttl = cache_ttl
        
    def extract_indicator(self, stix_obj):
        if stix_obj.get('type') != 'indicator':
            return None
            
        pattern = stix_obj.get('pattern', '')
        confidence = stix_obj.get('confidence', 50)
        valid_from = stix_obj.get('valid_from')
        valid_until = stix_obj.get('valid_until')
        
        # Parse pattern to extract observable value
        import re
        ip_match = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
        domain_match = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
        hash_match = re.search(r"file:hashes\.MD5\s*=\s*'([^']+)'", pattern)
        
        indicator = {}
        if ip_match:
            indicator = {'type': 'ip', 'value': ip_match.group(1)}
        elif domain_match:
            indicator = {'type': 'domain', 'value': domain_match.group(1)}
        elif hash_match:
            indicator = {'type': 'hash', 'value': hash_match.group(1)}
            
        indicator['confidence'] = confidence
        indicator['valid_from'] = valid_from
        indicator['valid_until'] = valid_until
        indicator['labels'] = stix_obj.get('labels', [])
        indicator['stix_id'] = stix_obj['id']
        
        return indicator
        
    def deduplicate(self, indicator):
        hash_key = f"{indicator['type']}:{indicator['value']}"
        if hash_key in self.seen_hashes:
            return False
        self.seen_hashes.add(hash_key)
        return True
```

## SIEM Integration

```python
# Splunk IOC deployment
import requests

def push_to_splunk(splunk_url, token, indicators):
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    for ind in indicators:
        payload = {
            'event': 'threat_intel',
            'fields': {
                'indicator_type': ind['type'],
                'indicator_value': ind['value'],
                'confidence': ind['confidence'],
                'source': 'taxii_ingest'
            }
        }
        requests.post(f'{splunk_url}/services/collector', json=payload, headers=headers)
```
