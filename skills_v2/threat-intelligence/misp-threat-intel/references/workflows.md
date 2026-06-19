# Deep Technical Procedures

## MISP API Operations

### Authentication and Event Creation
```python
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
import json

misp = ExpandedPyMISP('https://misp.local', 'YOUR_API_KEY', ssl=True)

# Create new event
event = MISPEvent()
event.info = 'Suspicious C2 Infrastructure from Incident IR-2024-047'
event.threat_level_id = 2
event.analysis = 1
event.distribution = 1

event = misp.add_event(event, pythonify=True)

# Add attributes
attr = MISPAttribute()
attr.category = 'Network activity'
attr.type = 'ip-dst'
attr.value = '185.234.72.18'
attr.to_ids = True
attr.comment = 'C2 server observed in incident'
misp.add_attribute(event, attr)

# Add tag
misp.tag(event, 'tlp:amber')
misp.tag(attr, 'cfr-suspected-victim:target="financial"')
```

### Search and Export
```python
# Search events by tag and date
events = misp.search_index(
    tags=['tlp:amber', 'ransomware'],
    datefrom='2024-01-01',
    limit=50
)

# Export as STIX
stix_output = misp.export_all(return_format='json')
with open('misp_export.json', 'w') as f:
    json.dump(stix_output, f)
```

## Object Templates

```python
# Create domain-ip object
from pymisp import MISPEvent, MISPObject

event = misp.get_event('1234')
obj = MISPObject('domain-ip')
obj.add_attribute('domain', {'value': 'evil.example.com', 'type': 'domain'})
obj.add_attribute('ip', {'value': '10.20.30.40', 'type': 'ip-dst', 'category': 'Network activity'})
obj.add_reference(attr1, 'resolves-to')
misp.add_object(event, obj)
```

## Correlation Analysis

```python
def analyze_correlations(misp, event_id):
    event = misp.get_event(event_id)
    correlation_count = sum(len(attr.get('RelatedAttributes', [])) for attr in event['Event']['Attribute'])
    return {
        'event_id': event_id,
        'info': event['Event']['info'],
        'total_attributes': len(event['Event']['Attribute']),
        'correlation_count': correlation_count,
        'correlation_rate': round(correlation_count / len(event['Event']['Attribute']) * 100, 2)
    }
```
