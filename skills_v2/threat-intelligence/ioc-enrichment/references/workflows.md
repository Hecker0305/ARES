# Deep Technical Procedures

## IOC Parser and Classifier

```python
import re
import hashlib
from typing import Tuple, Optional

class IOCParser:
    PATTERNS = {
        'ipv4': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
        'ipv6': r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$',
        'domain': r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$',
        'md5': r'^[a-fA-F0-9]{32}$',
        'sha1': r'^[a-fA-F0-9]{40}$',
        'sha256': r'^[a-fA-F0-9]{64}$',
        'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    }

    def classify(self, ioc: str) -> Tuple[str, str]:
        """Classify IOC and return normalized value"""
        ioc = ioc.strip()
        for ioc_type, pattern in self.PATTERNS.items():
            if re.match(pattern, ioc):
                normalized = self.normalize(ioc, ioc_type)
                return ioc_type, normalized
        return 'unknown', ioc

    def normalize(self, ioc: str, ioc_type: str) -> str:
        if ioc_type in ('md5', 'sha1', 'sha256'):
            return ioc.lower()
        if ioc_type == 'domain':
            return ioc.lower()
        return ioc
```

## Composite Scoring Engine

```python
class CompositeScore:
    SOURCE_WEIGHTS = {
        'virustotal': 0.25,
        'abuseipdb': 0.20,
        'alienvault': 0.20,
        'shodan': 0.15,
        'urlscan': 0.10,
        'ibm_xforce': 0.10,
    }

    def calculate(self, source_scores: dict) -> dict:
        weighted_score = 0.0
        total_weight = 0.0
        source_reports = []

        for source, score_data in source_scores.items():
            weight = self.SOURCE_WEIGHTS.get(source, 0.1)
            weighted_score += score_data['score'] * weight
            total_weight += weight
            if score_data.get('malicious', False):
                source_reports.append(source)

        final_score = weighted_score / total_weight if total_weight > 0 else 0

        if final_score >= 0.7 and len(source_reports) >= 2:
            verdict = 'Malicious'
        elif final_score >= 0.4:
            verdict = 'Suspicious'
        else:
            verdict = 'Unknown'

        return {'score': round(final_score, 2), 'verdict': verdict}
```

## Cache Strategy

```python
import redis
from datetime import timedelta

class IOCCache:
    def __init__(self, host='localhost', port=6379, ttl=3600):
        self.client = redis.Redis(host=host, port=port)
        self.ttl = ttl

    def get(self, ioc_key: str) -> Optional[dict]:
        cached = self.client.get(f'ioc:{ioc_key}')
        return json.loads(cached) if cached else None

    def set(self, ioc_key: str, enrichment: dict):
        self.client.setex(f'ioc:{ioc_key}', self.ttl, json.dumps(enrichment))
```
