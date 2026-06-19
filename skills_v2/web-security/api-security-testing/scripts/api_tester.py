#!/usr/bin/env python3
"""REST/GraphQL API Security Tester"""
import argparse
import json
import requests
import jwt
import time
from urllib.parse import urljoin

class APISecurityTester:
    def __init__(self, base_url, auth_token=None, rate_limit=50):
        self.base = base_url.rstrip('/')
        self.session = requests.Session()
        if auth_token:
            self.session.headers['Authorization'] = f'Bearer {auth_token}'
        self.session.headers['Content-Type'] = 'application/json'
        self.rate_limit = rate_limit
        self.findings = []

    def test_authentication(self, endpoints):
        for ep in endpoints:
            resp = requests.get(urljoin(self.base, ep))
            if resp.status_code == 200:
                self.findings.append({
                    'type': 'missing_auth',
                    'endpoint': ep,
                    'status_code': resp.status_code,
                    'severity': 'HIGH'
                })

    def test_idor(self, pattern, ids=[1,2,3,100,500,1000,9999]):
        for rid in ids:
            url = f"{self.base}{pattern}/{rid}"
            resp = self.session.get(url)
            if resp.status_code == 200 and resp.text:
                self.findings.append({
                    'type': 'idor',
                    'url': url,
                    'status': resp.status_code,
                    'data_preview': resp.text[:100],
                    'severity': 'CRITICAL'
                })
                break

    def test_mass_assignment(self, endpoint, base_payload, extra_fields):
        for field, value in extra_fields.items():
            payload = {**base_payload, field: value}
            resp = self.session.post(urljoin(self.base, endpoint), json=payload)
            if resp.status_code in (200, 201):
                self.findings.append({
                    'type': 'mass_assignment',
                    'endpoint': endpoint,
                    'field': field,
                    'value': value,
                    'severity': 'MEDIUM'
                })

    def test_rate_limiting(self, endpoint, method='GET', requests_count=100):
        start = time.time()
        success_count = 0
        for _ in range(requests_count):
            resp = self.session.get(urljoin(self.base, endpoint))
            if resp.status_code == 200:
                success_count += 1
            elif resp.status_code == 429:
                self.findings.append({
                    'type': 'rate_limiting',
                    'endpoint': endpoint,
                    'requests_before_blocked': success_count,
                    'severity': 'LOW'
                })
                break
            time.sleep(0.05)
        elapsed = time.time() - start
        if success_count == requests_count:
            self.findings.append({
                'type': 'no_rate_limiting',
                'endpoint': endpoint,
                'requests_per_second': round(requests_count/elapsed, 2),
                'severity': 'MEDIUM'
            })

    def run(self):
        self.test_authentication(['/admin', '/api/users', '/api/config', '/api/admin/users'])
        self.test_rate_limiting('/api/login')
        return {'target': self.base, 'findings': self.findings}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--token')
    parser.add_argument('--rate-limit', type=int, default=50)
    args = parser.parse_args()
    tester = APISecurityTester(args.url, args.token, args.rate_limit)
    print(json.dumps(tester.run(), indent=2))
