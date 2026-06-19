#!/usr/bin/env python3
"""STIX/TAXII 2.1 Threat Intelligence Ingestor"""
import argparse
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TAXIIngestor:
    def __init__(self, server_url, collection_id, auth_token=None):
        self.server_url = server_url.rstrip('/')
        self.collection_id = collection_id
        self.auth_token = auth_token
        self.seen_indicators = set()

    def build_collection_url(self):
        return f"{self.server_url}/collections/{self.collection_id}/objects/"

    def poll(self, added_after=None):
        import requests
        headers = {'Accept': 'application/taxii+json;version=2.1'}
        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'

        params = {}
        if added_after:
            params['added_after'] = added_after.isoformat()

        response = requests.get(
            self.build_collection_url(),
            headers=headers,
            params=params,
            timeout=30
        )
        response.raise_for_status()
        return response.json().get('objects', [])

    def process_objects(self, objects: List[Dict]):
        indicators = []
        for obj in objects:
            if obj.get('type') != 'indicator':
                continue

            pattern = obj.get('pattern', '')
            value = self.extract_value_from_pattern(pattern)
            if not value:
                continue

            dedup_key = f"{obj['id']}:{value}"
            if dedup_key in self.seen_indicators:
                continue
            self.seen_indicators.add(dedup_key)

            indicators.append({
                'stix_id': obj['id'],
                'pattern': pattern,
                'value': value,
                'confidence': obj.get('confidence', 50),
                'valid_from': obj.get('valid_from'),
                'valid_until': obj.get('valid_until'),
                'labels': obj.get('labels', []),
                'created': obj.get('created'),
                'modified': obj.get('modified')
            })
        return indicators

    def extract_value_from_pattern(self, pattern):
        import re
        patterns = [
            (r"ipv4-addr:value\s*=\s*'([^']+)'", 'ip'),
            (r"ipv6-addr:value\s*=\s*'([^']+)'", 'ipv6'),
            (r"domain-name:value\s*=\s*'([^']+)'", 'domain'),
            (r"url:value\s*=\s*'([^']+)'", 'url'),
            (r"file:hashes\.MD5\s*=\s*'([^']+)'", 'md5'),
            (r"file:hashes\.SHA-1\s*=\s*'([^']+)'", 'sha1'),
            (r"file:hashes\.SHA-256\s*=\s*'([^']+)'", 'sha256'),
        ]
        for regex, ioc_type in patterns:
            match = re.search(regex, pattern)
            if match:
                return match.group(1)
        return None

    def run(self, hours_back=1):
        added_after = datetime.utcnow() - timedelta(hours=hours_back)
        logger.info(f"Polling from {added_after.isoformat()}")
        objects = self.poll(added_after)
        logger.info(f"Retrieved {len(objects)} objects")
        indicators = self.process_objects(objects)
        logger.info(f"Extracted {len(indicators)} indicators")
        return indicators

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True, help='TAXII server URL')
    parser.add_argument('--collection', required=True, help='Collection ID')
    parser.add_argument('--token', help='Auth token')
    parser.add_argument('--hours', type=int, default=1)
    args = parser.parse_args()
    ingestor = TAXIIngestor(args.server, args.collection, args.token)
    results = ingestor.run(hours_back=args.hours)
    print(json.dumps(results, indent=2))
