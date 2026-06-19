#!/usr/bin/env python3
"""IOC Enrichment Engine"""
import argparse
import json
import logging
import re
import time
from datetime import datetime
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IOCEnricher:
    def __init__(self, api_keys: Dict[str, str], cache_ttl: int = 3600):
        self.api_keys = api_keys
        self.results = []
        self.cache = {}

    def enrich_ip(self, ip: str) -> Dict:
        import requests
        result = {'type': 'ip', 'value': ip, 'sources': {}}

        # VirusTotal
        vt_key = self.api_keys.get('virustotal')
        if vt_key:
            try:
                r = requests.get(
                    f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                    headers={'x-apikey': vt_key}, timeout=10
                )
                if r.status_code == 200:
                    data = r.json().get('data', {}).get('attributes', {})
                    result['sources']['virustotal'] = {
                        'reputation': data.get('reputation', 0),
                        'last_analysis': data.get('last_analysis_stats', {}),
                        'country': data.get('country'),
                        'asn': data.get('asn')
                    }
                    result['country'] = data.get('country')
                    result['asn'] = data.get('asn')
            except Exception as e:
                logger.warning(f"VT lookup failed for {ip}: {e}")

        # AbuseIPDB
        abuse_key = self.api_keys.get('abuseipdb')
        if abuse_key:
            try:
                r = requests.get(
                    f'https://api.abuseipdb.com/api/v2/check',
                    params={'ipAddress': ip, 'maxAgeInDays': '90'},
                    headers={'Key': abuse_key, 'Accept': 'application/json'},
                    timeout=10
                )
                if r.status_code == 200:
                    data = r.json().get('data', {})
                    result['sources']['abuseipdb'] = {
                        'abuse_score': data.get('abuseConfidenceScore', 0),
                        'isp': data.get('isp'),
                        'domain': data.get('domain'),
                        'usage_type': data.get('usageType'),
                        'total_reports': data.get('totalReports')
                    }
                    result['isp'] = data.get('isp')
            except Exception as e:
                logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")

        return result

    def enrich_domain(self, domain: str) -> Dict:
        import requests
        result = {'type': 'domain', 'value': domain, 'sources': {}}

        vt_key = self.api_keys.get('virustotal')
        if vt_key:
            try:
                r = requests.get(
                    f'https://www.virustotal.com/api/v3/domains/{domain}',
                    headers={'x-apikey': vt_key}, timeout=10
                )
                if r.status_code == 200:
                    data = r.json().get('data', {}).get('attributes', {})
                    result['sources']['virustotal'] = {
                        'reputation': data.get('reputation', 0),
                        'last_analysis': data.get('last_analysis_stats', {}),
                        'categories': data.get('categories', {})
                    }
            except Exception as e:
                logger.warning(f"VT domain lookup failed for {domain}: {e}")

        return result

    def enrich_hash(self, file_hash: str) -> Dict:
        import requests
        result = {'type': 'hash', 'value': file_hash, 'sources': {}}

        vt_key = self.api_keys.get('virustotal')
        if vt_key:
            try:
                hash_type = 'sha256' if len(file_hash) == 64 else ('sha1' if len(file_hash) == 40 else 'md5')
                r = requests.get(
                    f'https://www.virustotal.com/api/v3/files/{file_hash}',
                    headers={'x-apikey': vt_key}, timeout=10
                )
                if r.status_code == 200:
                    data = r.json().get('data', {}).get('attributes', {})
                    result['sources']['virustotal'] = {
                        'detection_ratio': f"{data.get('last_analysis_stats', {}).get('malicious', 0)}/{data.get('last_analysis_stats', {}).get('total', 0)}",
                        'type_description': data.get('type_description'),
                        'names': data.get('names', [])
                    }
                    result['malware_family'] = data.get('popular_threat_classification', {}).get('suggested_threat_label')
            except Exception as e:
                logger.warning(f"VT hash lookup failed for {file_hash}: {e}")

        return result

    def process_batch(self, iocs: List[str]):
        parser = re.compile
        for ioc in iocs:
            ioc = ioc.strip()
            if not ioc:
                continue
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
                self.results.append(self.enrich_ip(ioc))
            elif re.match(r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$', ioc):
                self.results.append(self.enrich_domain(ioc))
            elif re.match(r'^[a-fA-F0-9]{32,64}$', ioc):
                self.results.append(self.enrich_hash(ioc))
            time.sleep(0.5)  # Rate limiting
        return self.results

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--iocs', nargs='+', required=True, help='IOCs to enrich')
    parser.add_argument('--api-keys', help='JSON file with API keys')
    args = parser.parse_args()
    keys = {}
    if args.api_keys:
        with open(args.api_keys) as f:
            keys = json.load(f)
    enricher = IOCEnricher(keys)
    results = enricher.process_batch(args.iocs)
    print(json.dumps(results, indent=2))
