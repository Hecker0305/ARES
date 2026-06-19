#!/usr/bin/env python3
"""Firewall Rule Base Auditor"""
import argparse
import json
import csv
import ipaddress
from typing import List, Dict

class FirewallAuditor:
    def __init__(self, rule_file: str):
        self.rules = []
        self.findings = []
        self._load_rules(rule_file)

    def _load_rules(self, filepath):
        with open(filepath) as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.rules.append(row)

    def check_overly_permissive(self):
        for idx, rule in enumerate(self.rules):
            if rule['source'] in ('any', '0.0.0.0/0') and rule['destination'] in ('any', '0.0.0.0/0'):
                self.findings.append({
                    'type': 'overly_permissive',
                    'rule': idx + 1,
                    'name': rule.get('name', 'Unnamed'),
                    'detail': 'Source AND destination are any',
                    'severity': 'CRITICAL'
                })

    def check_unused_rules(self, hit_counts: Dict[str, int]):
        for idx, rule in enumerate(self.rules):
            rule_key = f"{rule.get('name', '')}_{idx}"
            hits = hit_counts.get(rule_key, 0)
            if hits == 0 and rule.get('action', 'deny').lower() == 'allow':
                self.findings.append({
                    'type': 'unused_rule',
                    'rule': idx + 1,
                    'name': rule.get('name', 'Unnamed'),
                    'days_without_hits': 'Unknown',
                    'severity': 'MEDIUM'
                })

    def find_rule_gaps(self, traffic_flows: List[Dict]):
        for flow in traffic_flows:
            matched = False
            for rule in self.rules:
                if (self._cidr_match(flow['src'], rule['source']) and
                    self._cidr_match(flow['dst'], rule['destination']) and
                    flow['service'] == rule.get('service', 'any') and
                    rule.get('action', 'allow').lower() == 'allow'):
                    matched = True
                    break
            if not matched:
                self.findings.append({
                    'type': 'rule_gap',
                    'flow': flow,
                    'severity': 'HIGH'
                })

    def _cidr_match(self, ip_str, cidr_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            net = ipaddress.ip_network(cidr_str, strict=False)
            return ip in net
        except:
            return False

    def audit(self):
        self.check_overly_permissive()
        return {'rules_count': len(self.rules), 'findings': self.findings,
                'critical': sum(1 for f in self.findings if f['severity'] == 'CRITICAL'),
                'high': sum(1 for f in self.findings if f['severity'] == 'HIGH'),
                'medium': sum(1 for f in self.findings if f['severity'] == 'MEDIUM')}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--rules', required=True, help='CSV with columns: name,source,destination,service,action')
    args = parser.parse_args()
    auditor = FirewallAuditor(args.rules)
    print(json.dumps(auditor.audit(), indent=2))
