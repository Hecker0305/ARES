#!/usr/bin/env python3
"""Threat Actor Profiling Engine"""
import json
import argparse
from datetime import datetime
from typing import Dict, List

class ThreatActorProfile:
    def __init__(self, name: str, aliases: List[str] = None):
        self.name = name
        self.aliases = aliases or []
        self.motivation = ""
        self.sophistication = ""
        self.techniques = {}
        self.malware = []
        self.infrastructure = []
        self.targeting = {'sectors': [], 'geographies': []}
        self.attribution_confidence = 0.0

    def add_technique(self, technique_id: str, technique_name: str, frequency: str, evidence: str):
        self.techniques[technique_id] = {
            'name': technique_name,
            'frequency': frequency,
            'evidence': evidence,
            'tactic': self._get_tactic_from_id(technique_id)
        }

    def add_malware(self, name: str, family: str, capabilities: List[str]):
        self.malware.append({
            'name': name,
            'family': family,
            'capabilities': capabilities
        })

    def add_infrastructure(self, ioc_type: str, value: str, provider: str, first_seen: str):
        self.infrastructure.append({
            'type': ioc_type,
            'value': value,
            'provider': provider,
            'first_seen': first_seen
        })

    def _get_tactic_from_id(self, technique_id: str) -> str:
        tactic_map = {
            'T1': 'Initial Access', 'T2': 'Execution',
            'T3': 'Persistence', 'T4': 'Privilege Escalation',
            'T5': 'Defense Evasion', 'T6': 'Credential Access',
            'T7': 'Discovery', 'T8': 'Lateral Movement',
            'T9': 'Collection', 'T10': 'Command and Control',
            'T11': 'Exfiltration', 'T12': 'Impact'
        }
        prefix = technique_id[:2]
        return tactic_map.get(prefix, 'Unknown')

    def calculate_confidence(self) -> float:
        score = 0.0
        if len(self.techniques) >= 5:
            score += 0.3
        if len(self.malware) >= 1:
            score += 0.2
        if len(self.infrastructure) >= 3:
            score += 0.3
        if self.targeting['sectors']:
            score += 0.2
        return score

    def to_json(self) -> str:
        profile = {
            'name': self.name,
            'aliases': self.aliases,
            'motivation': self.motivation,
            'sophistication': self.sophistication,
            'attribution_confidence': self.calculate_confidence(),
            'techniques': self.techniques,
            'malware': self.malware,
            'infrastructure': self.infrastructure,
            'targeting': self.targeting
        }
        return json.dumps(profile, indent=2)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', required=True, help='Actor name')
    parser.add_argument('--aliases', help='Comma-separated aliases')
    parser.add_argument('--output', default='actor_profile.json')
    args = parser.parse_args()
    profile = ThreatActorProfile(args.name, args.aliases.split(',') if args.aliases else [])
    print(profile.to_json())
