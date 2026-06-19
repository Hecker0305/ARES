#!/usr/bin/env python3
"""Living-off-the-Land Binary Abuse Hunter"""
import json
import argparse
import re
from datetime import datetime
import pandas as pd

class LotLHunter:
    LOLBIN_SIGNATURES = {
        'certutil': {
            'suspicious_patterns': [r'-urlcache\s+-[splif]+\s+\w+://', r'-decode\s+\w+\.(txt|b64|dat)'],
            'severity': 'HIGH',
            'technique': 'T1140'
        },
        'regsvr32': {
            'suspicious_patterns': [r'scrobj\.dll'],
            'severity': 'CRITICAL',
            'technique': 'T1218.010'
        },
        'mshta': {
            'suspicious_patterns': [r'\w+://', r'javascript:', r'vbscript:'],
            'severity': 'HIGH',
            'technique': 'T1218.005'
        },
        'rundll32': {
            'suspicious_patterns': [r'javascript:', r'http://', r'https://', r'\\\\(192\.168|10\.|172\.)'],
            'severity': 'HIGH',
            'technique': 'T1218.011'
        }
    }

    def __init__(self, log_file):
        self.logs = pd.read_csv(log_file) if log_file else pd.DataFrame()
        self.alerts = []

    def analyze_process_creation(self, row):
        image = row.get('Image', '').lower()
        command = row.get('CommandLine', '')

        for lolbin, config in self.LOLBIN_SIGNATURES.items():
            if lolbin in image:
                for pattern in config['suspicious_patterns']:
                    if re.search(pattern, command, re.IGNORECASE):
                        self.alerts.append({
                            'timestamp': row.get('_time', datetime.now().isoformat()),
                            'host': row.get('host', 'unknown'),
                            'user': row.get('User', 'unknown'),
                            'lolbin': lolbin,
                            'technique': config['technique'],
                            'severity': config['severity'],
                            'command': command
                        })
                        break

    def run(self):
        for _, row in self.logs.iterrows():
            self.analyze_process_creation(row)
        return json.dumps(self.alerts, indent=2)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-file', help='CSV file with process creation events')
    args = parser.parse_args()
    hunter = LotLHunter(args.log_file)
    print(hunter.run())
