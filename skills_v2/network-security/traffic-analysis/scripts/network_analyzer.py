#!/usr/bin/env python3
"""Network Traffic Analyzer - PCAP and NetFlow Analysis"""
import argparse
import json
import pandas as pd
import numpy as np

class TrafficAnalyzer:
    def __init__(self, log_dir=None):
        self.log_dir = log_dir
        self.conn_log = None
        self.dns_log = None
        self.ssl_log = None
        self.findings = []

    def load_zeek_logs(self):
        if not self.log_dir:
            return
        try:
            self.conn_log = pd.read_csv(f'{self.log_dir}/conn.log', sep='\t', comment='#', low_memory=False)
            self.dns_log = pd.read_csv(f'{self.log_dir}/dns.log', sep='\t', comment='#', low_memory=False)
            self.ssl_log = pd.read_csv(f'{self.log_dir}/ssl.log', sep='\t', comment='#', low_memory=False)
        except FileNotFoundError as e:
            print(f"Could not load logs: {e}")

    def detect_beacons(self):
        if self.conn_log is None:
            return []
        pairs = self.conn_log.groupby(['id.orig_h', 'id.resp_h', 'id.resp_p'])
        beacons = []
        for (src, dst, port), group in pairs:
            if len(group) < 15:
                continue
            times = pd.to_numeric(group['ts'], errors='coerce').dropna().values
            if len(times) < 5:
                continue
            intervals = np.diff(times)
            cv = np.std(intervals) / np.mean(intervals) if np.mean(intervals) > 0 else 99
            if cv < 0.25:
                beacons.append({'source': src, 'destination': dst, 'port': port,
                                'count': len(group), 'cv': round(cv, 3)})
        return beacons

    def detect_dns_anomalies(self):
        if self.dns_log is None:
            return []
        anomalies = []
        for _, row in self.dns_log.iterrows():
            query = str(row.get('query', ''))
            if len(query) > 100:
                anomalies.append({'query': query, 'type': 'long_domain', 'length': len(query)})
            if query.endswith('.xyz') or query.endswith('.top'):
                anomalies.append({'query': query, 'type': 'suspicious_tld'})
        return anomalies

    def analyze(self):
        self.load_zeek_logs()
        beacons = self.detect_beacons()
        dns_anomalies = self.detect_dns_anomalies()
        return {
            'beacon_candidates': beacons,
            'dns_anomalies': dns_anomalies,
            'summary': {
                'beacons_found': len(beacons),
                'dns_anomalies_found': len(dns_anomalies)
            }
        }

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-dir', required=True, help='Directory with Zeek logs')
    args = parser.parse_args()
    analyzer = TrafficAnalyzer(args.log_dir)
    print(json.dumps(analyzer.analyze(), indent=2))
