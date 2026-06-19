#!/usr/bin/env python3
"""IDS/IPS Rule Generator and Analyzer"""
import argparse
import json
import datetime

class SnortRuleGenerator:
    def __init__(self):
        self.sid_counter = 1000000
        self.rules = []

    def generate_c2_rule(self, src_network, dst_network, user_agent, interval_seconds=60):
        self.sid_counter += 1
        rule = (
            f"alert tcp {src_network} any -> {dst_network} any ("
            f"msg:\"C2 Beacon - {user_agent[:20]} Check-in\";"
            f"flow:to_server,established;"
            f"content:\"User-Agent: {user_agent}\";"
            f"threshold:type both, track by_src, count 5, seconds {interval_seconds};"
            f"sid:{self.sid_counter}; rev:1; priority:1;"
            f"classtype:trojan-activity;)"
        )
        self.rules.append(rule)
        return rule

    def generate_malware_download(self, src_network, file_hash, malware_family):
        self.sid_counter += 1
        rule = (
            f"alert http {src_network} any -> any any ("
            f"msg:\"ET Malware - {malware_family} Download ({file_hash[:16]})\";"
            f"flow:to_client,established;"
            f"file_data;"
            f"content:\"{'|' + '|'.join(file_hash[i:i+2] for i in range(0, len(file_hash), 2))}\";"
            f"sid:{self.sid_counter}; rev:1; priority:1;"
            f"reference:url,virustotal.com/gui/file/{file_hash};"
            f"classtype:trojan-activity;)"
        )
        self.rules.append(rule)
        return rule

    def export_rules(self, filename):
        header = f"# Custom Rules - Generated {datetime.datetime.now()}\n"
        header += "# Author: ARES Team\n\n"
        with open(filename, 'w') as f:
            f.write(header)
            f.write('\n'.join(self.rules))
        return filename

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='custom.rules')
    args = parser.parse_args()
    gen = SnortRuleGenerator()
    gen.generate_c2_rule('$HOME_NET', '$EXTERNAL_NET', 'Mozilla/5.0 (Windows NT 10.0)', 60)
    gen.generate_malware_download('$HOME_NET', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'AgentTesla')
    gen.export_rules(args.output)
    print(json.dumps({'rules_generated': len(gen.rules), 'file': args.output}))
