#!/usr/bin/env python3
"""Insecure Deserialization Detection Toolkit"""
import argparse
import base64
import binascii
import json
import re

class DeserializationDetector:
    JAVA_MAGIC = b'\xac\xed\x00\x05'
    PYTHON_PICKLE = b'\x80\x04'
    DOTNET_MAGIC = b'\x00\x01\x00\x00\x00'

    def __init__(self, data_hex=None, data_b64=None, data_raw=None):
        self.data = None
        if data_raw:
            self.data = data_raw.encode()
        elif data_b64:
            try:
                self.data = base64.b64decode(data_b64)
            except:
                pass
        elif data_hex:
            try:
                self.data = binascii.unhexlify(data_hex)
            except:
                pass

    def detect_format(self):
        if not self.data:
            return {'error': 'No data provided'}

        result = {'detected': False, 'formats': [], 'confidence': 0}

        if self.JAVA_MAGIC in self.data[:4]:
            result['formats'].append({'format': 'Java Native Serialization', 'confidence': 'High'})
            result['detected'] = True

        if self.PYTHON_PICKLE in self.data[:2]:
            result['formats'].append({'format': 'Python Pickle (protocol 4)', 'confidence': 'High'})
            result['detected'] = True

        if self.DOTNET_MAGIC in self.data[:5]:
            result['formats'].append({'format': '.NET BinaryFormatter', 'confidence': 'High'})
            result['detected'] = True

        text_data = self.data.decode('latin-1')
        php_patterns = [
            (r'O:\d+:"[^"]+":\d+:\{', 'PHP Serialization', 'High'),
            (r'a:\d+:\{s:\d+:"[^"]+";', 'PHP Array Serialization', 'Medium'),
            (r'C:\d+:"[^"]+":\d+:\{', 'PHP Custom Serialization', 'High'),
        ]
        for pattern, fmt_name, confidence in php_patterns:
            if re.search(pattern, text_data):
                result['formats'].append({'format': fmt_name, 'confidence': confidence})
                result['detected'] = True

        yaml_patterns = [
            (r'!!python/object:', 'PyYAML Deserialization', 'High'),
            (r'!!javax.script.ScriptEngineManager', 'Java YAML Deserialization', 'High'),
        ]
        for pattern, fmt_name, confidence in yaml_patterns:
            if re.search(pattern, text_data):
                result['formats'].append({'format': fmt_name, 'confidence': confidence})
                result['detected'] = True

        result['data_preview'] = text_data[:200]
        return result

    def check_ysoserial_payloads(self):
        if not self.data:
            return []
        text_data = self.data.decode('latin-1', errors='replace')
        chains = [
            'CommonsCollections', 'Spring', 'Jackson', 'Fastjson',
            'Hibernate', 'C3P0', 'Jython', 'JBoss', 'Wicket',
            'ROME', 'BeanShell', 'Clojure'
        ]
        found = [chain for chain in chains if chain.lower() in text_data.lower()]
        return found

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--b64', help='Base64 encoded data')
    group.add_argument('--hex', help='Hex encoded data')
    group.add_argument('--raw', help='Raw serialized data string')
    args = parser.parse_args()
    detector = DeserializationDetector(data_b64=args.b64, data_hex=args.hex, data_raw=args.raw)
    result = detector.detect_format()
    result['gadget_chains'] = detector.check_ysoserial_payloads()
    print(json.dumps(result, indent=2))
