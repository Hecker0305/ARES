#!/usr/bin/env python3
"""Phishing incident response analysis and IOC extraction."""
import re
import json
import hashlib
import requests
from email import policy
from email.parser import BytesParser

class PhishAnalyzer:
    def __init__(self, raw_email: bytes):
        self.msg = BytesParser(policy=policy.default).parsebytes(raw_email)
        self.iocs = {"urls": [], "hashes": [], "domains": [], "senders": []}

    def extract_headers(self) -> dict:
        headers = {}
        for k in ["From", "To", "Subject", "Date", "Message-ID",
                   "Return-Path", "Reply-To", "Authentication-Results",
                   "Received-SPF", "DKIM-Signature"]:
            headers[k] = self.msg.get(k, "")
        return headers

    def extract_urls(self) -> list:
        url_pattern = re.compile(r'https?://[^\s<>"\'"]+|href="([^"]+)"', re.I)
        for part in self.msg.walk():
            if part.get_content_type() == "text/html":
                self.iocs["urls"] = url_pattern.findall(str(part))
        return self.iocs["urls"]

    def extract_attachments(self) -> list:
        attachments = []
        for part in self.msg.walk():
            if part.get_content_disposition() == "attachment":
                data = part.get_payload(decode=True)
                if data:
                    h = hashlib.sha256(data).hexdigest()
                    attachments.append({
                        "filename": part.get_filename(),
                        "sha256": h,
                        "size": len(data)
                    })
                    self.iocs["hashes"].append(h)
        return attachments

    def check_virustotal(self, api_key: str, resource: str) -> dict:
        url = f"https://www.virustotal.com/api/v3/files/{resource}"
        headers = {"x-apikey": api_key}
        resp = requests.get(url, headers=headers, timeout=30)
        return resp.json() if resp.ok else {}

    def generate_report(self) -> dict:
        return {
            "headers": self.extract_headers(),
            "iocs": self.iocs,
            "attachments": self.extract_attachments(),
            "verdict": "malicious" if len(self.iocs["urls"]) > 0 or len(self.iocs["hashes"]) > 0 else "clean"
        }

if __name__ == "__main__":
    import sys
    with open(sys.argv[1], "rb") as f:
        analyzer = PhishAnalyzer(f.read())
    print(json.dumps(analyzer.generate_report(), indent=2))
