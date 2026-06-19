#!/usr/bin/env python3
"""Automate T-Pot honeypot deployment and monitoring."""
import subprocess
import json
import sys
import requests
from datetime import datetime

class HoneypotManager:
    def __init__(self, tpot_api_url: str = "http://localhost:64297"):
        self.api = tpot_api_url

    def deploy_cowrie(self, listen_port: int = 2222) -> bool:
        cmd = ["docker", "run", "-d", "--name", "cowrie",
               "-p", f"{listen_port}:2222",
               "--restart", "unless-stopped",
               "cowrie/cowrie:latest"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0

    def check_honeypot_status(self) -> dict:
        cmd = ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        status = {}
        for line in result.stdout.strip().split("\n"):
            parts = line.split("\t")
            if len(parts) == 2:
                status[parts[0]] = parts[1]
        return status

    def get_recent_attacks(self, minutes: int = 60) -> list:
        try:
            resp = requests.get(f"{self.api}/attacks?minutes={minutes}", timeout=10)
            return resp.json() if resp.ok else []
        except Exception as e:
            print(f"API error: {e}")
            return []

    def generate_alerts(self, threshold: int = 5) -> list:
        attacks = self.get_recent_attacks(30)
        if len(attacks) >= threshold:
            return [{"alert": "high_attack_volume",
                     "count": len(attacks),
                     "timestamp": datetime.utcnow().isoformat()}]
        return []

if __name__ == "__main__":
    mgr = HoneypotManager()
    print(json.dumps(mgr.check_honeypot_status(), indent=2))
