#!/usr/bin/env python3
"""Deploy and manage canary tokens via Canarytokens API."""
import os
import json
import requests

class CanaryTokenManager:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("CANARY_API_KEY")
        self.base_url = "https://canarytokens.org/generate"

    def create_dns_token(self, memo: str = "dns_canary") -> dict:
        resp = requests.post(self.base_url, data={"type": "dns", "memo": memo}, timeout=30)
        return resp.json() if resp.ok else {"error": resp.text}

    def create_web_token(self, memo: str = "web_canary",
                         webhook_url: str = None) -> dict:
        data = {"type": "web", "memo": memo}
        if webhook_url:
            data["webhook_url"] = webhook_url
        resp = requests.post(self.base_url, data=data, timeout=30)
        return resp.json() if resp.ok else {"error": resp.text}

    def create_aws_key_token(self, memo: str = "aws_canary") -> dict:
        resp = requests.post(self.base_url, data={"type": "aws", "memo": memo}, timeout=30)
        return resp.json() if resp.ok else {"error": resp.text}

    def list_tokens(self) -> list:
        # Canarytokens.org does not provide listing API in free tier
        # Use Thinkst Canary API instead
        return []

    def test_token(self, token_value: str) -> bool:
        """Trigger a canary token to verify alerting works."""
        try:
            resp = requests.get(f"http://{token_value}", timeout=10)
            return resp.ok
        except:
            return False

if __name__ == "__main__":
    mgr = CanaryTokenManager()
    token = mgr.create_dns_token("production_db_server_canary")
    print(json.dumps(token, indent=2))
