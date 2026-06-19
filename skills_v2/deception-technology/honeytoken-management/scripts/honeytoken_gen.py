#!/usr/bin/env python3
"""Honeytoken generation and deployment tool."""
import os
import json
import uuid
import hashlib
import base64
from datetime import datetime

class HoneytokenGenerator:
    def __init__(self, namespace: str = "corp"):
        self.namespace = namespace
        self.tokens = []

    def generate_dns_token(self, domain: str = "canary.local") -> dict:
        token_id = str(uuid.uuid4())
        subdomain = f"{token_id[:8]}.{domain}"
        return {
            "type": "dns",
            "token_id": token_id,
            "value": subdomain,
            "created": datetime.utcnow().isoformat()
        }

    def generate_credential_token(self, service: str = "aws") -> dict:
        if service == "aws":
            access_key = f"AKIA{base64.b32encode(os.urandom(20)).decode()[:20]}"
            secret_key = base64.b64encode(os.urandom(30)).decode()
            return {"type": "aws_key", "access_key": access_key, "secret_key": secret_key}
        elif service == "sql":
            return {"type": "sql_conn", "server": "db-prod-01",
                    "database": "customers", "user": f"svc_{uuid.uuid4().hex[:8]}",
                    "password": base64.b64encode(os.urandom(16)).decode()}

    def generate_file_token(self, filename: str = "passwords.xlsx") -> dict:
        token_id = str(uuid.uuid4())
        content = f"TokenID: {token_id}\nDNS: {token_id[:8]}.alert.local\n"
        return {
            "type": "file",
            "token_id": token_id,
            "filename": filename,
            "content": content,
            "md5": hashlib.md5(content.encode()).hexdigest()
        }

    def deploy(self, tokens: list, output_dir: str = "./honeytokens"):
        os.makedirs(output_dir, exist_ok=True)
        manifest = []
        for t in tokens:
            if t["type"] == "file":
                path = os.path.join(output_dir, t["filename"])
                with open(path, "w") as f:
                    f.write(t["content"])
            manifest.append(t)
        with open(os.path.join(output_dir, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)
        return manifest

if __name__ == "__main__":
    gen = HoneytokenGenerator()
    tokens = [gen.generate_dns_token(), gen.generate_credential_token("aws"),
              gen.generate_credential_token("sql"), gen.generate_file_token()]
    gen.deploy(tokens)
    print(json.dumps(tokens, indent=2))
