#!/usr/bin/env python3
"""Run Slither analysis on Solidity contracts."""
import subprocess
import json
import sys
from pathlib import Path

def run_slither(contract_path: str, output_dir: str = "./slither_output"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    cmd = [
        "slither",
        contract_path,
        "--json", f"{output_dir}/results.json",
        "--print", "human-summary",
        "--fail-pedantic"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "output_path": f"{output_dir}/results.json"
    }

def parse_results(json_path: str) -> dict:
    with open(json_path) as f:
        data = json.load(f)
    findings = []
    for desc in data.get("detectors", []):
        findings.append({
            "check": desc["check"],
            "impact": desc["impact"],
            "confidence": desc["confidence"],
            "description": desc["description"],
            "elements": len(desc.get("elements", []))
        })
    return {"findings": findings, "total": len(findings)}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python slither_runner.py <contract.sol>")
        sys.exit(1)
    output = run_slither(sys.argv[1])
    print(json.dumps(parse_results(output["output_path"]), indent=2))
