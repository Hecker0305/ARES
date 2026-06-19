
<div align="center">

# ARES
### Autonomous Reconnaissance & Exploitation System

**An open source AI-driven web security scanner for pentesters and bug bounty hunters.**  
Point it at a target. It handles the rest.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8.svg)](https://golang.org)
[![Built by ArmourMind](https://img.shields.io/badge/Built%20by-ArmourMind-red.svg)](https://armourmind.com)

</div>

---

## What is ARES?

ARES is an autonomous penetration testing engine built on an LLM agent loop. It performs a full security assessment pipeline Ã¢ÂÂ recon, discovery, vulnerability scanning, exploitation, and reporting Ã¢ÂÂ without manual intervention at each step.

The agent decides which tool to call next based on what it finds. It chains discoveries into attack paths, confirms vulnerabilities with proof before reporting them, and stops itself from looping on dead ends.

**Works offline. No data leaves your machine.**

---

## Features

- **Autonomous LLM agent loop** Ã¢ÂÂ Recon Ã¢ÂÂ Discovery Ã¢ÂÂ VulnScan Ã¢ÂÂ Exploit Ã¢ÂÂ Report, fully automated
- **Dual LLM architecture** Ã¢ÂÂ Primary model for reasoning, attack model for payload generation
- **Offline by default** Ã¢ÂÂ Runs on Ollama (local models) with no API calls to external services
- **DOM XSS via headless browser** Ã¢ÂÂ Chromium-based detection, not just curl reflection checks
- **Scope enforcement** Ã¢ÂÂ Hard blocks on out-of-scope targets, RFC1918, cloud metadata endpoints
- **OOB callback server** Ã¢ÂÂ Built-in DNS/HTTP out-of-band listener for blind vulnerability detection
- **SARIF + PDF report output** Ã¢ÂÂ Machine-readable and human-readable reports from every scan
- **Vulnerability classes covered:**
  - SQL Injection (error-based, boolean, time-based, blind)
  - Cross-Site Scripting (reflected, stored, DOM)
  - Server-Side Request Forgery
  - XML External Entity Injection
  - Server-Side Template Injection
  - GraphQL security testing
  - JWT vulnerabilities
  - NoSQL Injection
  - HTTP Request Smuggling
  - Directory Traversal
  - Business logic flaws
  - Authentication & authorization testing
  - API security (REST, GraphQL, OpenAPI)

---

## Model Requirements

> Ã¢ÂÂ Ã¯Â¸Â **Tool calling support is REQUIRED.** The model must support native function/tool calling. Models without this capability cannot execute any tools Ã¢ÂÂ making ARES completely non-functional.

ARES requires a model with reliable tool-calling and preferably extended thinking (`<think>` blocks). Model capabilities are auto-detected at startup via Ollama metadata.

**Recommended minimum: 8B parameters.** Models below 8B are technically usable but strongly discouraged Ã¢ÂÂ they frequently hallucinate tool output, invent CVEs, skip scope rules, and produce unreliable tool calls.

### Recommended Models (Ollama)

| Model | Pull Command | VRAM | Notes |
|---|---|---|---|
| Qwen3 32B | `ollama pull qwen3:32b` | 20GB+ | Best quality, most reliable |
| Qwen3 14B | `ollama pull qwen3:14b` | 10GB+ | Recommended for most users |
| Qwen3 8B | `ollama pull qwen3:8b` | 6GB+ | Minimum viable |
| Llama 3.1 8B | `ollama pull llama3.1:8b` | 6GB+ | Alternative minimum |

### Model Size Guidance

| Size | Reliability | Use Case |
|---|---|---|
| Ã¢ÂÂ¥32B | High Ã¢ÂÂ reliable for full recon pipelines | Production use, full autonomous scans |
| 14BÃ¢ÂÂ32B | Good Ã¢ÂÂ occasional tool call errors | Most users, standard engagements |
| 8BÃ¢ÂÂ14B | Usable Ã¢ÂÂ expect 20-40% tool call errors | Simple targets, limited scope |
| <8B | Unreliable Ã¢ÂÂ not recommended | Testing ARES setup only |

### Known Model Issues

- **DeepSeek R1** Ã¢ÂÂ produces incomplete function calls, do not use
- **Models < 8B** Ã¢ÂÂ lack reliable tool calling support, will fail on complex targets
- **High temperature (>0.3)** Ã¢ÂÂ causes hallucination of tool output and CVEs, keep at 0.1Ã¢ÂÂ0.2

### Cloud API Alternative

If you don't have the hardware for a large local model:

```env
# OpenAI
ARES_LLM_PROVIDER=openai
ARES_LLM_MODEL=gpt-4o
ARES_LLM_API_KEY=sk-...

# Anthropic
ARES_LLM_PROVIDER=anthropic
ARES_LLM_MODEL=claude-sonnet-4-6
ARES_LLM_API_KEY=sk-ant-...
```

Note: cloud providers receive the target URL and tool outputs. Use local Ollama if privacy is a requirement.

---

## Quick Start

### Prerequisites

- Go 1.26+
- [Ollama](https://ollama.com) (for local models) **or** OpenAI / Anthropic API key
- `nmap`, `subfinder`, `httpx`, `nuclei`, `sqlmap` installed and in PATH
- Chrome/Chromium (for DOM XSS scanning)

### Install

```bash

git clone https://github.com/armourmind/ares.git
cd ares
go build -o ares ./cmd/ares
```

Or install directly:

```bash

go install github.com/armourmind/ares/cmd/ares@latest
```

### Configure

```bash
cp .ares.env.example .ares.env
```

Edit `.ares.env`:

```env
# Use Ollama (local, offline, free)
ARES_LLM_PROVIDER=ollama
ARES_LLM_BASE_URL=http://localhost:11434/v1
ARES_LLM_MODEL=qwen3:latest
ARES_LLM_API_KEY=

# Or use OpenAI
# ARES_LLM_PROVIDER=openai
# ARES_LLM_API_KEY=sk-...
# ARES_LLM_MODEL=gpt-4o

# Or use Anthropic
# ARES_LLM_PROVIDER=anthropic
# ARES_LLM_API_KEY=sk-ant-...
# ARES_LLM_MODEL=claude-sonnet-4-6

# Target (optional Ã¢ÂÂ can pass via CLI)
ARES_TARGET=

# OOB callback server for blind vuln detection
ARES_OOB_ENABLED=true
ARES_OOB_PORT=8181

# Web dashboard
ARES_DASH_PORT=8080
```

### Run

```bash
# CLI scan
./ares -target https://example.com

# All phases (extended scan, up to 300 iterations)
./ares -target https://example.com -all-phases

# Custom iteration limit
./ares -target https://example.com -max-iter 100

# Web dashboard (then open http://localhost:8080)
./ares
```

---

## How It Works

```
Target
  Ã¢ÂÂ
  Ã¢ÂÂ¼
Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ
Ã¢ÂÂ           ARES Agent Loop               Ã¢ÂÂ
Ã¢ÂÂ                                         Ã¢ÂÂ
Ã¢ÂÂ  Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ   Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ            Ã¢ÂÂ
Ã¢ÂÂ  Ã¢ÂÂ  LLM    Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ¶Ã¢ÂÂ  Reason  Ã¢ÂÂ            Ã¢ÂÂ
Ã¢ÂÂ  Ã¢ÂÂ (Local) Ã¢ÂÂ   Ã¢ÂÂ + Decide Ã¢ÂÂ            Ã¢ÂÂ
Ã¢ÂÂ  Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ   Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ¬Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ            Ã¢ÂÂ
Ã¢ÂÂ                     Ã¢ÂÂ                  Ã¢ÂÂ
Ã¢ÂÂ              Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ¼Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ           Ã¢ÂÂ
Ã¢ÂÂ              Ã¢ÂÂ Tool Kernel  Ã¢ÂÂ           Ã¢ÂÂ
Ã¢ÂÂ              Ã¢ÂÂ (allowlist + Ã¢ÂÂ           Ã¢ÂÂ
Ã¢ÂÂ              Ã¢ÂÂ  scope gate) Ã¢ÂÂ           Ã¢ÂÂ
Ã¢ÂÂ              Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ¬Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ           Ã¢ÂÂ
Ã¢ÂÂ                     Ã¢ÂÂ                  Ã¢ÂÂ
Ã¢ÂÂ    Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ¼Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ   Ã¢ÂÂ
Ã¢ÂÂ    Ã¢ÂÂ         Tool Execution         Ã¢ÂÂ   Ã¢ÂÂ
Ã¢ÂÂ    Ã¢ÂÂ  nmap Ã¢ÂÂ sqlmap Ã¢ÂÂ nuclei Ã¢ÂÂ curl Ã¢ÂÂ   Ã¢ÂÂ
Ã¢ÂÂ    Ã¢ÂÂ  chromedp Ã¢ÂÂ subfinder Ã¢ÂÂ httpx  Ã¢ÂÂ   Ã¢ÂÂ
Ã¢ÂÂ    Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ¬Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ   Ã¢ÂÂ
Ã¢ÂÂ                     Ã¢ÂÂ                  Ã¢ÂÂ
Ã¢ÂÂ              Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ¼Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ           Ã¢ÂÂ
Ã¢ÂÂ              Ã¢ÂÂ   Results   Ã¢ÂÂ           Ã¢ÂÂ
Ã¢ÂÂ              Ã¢ÂÂ  Ã¢ÂÂ History  Ã¢ÂÂ           Ã¢ÂÂ
Ã¢ÂÂ              Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ           Ã¢ÂÂ
Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ
  Ã¢ÂÂ
  Ã¢ÂÂ¼
SARIF + PDF Report
```

**Phase pipeline:**

1. **Recon** Ã¢ÂÂ DNS, WHOIS, subdomain enum, port scan, HTTP probing, tech fingerprinting
2. **Discovery** Ã¢ÂÂ Spider/crawl, directory bruteforce, JS analysis, API discovery, parameter discovery
3. **VulnScan** Ã¢ÂÂ Systematic testing across all vulnerability classes with proof-of-exploitability requirement
4. **Exploit** Ã¢ÂÂ Impact demonstration on confirmed findings
5. **Report** Ã¢ÂÂ SARIF export + branded PDF with findings, evidence, remediation roadmap

---

## Output

Every scan produces:

**`report.sarif`** Ã¢ÂÂ Machine-readable findings for CI/CD integration, Defect Dojo, GitHub Security tab

**`report.pdf`** Ã¢ÂÂ Human-readable report with:
- Executive summary and risk rating
- Findings table with CVSS scores
- Detailed findings with PoC, impact, remediation
- Remediation roadmap (immediate / 30-day / 90-day)
- Compliance mapping (OWASP, PCI-DSS, ISO 27001)

---

## Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `ARES_LLM_PROVIDER` | `ollama` | LLM provider: `ollama`, `openai`, `anthropic` |
| `ARES_LLM_BASE_URL` | `http://localhost:11434/v1` | LLM API endpoint |
| `ARES_LLM_MODEL` | `qwen3:latest` | Model name |
| `ARES_LLM_API_KEY` | `` | API key (empty for Ollama) |
| `ARES_ATTACK_LLM_PROVIDER` | `ollama` | Attack model provider for payload generation |
| `ARES_ATTACK_LLM_MODEL` | `qwen3:latest` | Attack model name |
| `ARES_SCAN_MAX_ITERATIONS` | `200` | Max agent iterations per scan |
| `ARES_SCAN_MAX_WORKERS` | `3` | Parallel scan workers |
| `ARES_OOB_ENABLED` | `true` | Enable OOB callback server |
| `ARES_OOB_PORT` | `8181` | OOB listener port |
| `ARES_DASH_PORT` | `8080` | Web dashboard port |
| `ARES_OUTPUT` | `report.txt` | Output file path |
| `ARES_MEMORY_ENABLED` | `false` | Persistent scan memory (requires PostgreSQL) |
| `ARES_MEMORY_DSN` | `` | PostgreSQL connection string |

---

## Scope Enforcement

ARES enforces scope before every tool execution. The following are always blocked regardless of configuration:

- RFC1918 private ranges (10.x, 172.16.x, 192.168.x)
- Loopback (127.x, ::1)
- Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
- `.local` and `.internal` domains
- Link-local addresses

Scope is checked at the execution layer, not just advisory Ã¢ÂÂ the agent cannot bypass it.

---

## External Tool Dependencies

ARES orchestrates industry-standard tools. Install these for full coverage:

```bash
# Recon
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/OJ/gobuster/v3@latest

# Scanning
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Exploitation
pip install sqlmap

# Network
apt install nmap -y  # or brew install nmap
```

ARES runs without any of these Ã¢ÂÂ it will skip tools that aren't installed and note them in the scan log.

---

## Enterprise PTaaS

The open source version covers web application security scanning.


**[ArmourMind Enterprise](https://armourmind.com)** adds:

| Feature | Open Source | Enterprise |
|---|---|---|
| Web vuln scanning | Ã¢ÂÂ | Ã¢ÂÂ |
| Autonomous agent loop | Ã¢ÂÂ | Ã¢ÂÂ |
| Offline / local LLM | Ã¢ÂÂ | Ã¢ÂÂ |
| SARIF + PDF reports | Ã¢ÂÂ | Ã¢ÂÂ |
| Continuous monitoring | Ã¢ÂÂ | Ã¢ÂÂ |
| Authenticated scanning | Ã¢ÂÂ | Ã¢ÂÂ |
| AD / Kerberos simulation | Ã¢ÂÂ | Ã¢ÂÂ |
| Multi-target campaigns | Ã¢ÂÂ | Ã¢ÂÂ |
| SIEM integration | Ã¢ÂÂ | Ã¢ÂÂ |
| Compliance reporting | Ã¢ÂÂ | Ã¢ÂÂ |
| Remediation verification | Ã¢ÂÂ | Ã¢ÂÂ |
| Multi-user dashboard | Ã¢ÂÂ | Ã¢ÂÂ |
| On-premise deployment | Ã¢ÂÂ | Ã¢ÂÂ |
| Support SLA | Community | Dedicated |


Ã¢ÂÂ **[armourmindinfotech.com](https://armourmindinfotech.com)**

---

## Legal

ARES is for authorized security testing only. Only use against systems you own or have explicit written permission to test. Unauthorized use is illegal.

Users are responsible for ensuring they have proper authorization before running any scan. ArmourMind Infotech accepts no liability for unauthorized use.

---

## License

GNU Affero General Public License v3.0 Ã¢ÂÂ see [LICENSE](LICENSE)


Commercial licensing available for embedding ARES in proprietary products. Contact [armourmindinfotech.com](https://armourmindinfotech.com).

---

## Contributing

Issues and PRs welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting.


For vulnerability reports in ARES itself: armourmindinfotech@gmail.com

---

<div align="center">

Built by <a href="https://armourmindinfotech.com">ArmourMind Infotech</a>
</div>
