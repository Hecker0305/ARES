# Ares Engine — Complete Usage Guide

Autonomous AI penetration testing engine: recon → exploitation → structured report.
Zero external dependencies. Zero cloud LLM keys required (Ollama/NIM built-in).

---

## Table of Contents
1. [Architecture](#architecture)
2. [Requirements](#requirements)
3. [Build & Install](#build--install)
4. [Configuration](#configuration)
5. [CLI Usage](#cli-usage)
6. [Web Dashboard](#web-dashboard)
7. [Frontend Development](#frontend-development)
8. [LLM Providers & Models](#llm-providers--models)
9. [Understanding Output](#understanding-output)
10. [Advanced Usage](#advanced-usage)
11. [Troubleshooting](#troubleshooting)
12. [New Features v2.0](#new-features-v20)

---

## Architecture

```
ares/
├── cmd/ares/              — CLI entry point
├── internal/
│   ├── llm/               — LLM client (Ollama, OpenAI, Anthropic, Gemini, etc.)
│   ├── agent/             — ScanContext + Agent loop
│   ├── config/            — Config structs with env/flag overriding
│   ├── webserver/         — Web dashboard + login/auth + embedded SPA frontend
│   ├── security/          — Binary allowlist, path validation, encryption
│   ├── worker/            — Parallel scan coordinator
│   ├── oob/               — OOB callback server (SSRF/XXE/RCE detection)
│   ├── report/            — Structured report generation
│   └── ...                — Recon, exploit, compliance, CVE correlation, SIEM push
├── frontend/              — React + TypeScript + Vite + Tailwind SPA
│   ├── src/pages/         — Overview, NewScan, LiveScan, Findings, Projects, Reports, Settings
│   ├── src/components/    — Layout, Sidebar, MetricCard, Skeleton, StatusBadge, SeverityBar
│   └── dist/              — Built frontend (embedded into Go binary)
├── deploy/                — Kubernetes manifests, Dockerfile
└── build.ps1              — Windows build script (frontend → Go embed → binary)
```

---

## Requirements

| Requirement | Notes |
|---|---|
| **Go 1.21+** | `go build` — no CGO required |
| **Node.js 18+** | Only needed for frontend development/rebuilds |
| **Ollama** or **NVIDIA NIM** | Self-hosted LLM — no cloud keys needed |
| **Postgres** (optional) | For strategic memory / cross-scan learning |
| **Kali Linux** (recommended) | For built-in security tools (nmap, sqlmap, etc.) |

---

## Build & Install

### Windows (PowerShell)

```powershell
cd ares

# Quick build (if frontend hasn't changed):
go build -o ares.exe ./cmd/ares/

# Full build (rebuild frontend + Go binary):
.\build.ps1
```

### Linux / macOS

```bash
cd ares

# Install security tools (Kali):
sudo make install-kali

# Build Go binary only:
make build

# Full build with frontend:
cd frontend && npm install && npm run build && cd ..
cp -r frontend/dist internal/webserver/frontend/dist
go build -o ares ./cmd/ares/
```

### Docker

```bash
docker build -t ares-engine .
docker run --rm ares-engine -target example.com
```

---

## Configuration

Ares reads configuration from three sources (priority: flags > `.ares.env` > environment variables > defaults).

### Method 1: CLI Flags

```bash
ares.exe -target example.com -provider ollama -model llama3.1:70b -workers 3
```

### Method 2: Environment Variables

```powershell
$env:ARES_LLM_PROVIDER = "ollama"
$env:ARES_LLM_BASE_URL = "http://localhost:11434/v1"
$env:ARES_LLM_MODEL = "llama3.1:70b"
$env:ARES_TARGET = "example.com"
$env:ARES_OUTPUT = "report.txt"
```

### Method 3: `.ares.env` File

Create `.ares.env` in the `ares/` directory:

```
ARES_LLM_PROVIDER=ollama
ARES_LLM_BASE_URL=http://localhost:11434/v1
ARES_LLM_MODEL=llama3.1:70b
ARES_TARGET=example.com
ARES_OUTPUT=report.txt
ARES_SCAN_MAX_WORKERS=3
ARES_SCAN_MAX_ITERATIONS=200
ARES_FORMAT=text
```

### Method 4: JSON Config File

Create `config.json`:

```json
{
  "llm": {
    "provider": "ollama",
    "base_url": "http://localhost:11434/v1",
    "model": "llama3.1:70b"
  },
  "scan": {
    "max_workers": 3,
    "max_iterations": 200
  },
  "output": {
    "report_path": "report.txt",
    "format": "text"
  }
}
```

```powershell
ares.exe -config config.json -target example.com
```

### Full Environment Variables

| Variable | Description | Default |
|---|---|---|
| `ARES_LLM_PROVIDER` | LLM provider (see providers below) | `ollama` |
| `ARES_LLM_BASE_URL` | LLM API endpoint | `http://localhost:11434/v1` |
| `ARES_LLM_MODEL` | Model name | `llama3.1:70b` |
| `ARES_LLM_API_KEY` | API key for cloud providers | — |
| `ARES_LLM_MAX_TOKENS` | Max output tokens | `4096` |
| `ARES_LLM_TEMPERATURE` | LLM temperature | `0.1` |
| `ARES_ATTACK_LLM_PROVIDER` | Attack LLM provider (payload gen) | `ollama` |
| `ARES_ATTACK_LLM_MODEL` | Attack LLM model | `qwen2.5:14b` |
| `ARES_TARGET` | Target domain or IP | — |
| `ARES_SCAN_MAX_WORKERS` | Parallel scan workers | `3` |
| `ARES_SCAN_MAX_ITERATIONS` | Max LLM agent loops | `200` |
| `ARES_OUTPUT` | Report output path | `report.txt` |
| `ARES_FORMAT` | Output format: `text`, `json`, `csv` | `text` |
| `ARES_OOB_PORT` | OOB callback HTTP port | `8181` |
| `ARES_DASH_PORT` | Web dashboard port | `8080` |
| `ARES_ENCRYPTION_KEY` | AES-256-GCM key for evidence | — |
| `ARES_MEMORY_DSN` | Postgres DSN for strategic memory | — |

---

## CLI Usage

### Basic Scan

```powershell
ares.exe -target example.com
```

### Full Options Scan

```powershell
ares.exe -target example.com -provider ollama -llm-url http://localhost:11434/v1 -model llama3.1:70b -workers 5 -output report.txt -format text -log-level debug
```

### Web UI Mode (no target required)

```powershell
ares.exe -web -dash-port 8080
# Open http://localhost:8080
```

### Scan + Live Dashboard

```powershell
ares.exe -target example.com -dash-port 8080
# Open http://localhost:8080 to watch the scan live
```

### All CLI Flags

```
-target       Target domain or IP (required for scans)
-provider     LLM provider: ollama|nim|openai|anthropic|deepseek|gemini|azure
-llm-url      LLM base URL
-model        Model name
-api-key      API key for cloud providers
-workers      Parallel scan workers
-output       Report output path
-format       Output format: text|json|csv
-oob-port     OOB HTTP callback port
-dash-port    Web dashboard port (0 to disable)
-log-level    debug|info|warn|error
-config       JSON config file path
-web          Start web UI mode (no scan)
-version      Show version
-genkey       Generate encryption key
-service      Service mode: start|stop|restart|uninstall
-update       Check for updates
```

---

## Web Dashboard

The web dashboard is a React SPA built with dark space theme and liquid glass UI.
It's embedded into the Go binary — no separate server needed.

### Screens

| Screen | Route | Description |
|---|---|---|
| **Overview** | `/` | Metric cards (total scans, critical findings, targets, verified rate), active scans, recent criticals, severity breakdown, top vuln categories, scan queue |
| **New Scan** | `/new-scan` | 4 preset tiles (Quick/Deep/Authenticated/API) with tool listings, target input, authorization checkbox |
| **Live Scan** | `/live-scan` | Real-time agent feed showing tool calls, strategy switch events, phase progress bar, inject instruction box |
| **Findings** | `/findings` | Filterable table by severity/project/status, CVSS scores, retest column (open/fixed) |
| **Finding Detail** | `/findings/:id` | CVSS ring, verification chain (2-round confirmation), remediation text, PoC code, MITRE ATT&CK mapping, compliance controls, status buttons (mark fixed/accept risk/won't fix), re-verify button |
| **Projects** | `/projects` | Project cards showing target, severity bar, finding counts per severity |
| **Reports** | `/reports` | White-label fields (client name, tester, engagement ref, classification, logo), export buttons (PDF/Markdown/JSON/Re-test report), report preview |
| **Settings** | `/settings` | Tabbed sidebar nav: General (instance config), Webhooks (URL + secret), Scope Management (tagged authorized targets), Team (role-based members), LLM Provider (model, URL, API key) |

### Running the Dashboard

```powershell
# Standalone web UI (no scan):
ares.exe -web -dash-port 8080

# Scan with live dashboard:
ares.exe -target example.com -dash-port 8080

# Dashboard with auth:
$env:ARES_ADMIN_PASSWORD = "your-password"
ares.exe -web -dash-port 8080
```

### Authentication

Set admin password via `ARES_ADMIN_PASSWORD` environment variable.
Login at `http://localhost:8080` with username `admin` and your password.
Sessions use Argon2id hashing and CSRF protection.

---

## Frontend Development

For developers who want to modify the web UI:

```powershell
cd ares/frontend
npm install
npm run dev        # Dev server at http://localhost:5173
```

After making changes, rebuild the full binary:

```powershell
cd ares
.\build.ps1        # Builds frontend, copies to Go embed, compiles binary
```

### Frontend Stack

- **Framework:** React 19 + TypeScript
- **Build:** Vite 8
- **Styling:** Tailwind CSS v4
- **Icons:** lucide-react
- **Routing:** react-router-dom v7
- **Charts:** recharts
- **Theme:** Dark space (#010828), Anton/Condiment/ monospace fonts, liquid glass effects, skeleton loaders, tooltips, fade-in animations

### Project Structure

```
frontend/
├── index.html            — Google Fonts (Anton, Condiment)
├── src/
│   ├── index.css         — Tailwind theme, liquid-glass, animations
│   ├── main.tsx          — React entry with BrowserRouter
│   ├── App.tsx           — Route definitions
│   ├── lib/api.ts        — API types, mock data, fetch helpers
│   ├── components/
│   │   ├── Layout.tsx    — Sidebar + main content layout
│   │   ├── Sidebar.tsx   — Navigation links
│   │   ├── MetricCard.tsx
│   │   ├── Skeleton.tsx  — Loading placeholders
│   │   ├── StatusBadge.tsx
│   │   └── SeverityBar.tsx
│   └── pages/
│       ├── Overview.tsx
│       ├── NewScan.tsx
│       ├── LiveScan.tsx
│       ├── Findings.tsx
│       ├── FindingDetail.tsx
│       ├── Projects.tsx
│       ├── Reports.tsx
│       └── Settings.tsx
└── dist/                 — Built frontend (embedded in Go binary)
```

---

## LLM Providers & Models

### Supported Providers

| Provider | Flag Value | API Format | Requires API Key |
|---|---|---|---|
| **Ollama** (default) | `ollama` | OpenAI-compatible | No (local) |
| **NVIDIA NIM** | `nim` | OpenAI-compatible | No (local) |
| **OpenAI** | `openai` | OpenAI-compatible | Yes |
| **Anthropic** | `anthropic` | Anthropic native | Yes |
| **Gemini** | `gemini` / `google` | Gemini native | Yes |
| **DeepSeek** | `deepseek` | OpenAI-compatible | Yes |
| **Azure** | `azure` | OpenAI-compatible | Yes |
| **Groq** | `groq` | OpenAI-compatible | Yes |
| **Together** | `together` | OpenAI-compatible | Yes |

Any OpenAI-compatible endpoint works — just set `-llm-url` to the base URL.

### Default Models

| Role | Default Model |
|---|---|
| LLM (main agent) | `llama3.1:70b` |
| Attack LLM (payload gen) | `qwen2.5:14b` |

Override any model with `-model` flag or `ARES_LLM_MODEL` environment variable.

### Examples

```powershell
# Ollama (local):
ares.exe -target example.com -provider ollama -model llama3.1:70b

# OpenAI:
ares.exe -target example.com -provider openai -model gpt-4o -api-key sk-...

# Anthropic:
ares.exe -target example.com -provider anthropic -model claude-3-opus-20240229 -api-key sk-ant-...

# Gemini:
ares.exe -target example.com -provider gemini -model gemini-2.0-flash -api-key AIza...

# DeepSeek:
ares.exe -target example.com -provider deepseek -model deepseek-chat -api-key sk-...

# NVIDIA NIM:
ares.exe -target example.com -provider nim -llm-url http://nim-host:8000/v1 -model meta/llama-3.1-70b-instruct
```

### Provider Policy

The engine **panics at startup** if the provider is anything other than `ollama` or `nim` when no API key is provided. All cloud providers require an API key. No cloud API keys are ever stored in plaintext — all credentials use constant-time comparison and secure memory zeroing after use.

---

## Understanding Output

### Report Structure

```
report.txt or /reports/client-name/
├── report.txt              — Main findings report
├── report.json             — JSON format
├── report.csv              — CSV format
├── compliance_*.json       — Compliance mapping (SOC2, ISO27001, PCI-DSS, HIPAA)
└── evidence/               — Evidence files
```

### Report Sections

1. **Cover page** — Target, scan ID, date, firm, classification
2. **Scope & authorization**
3. **Executive summary** — Overall risk rating
4. **Severity summary** — Critical / High / Medium / Low / Info counts
5. **Per-finding detail** — Description, impact, PoC steps, PoC code, extraction proof, evidence path
6. **MITRE ATT&CK mapping** — Deterministic (zero LLM cost)
7. **Compliance controls** — SOC2 / ISO27001 / PCI-DSS / HIPAA — deterministic
8. **Full timestamped audit trail**
9. **Legal disclaimer**

### Finding Severity

| Severity | Description |
|---|---|
| **CRITICAL** | RCE, SQLi with data exfil, full compromise |
| **HIGH** | XSS with session hijack, auth bypass, privilege escalation |
| **MEDIUM** | Information disclosure, CSRF, IDOR |
| **LOW** | Verbose errors, weak crypto, missing headers |
| **INFO** | Stack traces, version disclosure |

### Zero False Positive Enforcement

`report_vulnerability` enforces **4 gates** before accepting any finding:

| Gate | Requirement |
|---|---|
| 1 — Extraction proof | Non-empty `extraction_proof` with actual extracted data |
| 2 — Evidence on disk | `evidence_path` points to an existing file |
| 3 — Confidence ≥ 0.95 | LLM must assign ≥95% confidence |
| 4 — Required fields | `title`, `endpoint`, `description`, `impact` all non-empty |

---

## Advanced Usage

### Parallel Scanning

```powershell
ares.exe -target "example.com,subdomain.example.com" -workers 5
```

### Scan with OOB Callbacks (SSRF/XXE detection)

```powershell
ares.exe -target example.com -oob-port 53530
```

### Resume from Checkpoint

```powershell
$env:ARES_MEMORY_ENABLED = "true"
$env:ARES_MEMORY_DSN = "file:///$pwd\.ares-memory.db"
ares.exe -target example.com
```

### Using with Sliver C2

```powershell
$env:ARES_SLIVER_ENABLED = "true"
$env:ARES_SLIVER_HOST = "attacker.com"
$env:ARES_SLIVER_PORT = "443"
ares.exe -target https://example.com
```

### Rate Limiting

```powershell
$env:ARES_MAX_REQUEST_RATE = "10"
ares.exe -target https://example.com
```

### Evidence Encryption

```powershell
ares.exe -genkey
# Add output to .ares.env:
ARES_ENCRYPTION_KEY=your-generated-hex-key
```

---

## Troubleshooting

### "LLM init failed"

```powershell
# Check if Ollama is running
curl http://localhost:11434/v1/models

# If not, start it:
ollama serve
```

### "API key required for ... provider"

Cloud providers (OpenAI, Anthropic, etc.) require an API key. Set via `-api-key` flag or `ARES_LLM_API_KEY` env var.

### "Binary not in allowlist"

```powershell
ares.exe --list-tools
$env:ARES_ALLOW_CUSTOM_BINARIES = "1"
```

### "Target validation failed"

Ares blocks private IPs by default. Use VPN/tunnel for internal targets.

### Stuck Scan

```powershell
# Use dashboard to view progress:
ares.exe -dash-port 8080
# Or send Ctrl+C for graceful shutdown
```

### Web UI shows blank page

The frontend is embedded in the binary. If you rebuilt Go without rebuilding the frontend, the old frontend is embedded. Run `.\build.ps1` to rebuild both.

---

## Quick Reference

```powershell
# Help
ares.exe --help

# Version
ares.exe --version

# Build
.\build.ps1

# Run scan
ares.exe -target example.com

# Web UI
ares.exe -web -dash-port 8080

# Scan + dashboard
ares.exe -target example.com -dash-port 8080

# Frontend dev
cd frontend && npm run dev
```

---

**DISCLAIMER**: This tool is for authorized security testing only. Always obtain written permission before testing any system. Unauthorized scanning is illegal.
