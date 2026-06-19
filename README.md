# Ares — AI Penetration Testing Engine

Autonomous AI pentesting: recon → exploitation → structured report.
**Zero external dependencies. Zero cloud LLM keys. Pure stdlib Go.**

## 🚀 New Features in v2.0

Ares now includes 13 enterprise-grade security features:

- 🔔 **Webhook Notifications** - Slack/Discord/Email alerts with HMAC-SHA256 signing
- 🎫 **Ticketing System** - Jira/GitHub integration with automated PR-based remediation  
- ⏰ **Scan Scheduler** - Cron-based recurring scans with pause/resume capability
- 🚀 **Demo/Onboarding Mode** - Guided tutorials for new users
- 🔍 **API Discovery** - OpenAPI/Swagger + GraphQL endpoint auto-discovery
- 🏆 **Bug Bounty Platform** - HackerOne/Bugcrowd integration with deduplication
- 🏢 **Multi-tenancy** - Organizational isolation with role-based access control
- 🔒 **Air-gapped Mode** - Fully offline operation for secure environments
- 💻 **VS Code Extension** - In-IDE scanning with fix application
- 🧪 **LLM Red-teaming** - 50+ injection prompts across attack categories
- ☁️ **Cloud Config Scanner** - Terraform/CloudFormation misconfiguration detection
- 🔧 **Code Fix Remediation** - Framework-specific patches for 6 vuln types across 7 languages
- 🔄 **PR-based Remediation** - Automated pull requests for vulnerability fixes

**[→ Read the full USAGE guide](./USAGE.md)** for complete build, configuration, CLI, web dashboard, and development instructions.

---

## Quick Start

```powershell
# 1. Build
cd ares
.\build.ps1

# 2. Start Ollama
ollama serve

# 3. Run a scan
.\ares.exe -target example.com -dash-port 8080
# Open http://localhost:8080
```

## Web UI Only

```powershell
.\ares.exe -web -dash-port 8080
```

---

## TL;DR

| Task | Command |
|---|---|
| Build | `.\build.ps1` |
| CL scan | `.\ares.exe -target example.com` |
| Web UI | `.\ares.exe -web -dash-port 8080` |
| Scan + dashboard | `.\ares.exe -target example.com -dash-port 8080` |
| Full docs | `.\USAGE.md` |
| Frontend dev | `cd frontend && npm run dev` |

---

**DISCLAIMER**: For authorized security testing only. Unauthorized scanning is illegal.
