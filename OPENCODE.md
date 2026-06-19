# Ares Engine — OpenCode Installation Guide

## Setup

1. Navigate to the Ares Engine directory:
```bash
cd ares-engine
```

2. Build the engine:
```bash
make build
```

3. Run tests to verify:
```bash
make test
```

## OpenCode Configuration

OpenCode uses the standard Go tools for development. Configure `.opencode.json` in the project root:

```json
{
  "name": "ares-engine",
  "description": "AI-powered security operations engine",
  "commands": {
    "build": "make build",
    "test": "make test",
    "lint": "make lint",
    "vet": "make vet"
  },
  "skills": [
    "ares/skills/sql_injection.skill",
    "ares/skills/xss_scanner.json",
    "ares/skills/web_recon.skill"
  ]
}
```

## Available Commands

| Command | Description |
|---------|-------------|
| `make build` | Build the main engine binary |
| `make test` | Run all Go tests |
| `make lint` | Run golangci-lint |
| `make vet` | Run go vet |
| `make sec` | Run gosec security scanner |
| `make run` | Run the engine |
| `make clean` | Clean build artifacts |

## MCP Integration

The MCP server at `cmd/ares-mcp/` provides JSON-RPC tools:
- `scan` — Start a security scan
- `get_findings` — Retrieve scan results
- `get_scan_status` — Check scan progress
- `remediate` — Get remediation advice

Run the MCP server:
```bash
go run ./cmd/ares-mcp
```

## Security Tool Integrations

Install security tools:
```bash
./install_tools.sh
```

Available integrations (in `internal/mcp/`):
- **Burp Suite** — REST API integration
- **Caido** — GraphQL API integration
- **HackerOne** — Bug bounty platform integration
- **Nuclei** — Template-based scanner

## Web3/Smart Contract Auditing

The `internal/web3/` package provides:
- Static analysis for 10 vulnerability classes
- Foundry PoC generation templates
- ERC-4626 share inflation checks
- Token rug pull scanning

## Wordlists

The `internal/wordlists/` package provides:
- 100+ subdomains for DNS brute force
- 200+ common web paths
- 100+ HTTP parameters
- SQLi, XSS, SSRF, SSTI, LFI, RCE, Open Redirect payloads
- 50+ usernames and passwords

## Bug Bounty Integration

Configure bounty platforms via environment variables:
- `ARES_BOUNTY_HACKERONE_TOKEN` + `ARES_BOUNTY_HACKERONE_USERNAME`
- `ARES_BOUNTY_BUGCROWD_TOKEN` + `ARES_BOUNTY_BUGCROWD_PROGRAM_ID`
- `ARES_BOUNTY_INTIGRITI_TOKEN`
- `ARES_BOUNTY_YESWEHACK_TOKEN`

## Best Practices

1. Always run `make vet && make test` before submitting changes
2. Follow Go security conventions (constant-time comparisons, URL validation)
3. Never hardcode credentials — use environment variables
4. Respect scope boundaries for all scanning operations
5. Use `context.Context` with timeouts for all network operations
