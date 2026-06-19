# Ares Engine — Multi-Harness Plugin Guide

This guide covers setup and configuration for AI coding assistants: **OpenCode**, **Claude Code**, **Codex CLI**, and **Pi Agent**.

## Directory Structure

```
ares/
├── ARES_MANIFEST.md  # Agent manifest (auto-loaded)
├── ARES_SETUP.md     # Installation guide
├── AGENTS.md         # This file — multi-harness reference
├── skills/           # Agent skill definitions
│   ├── sql_injection.skill
│   ├── xss_scanner.json
│   └── web_recon.skill
├── install.sh        # Main installation script
├── install_tools.sh  # Security tool installer
├── uninstall.sh      # Cleanup script
├── uninstall_tools.sh # Tool removal
├── .hooks/
│   └── hooks.json    # Git hooks configuration
├── cmd/
│   ├── ares/         # Main engine binary
│   └── ares-mcp/     # MCP server for agent integration
├── internal/
│   ├── agent/        # Agent orchestration
│   ├── mcp/          # Security tool MCP integrations
│   ├── web3/         # Smart contract auditing
│   └── wordlists/    # Fuzzing wordlists
```

## Installation by Agent

### OpenCode

```
opencode . --config ares/ARES_SETUP.md
```

See `ARES_SETUP.md` for full details.

### Claude Code

Auto-loads `ARES_MANIFEST.md` when run from the `ares/` directory:

```
cd ares
claude
```

Skills are automatically discovered from the `skills/` directory.

### Codex CLI

Codex CLI does not auto-load configuration files. Use the setup script:

```
./install.sh --agent codex
```

This creates a `.codex` config pointing to the skills directory.

### Pi Agent

Pi Agent supports custom tool definitions. Install with:

```
./install.sh --agent pi
```

Or for all agents:

```
./install.sh --agent all
```

## Configuration Differences

| Feature               | OpenCode | Claude Code | Codex CLI | Pi Agent |
|----------------------|----------|-------------|-----------|----------|
| Auto-loads config    | Yes      | Yes         | No        | No       |
| Skill discovery      | Manual   | Auto        | Manual    | Manual   |
| MCP support          | Built-in | Built-in    | Plugin    | Plugin   |
| Tool installation    | Manual   | Manual      | Script    | Script   |

## Common Commands

```bash
# Build and test
make build
make test
make vet

# Run security tools
./install_tools.sh
nuclei -target example.com

# Smart contract audit
# (use MCP tools from cmd/ares-mcp)

# Fuzzing
# (wordlists available in internal/wordlists)
```

## Environment Variables

See `.ares.env.example` for all configuration options.
Key variables:
- `ARES_API_KEY` — API authentication
- `ARES_MCP_API_KEY` — MCP server authentication
- `ARES_BOUNTY_HACKERONE_TOKEN` — HackerOne integration
- `ARES_BOUNTY_BUGCROWD_TOKEN` — Bugcrowd integration
