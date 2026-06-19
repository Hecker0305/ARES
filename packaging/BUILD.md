# Building Ares Engine .deb Package for Kali Linux

## Prerequisites (Kali Linux)

```bash
sudo apt update
sudo apt install -y \
    golang-go \
    nodejs \
    npm \
    make \
    git \
    dpkg-dev \
    fakeroot \
    ca-certificates
```

Verify versions:

```bash
go version    # requires >= 1.25
node -v       # requires >= 20
npm -v
```

## Build the .deb Package

### Method 1 — One command (recommended)

```bash
cd /path/to/ares-engine
make deb
```

### Method 2 — Manual script

```bash
cd /path/to/ares-engine/packaging
bash build-deb.sh
```

### What the build does

1. Installs frontend npm dependencies
2. Builds the React frontend (`npm run build`)
3. Copies frontend output to the Go embed location
4. Cross-compiles the Go binary for `linux/amd64` (static, stripped)
5. Packages everything into a `.deb` with proper directory layout

### Output

```
packaging/ares-engine_<version>_amd64.deb
```

## Install the .deb

```bash
sudo dpkg -i packaging/ares-engine_*.deb
sudo apt install -f   # install any missing dependencies
```

## Verify Installation

```bash
# Check binary exists
which ares-engine
# Should output: /usr/bin/ares-engine

# Check version
ares-engine --version 2>&1 || /usr/share/ares-engine/ares --version 2>&1

# Check desktop entry
ls -la /usr/share/applications/ares-engine.desktop

# Check systemd service
ls -la /lib/systemd/system/ares-engine.service

# Check config
ls -la /etc/ares-engine/ares.env
```

## Run Ares Engine

### Option 1 — Desktop app (recommended)

Launch from application menu: **Ares Engine** (found under Security category)

Or run from terminal:

```bash
ares-engine
```

This starts the server and opens `http://127.0.0.1:8080` in your default browser.

### Option 2 — System service (auto-start)

```bash
sudo systemctl enable --now ares-engine
```

Check status:

```bash
sudo systemctl status ares-engine
```

View logs:

```bash
sudo journalctl -u ares-engine -f
```

### Option 3 — Direct binary

```bash
/usr/share/ares-engine/ares
```

## Uninstall

```bash
sudo systemctl stop ares-engine.service
sudo systemctl disable ares-engine.service
sudo dpkg -r ares-engine
```

## Package Contents

| Path | Description |
|---|---|
| `/usr/bin/ares-engine` | Symlink to main binary |
| `/usr/share/ares-engine/ares` | Main Go binary (embedded frontend) |
| `/usr/share/ares-engine/ares-engine-launcher.sh` | Desktop launcher script |
| `/usr/share/applications/ares-engine.desktop` | Desktop entry |
| `/usr/share/icons/hicolor/256x256/apps/ares-engine.png` | App icon |
| `/lib/systemd/system/ares-engine.service` | Systemd service unit |
| `/etc/ares-engine/ares.env` | Runtime configuration |

## Configuration

Edit `/etc/ares-engine/ares.env` to configure:

```bash
ARES_WEB_PORT=8080
ARES_LLM_PROVIDER=openai
ARES_LLM_MODEL=gpt-4
# ... see .ares.env.example for all options
```

Restart after changing config:

```bash
sudo systemctl restart ares-engine
```

## Troubleshooting

**"command not found: go"** — Install Go:
```bash
sudo apt install -y golang-go
```

**"npm ERR!"** — Ensure Node.js is installed:
```bash
sudo apt install -y nodejs npm
```

**"dpkg-deb: command not found"** — Install dpkg-dev:
```bash
sudo apt install -y dpkg-dev fakeroot
```

**Server won't start** — Check config and ports:
```bash
sudo journalctl -u ares-engine -n 50 --no-pager
```

**Port 8080 already in use** — Change port in `/etc/ares-engine/ares.env`:
```bash
ARES_WEB_PORT=9090
```
