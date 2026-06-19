#!/bin/bash
# Ares Engine — Main Install Script
# Supports one-liner: curl -fsSL https://ares.security/install.sh | bash
set -euo pipefail

# === Configuration ===
ARES_VERSION="${ARES_VERSION:-latest}"
ARES_HOME="${ARES_HOME:-$HOME/.ares}"
INSTALL_METHOD=""

# Detect if running via curl pipe (one-liner) or from a local checkout
if [[ -d "$(cd "$(dirname "$0")" 2>/dev/null && pwd)/.git" ]] || [[ -f "$(cd "$(dirname "$0")" 2>/dev/null && pwd)/Makefile" ]]; then
    ARES_DIR="$(cd "$(dirname "$0")" && pwd)"
    INSTALL_METHOD="local"
else
    INSTALL_METHOD="curl"
    ARES_DIR="$ARES_HOME/src"
fi

AGENT="${1:-all}"
if [[ "$1" == "--agent" ]]; then
    AGENT="${2:-all}"
fi

# === Homebrew detection ===
if command -v brew &>/dev/null && [[ -n "$(brew tap 2>/dev/null | grep ares)" ]]; then
    log_info "Homebrew tap detected — you can also install via: brew install ares"
fi

# === Colors and helpers ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# === Detect OS/Arch for prebuilt binaries ===
detect_platform() {
    local os arch
    case "$(uname -s)" in
        Linux)  os="linux"  ;;
        Darwin) os="darwin" ;;
        CYGWIN*|MINGW*|MSYS*) os="windows" ;;
        *)      os=""       ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)          arch=""     ;;
    esac
    echo "${os}_${arch}"
}

check_deps() {
    local deps=("go" "git" "make")
    local missing=()
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing build dependencies: ${missing[*]}"
        log_info "You can install Go: https://go.dev/dl/"
        # Try prebuilt binary instead
        return 1
    fi
    log_ok "All dependencies found"
    return 0
}

# === Try prebuilt binary download ===
try_prebuilt() {
    local platform="${1:-}"
    if [[ -z "$platform" ]]; then
        return 1
    fi
    local os="${platform%_*}"
    local arch="${platform#*_}"
    local binary_name="ares-${os}-${arch}"
    if [[ "$os" == "windows" ]]; then
        binary_name="ares.exe"
    fi

    # Try GitHub Releases for prebuilt binary
    local download_url="https://github.com/ares/engine/releases/download/${ARES_VERSION}/${binary_name}"
    log_info "Attempting to download prebuilt binary from GitHub Releases..."
    
    if command -v curl &>/dev/null; then
        if curl -fsSL "$download_url" -o "$ARES_DIR/$binary_name" 2>/dev/null; then
            chmod +x "$ARES_DIR/$binary_name" 2>/dev/null || true
            log_ok "Downloaded prebuilt binary: $binary_name"
            return 0
        fi
    fi
    return 1
}

create_dirs() {
    mkdir -p "$ARES_HOME"/{skills,commands,config,data,evidence,state}
    mkdir -p "$ARES_HOME"/skills
    log_ok "Created directories in $ARES_HOME"
}

copy_skills() {
    if [[ -d "$ARES_DIR/skills" ]]; then
        cp -r "$ARES_DIR/skills/"* "$ARES_HOME/skills/" 2>/dev/null || true
        log_ok "Copied skills to $ARES_HOME/skills/"
    fi
}

setup_agent_config() {
    case "$AGENT" in
        opencode)
            log_info "Setting up for OpenCode"
            if [[ -f "$ARES_DIR/ARES_SETUP.md" ]]; then
                cp "$ARES_DIR/ARES_SETUP.md" "$ARES_HOME/config/opencode.md"
                log_ok "OpenCode config copied"
            fi
            ;;
        claude)
            log_info "Setting up for Claude Code"
            if [[ -f "$ARES_DIR/ARES_MANIFEST.md" ]]; then
                cp "$ARES_DIR/ARES_MANIFEST.md" "$ARES_HOME/config/claude.md"
                log_ok "Claude Code config copied"
            fi
            ;;
        codex)
            log_info "Setting up for Codex CLI"
            mkdir -p "$ARES_HOME/config/codex"
            echo '{"skills_path": "'"$ARES_HOME/skills"'", "project": "ares-engine"}' > "$ARES_HOME/config/codex/config.json"
            log_ok "Codex CLI config created"
            ;;
        pi)
            log_info "Setting up for Pi Agent"
            echo "ARES_ENGINE_PATH=$ARES_DIR" > "$ARES_HOME/config/pi.env"
            log_ok "Pi Agent config created"
            ;;
        all)
            log_info "Setting up for all agents"
            setup_agent_config opencode
            setup_agent_config claude
            setup_agent_config codex
            setup_agent_config pi
            ;;
        *)
            log_warn "Unknown agent: $AGENT"
            log_info "Supported agents: opencode, claude, codex, pi, all"
            ;;
    esac
}

setup_env() {
    local env_file="$ARES_DIR/.ares.env.example"
    if [[ -f "$ARES_DIR/.ares.env.example" ]]; then
        env_file="$ARES_DIR/.ares.env.example"
    elif [[ -f "$ARES_HOME/src/.ares.env.example" ]]; then
        env_file="$ARES_HOME/src/.ares.env.example"
    fi
    if [[ -f "$env_file" ]] && [[ ! -f "$ARES_DIR/.ares.env" ]]; then
        cp "$env_file" "$ARES_DIR/.ares.env"
        log_info "Created .ares.env from example — edit to configure API keys"
    fi
}

build_engine() {
    log_info "Building Ares Engine from source..."
    (cd "$ARES_DIR" && make build 2>/dev/null) || {
        log_warn "Build failed — you can build manually with 'make build'"
        return 1
    }
    log_ok "Ares Engine built successfully"
}

verify() {
    log_info "Verifying installation..."
    if [[ -f "$ARES_DIR/ares" ]] || [[ -f "$ARES_DIR/ares.exe" ]]; then
        log_ok "Engine binary found at $ARES_DIR"
    else
        log_warn "Engine binary not found — run 'make build'"
    fi
    echo ""
    echo "=== Ares Engine Installation Summary ==="
    echo "  Home:     $ARES_HOME"
    echo "  Engine:   $ARES_DIR"
    echo "  Method:   $INSTALL_METHOD"
    echo "  Agent:    $AGENT"
    echo "  Skills:   $(find "$ARES_HOME/skills" -type f 2>/dev/null | wc -l)"
    echo "========================================"
}

main() {
    echo ""
    echo "=== Ares Engine Installer v2.0 ==="
    echo ""

    # Try prebuilt binary first if not a local install
    local platform
    platform="$(detect_platform)"
    
    if [[ "$INSTALL_METHOD" == "curl" ]]; then
        if try_prebuilt "$platform"; then
            log_ok "Prebuilt binary installation successful"
            create_dirs
            setup_env
            echo ""
            log_info "Installation complete!"
            echo ""
            echo "Next steps:"
            echo "  1. Edit .ares.env with your API keys"
            echo "  2. Run 'ares -target example.com' to start scanning"
            return 0
        fi
        log_info "Prebuilt binary not available for $platform, falling back to source build"
        
        # Clone repository if doing one-liner install
        if [[ ! -d "$ARES_DIR" ]]; then
            log_info "Cloning repository..."
            git clone --depth 1 https://github.com/ares/engine.git "$ARES_DIR" 2>/dev/null || {
                log_error "Failed to clone repository. Install Git and try again."
                exit 1
            }
        fi
        cd "$ARES_DIR"
    fi

    check_deps || {
        log_error "Cannot build from source — missing dependencies"
        log_info "Install Go from https://go.dev/dl/ and try again"
        exit 1
    }
    
    create_dirs
    copy_skills
    setup_agent_config
    setup_env
    build_engine
    verify

    echo ""
    log_info "Installation complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Edit .ares.env with your API keys"
    echo "  2. Run './install_tools.sh' for security tools"
    echo "  3. Run 'make test' to verify the build"
    echo ""
    echo "=== Homebrew (macOS/Linux) ==="
    echo "  brew tap ares/engine"
    echo "  brew install ares"
    echo ""
    echo "=== Quick Start ==="
    echo "  curl -fsSL https://ares.security/install.sh | bash"
    echo "  ares -target example.com"
}

main "$@"
