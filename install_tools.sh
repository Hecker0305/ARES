#!/bin/bash
# Ares Engine — Security Tool Installation
set -euo pipefail

log_info()  { echo -e "[INFO]  $*"; }
log_ok()    { echo -e "[OK]    $*"; }
log_warn()  { echo -e "[WARN]  $*"; }
log_error() { echo -e "[ERROR] $*"; }

detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "linux";;
        Darwin*)    echo "darwin";;
        MINGW*|MSYS*|CYGWIN*) echo "windows";;
        *)          echo "unknown";;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64";;
        aarch64|arm64) echo "arm64";;
        *)          echo "unknown";;
    esac
}

OS=$(detect_os)
ARCH=$(detect_arch)
TOOLS_DIR="${TOOLS_DIR:-$HOME/.ares/tools}"
PATH="${TOOLS_DIR}:${PATH}"

mkdir -p "$TOOLS_DIR"

install_go_tool() {
    local pkg="$1"
    local name="$2"
    local version="${3:-latest}"

    if command -v "$name" &>/dev/null; then
        log_ok "$name already installed"
        return 0
    fi

    log_info "Installing $name..."
    if GOFLAGS="" go install "$pkg@$version" &>/tmp/ares-install-"$name".log; then
        # Move from GOPATH/bin if needed
        if [[ -f "$(go env GOPATH)/bin/$name" ]]; then
            cp "$(go env GOPATH)/bin/$name" "$TOOLS_DIR/$name"
            chmod +x "$TOOLS_DIR/$name"
        fi
        log_ok "$name installed"
    else
        log_warn "Failed to install $name — see /tmp/ares-install-$name.log"
        return 1
    fi
}

install_subfinder() {
    install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "subfinder"
}

install_httpx() {
    install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx" "httpx"
}

install_nuclei() {
    install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei" "nuclei"
    if command -v nuclei &>/dev/null; then
        log_info "Updating nuclei templates..."
        nuclei -update-templates 2>/dev/null || log_warn "Template update skipped"
    fi
}

install_katana() {
    install_go_tool "github.com/projectdiscovery/katana/cmd/katana" "katana"
}

install_ffuf() {
    local version="2.1.0"
    local filename="ffuf_${version}_${OS}_${ARCH}.tar.gz"
    local url="https://github.com/ffuf/ffuf/releases/download/v${version}/${filename}"

    if command -v ffuf &>/dev/null; then
        log_ok "ffuf already installed"
        return 0
    fi

    log_info "Downloading ffuf..."
    if curl -sL "$url" -o "/tmp/$filename"; then
        tar -xzf "/tmp/$filename" -C "/tmp/"
        mv "/tmp/ffuf" "$TOOLS_DIR/ffuf"
        chmod +x "$TOOLS_DIR/ffuf"
        log_ok "ffuf installed"
    else
        log_warn "ffuf download failed — install manually: https://github.com/ffuf/ffuf"
    fi
}

install_dalfox() {
    install_go_tool "github.com/hahwul/dalfox/v2" "dalfox"
}

install_gau() {
    install_go_tool "github.com/lc/gau/v2/cmd/gau" "gau"
}

install_dnsx() {
    install_go_tool "github.com/projectdiscovery/dnsx/cmd/dnsx" "dnsx"
}

install_nmap() {
    if command -v nmap &>/dev/null; then
        log_ok "nmap already installed"
        return 0
    fi

    log_info "nmap requires system package manager"
    case "$OS" in
        linux)
            if command -v apt-get &>/dev/null; then
                sudo apt-get install -y nmap 2>/dev/null && log_ok "nmap installed" || log_warn "nmap install failed"
            elif command -v yum &>/dev/null; then
                sudo yum install -y nmap 2>/dev/null && log_ok "nmap installed" || log_warn "nmap install failed"
            else
                log_warn "Install nmap manually: https://nmap.org/download.html"
            fi
            ;;
        darwin)
            if command -v brew &>/dev/null; then
                brew install nmap 2>/dev/null && log_ok "nmap installed" || log_warn "nmap install failed"
            else
                log_warn "Install nmap manually: https://nmap.org/download.html"
            fi
            ;;
        windows)
            log_warn "Install nmap manually: https://nmap.org/download.html"
            ;;
    esac
}

main() {
    echo ""
    echo "=== Ares Engine — Tool Installation ==="
    echo "  OS:   $OS"
    echo "  Arch: $ARCH"
    echo "  Dir:  $TOOLS_DIR"
    echo ""

    install_subfinder
    install_httpx
    install_nuclei
    install_katana
    install_ffuf
    install_dalfox
    install_gau
    install_dnsx
    install_nmap

    echo ""
    echo "=== Installation Complete ==="
    echo ""
    echo "Tools installed in: $TOOLS_DIR"
    echo "Add to your shell config: export PATH=\"\$PATH:$TOOLS_DIR\""
    echo ""

    # Show installed tools
    for tool in subfinder httpx nuclei katana ffuf dalfox gau dnsx nmap; do
        if command -v "$tool" &>/dev/null; then
            echo "  [OK]    $tool"
        else
            echo "  [MISS]  $tool"
        fi
    done
}

main "$@"
