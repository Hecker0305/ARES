#!/bin/bash
# Ares Engine — Tool Removal Script
set -euo pipefail

TOOLS_DIR="${TOOLS_DIR:-$HOME/.ares/tools}"

log_info()  { echo -e "[INFO]  $*"; }
log_ok()    { echo -e "[OK]    $*"; }
log_warn()  { echo -e "[WARN]  $*"; }

remove_go_tool() {
    local name="$1"
    local gopath_bin
    gopath_bin="$(go env GOPATH)/bin/$name"

    if [[ -f "$TOOLS_DIR/$name" ]]; then
        rm -f "$TOOLS_DIR/$name"
        log_ok "Removed $name from $TOOLS_DIR"
    fi

    if [[ -f "$gopath_bin" ]]; then
        rm -f "$gopath_bin"
        log_ok "Removed $name from GOPATH/bin"
    fi

    if ! command -v "$name" &>/dev/null; then
        log_ok "$name fully removed"
    fi
}

remove_system_tool() {
    local name="$1"
    local os
    os="$(uname -s)"

    if ! command -v "$name" &>/dev/null; then
        log_ok "$name not installed"
        return 0
    fi

    log_warn "Removing $name via package manager..."
    case "$os" in
        Linux*)
            if command -v apt-get &>/dev/null; then
                sudo apt-get remove -y "$name" 2>/dev/null && log_ok "$name removed" || log_warn "$name removal failed"
            elif command -v yum &>/dev/null; then
                sudo yum remove -y "$name" 2>/dev/null && log_ok "$name removed" || log_warn "$name removal failed"
            fi
            ;;
        Darwin*)
            if command -v brew &>/dev/null; then
                brew uninstall "$name" 2>/dev/null && log_ok "$name removed" || log_warn "$name removal failed"
            fi
            ;;
    esac
}

main() {
    echo ""
    echo "=== Ares Engine — Tool Removal ==="
    echo ""

    if [[ ! -d "$TOOLS_DIR" ]]; then
        log_info "No tools directory found at $TOOLS_DIR"
    fi

    log_warn "This will remove all installed security tools."
    echo -n "Continue? [y/N] "
    read -r confirm
    if [[ ! "$confirm" =~ ^[yY] ]]; then
        echo "Cancelled."
        exit 0
    fi

    remove_go_tool "subfinder"
    remove_go_tool "httpx"
    remove_go_tool "nuclei"
    remove_go_tool "katana"
    remove_go_tool "ffuf"
    remove_go_tool "dalfox"
    remove_go_tool "gau"
    remove_go_tool "dnsx"
    remove_system_tool "nmap"

    # Remove nuclei templates if present
    if [[ -d "$HOME/nuclei-templates" ]]; then
        rm -rf "$HOME/nuclei-templates"
        log_ok "Removed nuclei templates"
    fi

    # Clean tools directory if empty
    if [[ -d "$TOOLS_DIR" ]] && [[ -z "$(ls -A "$TOOLS_DIR")" ]]; then
        rmdir "$TOOLS_DIR" 2>/dev/null || true
        log_ok "Removed empty tools directory"
    fi

    echo ""
    log_info "Tool removal complete."
}

main "$@"
