#!/bin/bash
# Ares Engine — Uninstall Script
set -euo pipefail

ARES_HOME="${ARES_HOME:-$HOME/.ares}"
BACKUP_DIR="/tmp/ares-backup-$(date +%Y%m%d%H%M%S)"

log_info()  { echo -e "[INFO]  $*"; }
log_ok()    { echo -e "[OK]    $*"; }
log_warn()  { echo -e "[WARN]  $*"; }

backup_configs() {
    if [[ -d "$ARES_HOME" ]]; then
        log_info "Backing up configurations to $BACKUP_DIR..."
        mkdir -p "$BACKUP_DIR"
        cp -r "$ARES_HOME" "$BACKUP_DIR/ares-home"
        log_ok "Backed up $ARES_HOME to $BACKUP_DIR/ares-home"
    fi
}

remove_skills() {
    if [[ -d "$ARES_HOME/skills" ]]; then
        log_info "Removing skills..."
        rm -rf "$ARES_HOME/skills"
        log_ok "Skills removed"
    fi
}

remove_commands() {
    if [[ -d "$ARES_HOME/commands" ]]; then
        log_info "Removing commands..."
        rm -rf "$ARES_HOME/commands"
        log_ok "Commands removed"
    fi
}

remove_configs() {
    if [[ -d "$ARES_HOME/config" ]]; then
        log_info "Removing agent configurations..."
        rm -rf "$ARES_HOME/config"
        log_ok "Configurations removed"
    fi
}

remove_data() {
    if [[ -d "$ARES_HOME/data" ]]; then
        log_info "Removing data directory..."
        rm -rf "$ARES_HOME/data"
        log_ok "Data removed"
    fi
}

remove_evidence() {
    if [[ -d "$ARES_HOME/evidence" ]]; then
        log_info "Removing evidence directory..."
        rm -rf "$ARES_HOME/evidence"
        log_ok "Evidence removed"
    fi
}

clean_engine() {
    local engine_dir
    engine_dir="$(cd "$(dirname "$0")" && pwd)"
    if [[ -d "$engine_dir" ]]; then
        log_info "Cleaning engine build artifacts..."
        (cd "$engine_dir" && make clean 2>/dev/null) || true
        rm -f "$engine_dir"/ares "$engine_dir"/ares.exe 2>/dev/null || true
        log_ok "Engine artifacts cleaned"
    fi
}

main() {
    echo ""
    echo "=== Ares Engine — Uninstall ==="
    echo ""
    log_warn "This will remove all Ares Engine configurations and data."
    echo -n "Continue? [y/N] "
    read -r confirm
    if [[ ! "$confirm" =~ ^[yY] ]]; then
        echo "Cancelled."
        exit 0
    fi

    backup_configs
    remove_skills
    remove_commands
    remove_configs
    remove_data
    remove_evidence
    clean_engine

    echo ""
    log_info "Uninstall complete."
    log_info "Backup saved to: $BACKUP_DIR"
    echo ""
    echo "To remove installed security tools, run: ./uninstall_tools.sh"
}

main "$@"
