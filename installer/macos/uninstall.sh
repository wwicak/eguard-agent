#!/bin/bash
set -euo pipefail

# eGuard Agent macOS uninstaller
# Usage: bash uninstall.sh

BASE_DIR="/Library/Application Support/eGuard"
LAUNCHD_PLIST="/Library/LaunchDaemons/com.eguard.agent.plist"
BINARY_PATH="/usr/local/bin/eguard-agent"
LAUNCHD_LABEL="system/com.eguard.agent"

log() {
    printf '[eGuard-uninstall] %s\n' "$1"
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        printf 'Error: required command not found: %s\n' "$cmd" >&2
        exit 1
    fi
}

remove_path_if_exists() {
    local path="$1"
    local description="$2"

    if [[ -e "$path" || -L "$path" ]]; then
        run_as_root rm -rf "$path"
        log "Removed ${description}: $path"
    else
        log "Already absent: $path"
    fi
}

require_cmd launchctl
require_cmd rm

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        printf 'Error: root privileges are required (run as root or install sudo).\n' >&2
        exit 1
    fi
fi

run_as_root() {
    if [[ -n "$SUDO" ]]; then
        "$SUDO" "$@"
    else
        "$@"
    fi
}

log "Stopping eGuard Agent LaunchDaemon if present"
run_as_root launchctl bootout "$LAUNCHD_LABEL" 2>/dev/null || true

log "Removing installed files"
remove_path_if_exists "$LAUNCHD_PLIST" "LaunchDaemon plist"
remove_path_if_exists "$BINARY_PATH" "agent binary"
remove_path_if_exists "$BASE_DIR" "application support directory"

log "eGuard Agent uninstall completed"
