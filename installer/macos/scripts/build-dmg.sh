#!/bin/bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: build-dmg.sh --pkg <path-to-pkg> [--out <output-dmg>] [--volume-name <name>]
EOF
}

PKG_PATH=""
OUT_PATH=""
VOLUME_NAME="eGuard Agent Installer"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pkg)
            PKG_PATH="$2"
            shift 2
            ;;
        --out)
            OUT_PATH="$2"
            shift 2
            ;;
        --volume-name)
            VOLUME_NAME="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -z "$PKG_PATH" ]]; then
    echo "Error: --pkg is required" >&2
    exit 1
fi

if [[ ! -f "$PKG_PATH" ]]; then
    echo "Error: package not found: $PKG_PATH" >&2
    exit 1
fi

if ! command -v hdiutil >/dev/null 2>&1; then
    echo "Error: hdiutil is required and only available on macOS" >&2
    exit 1
fi

PKG_BASENAME="$(basename "$PKG_PATH")"
PKG_STEM="${PKG_BASENAME%.pkg}"

if [[ -z "$OUT_PATH" ]]; then
    OUT_PATH="$(pwd)/${PKG_STEM}.dmg"
fi

STAGING_DIR="$(mktemp -d "${TMPDIR:-/tmp}/eguard-dmg.XXXXXX")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MACOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cleanup() {
    rm -rf "$STAGING_DIR"
}
trap cleanup EXIT

cp "$PKG_PATH" "$STAGING_DIR/$PKG_BASENAME"
cp "$SCRIPT_DIR/configure-from-env.sh" "$STAGING_DIR/configure-from-env.sh"
cp "$MACOS_DIR/uninstall.sh" "$STAGING_DIR/Uninstall eGuard.command"
chmod 755 "$STAGING_DIR/configure-from-env.sh"
chmod 755 "$STAGING_DIR/Uninstall eGuard.command"

cat > "$STAGING_DIR/Install eGuard.command" <<'EOF'
#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_PATH="$(find "$SCRIPT_DIR" -maxdepth 1 -name '*.pkg' -print -quit)"
ENV_FILE="$(mktemp "${TMPDIR:-/tmp}/eguard-installer-env.XXXXXX")"
cleanup() {
    rm -f "$ENV_FILE"
}
trap cleanup EXIT
if [[ -z "$PKG_PATH" ]]; then
    osascript -e 'display alert "eGuard Installer" message "Unable to find the .pkg on this disk image." as critical'
    exit 1
fi

cat <<'EOM'
Paste your eGuard installer config block below, then press Ctrl-D.
EOM
cat > "$ENV_FILE"

if [[ ! -s "$ENV_FILE" ]]; then
    echo "No installer config was provided; aborting."
    exit 1
fi

echo "Installing package..."
sudo installer -pkg "$PKG_PATH" -target /
echo "Applying installer config and starting agent..."
sudo "$SCRIPT_DIR/configure-from-env.sh" --env-file "$ENV_FILE"
echo "eGuard install and configuration completed."
EOF

chmod 755 "$STAGING_DIR/Install eGuard.command"

cat > "$STAGING_DIR/README.txt" <<EOF
eGuard Agent macOS Installer

1. Double-click Install eGuard.command
2. Authenticate when prompted by macOS
3. Paste the eGuard installer config block from the admin UI when prompted
4. To remove the agent later, run Uninstall eGuard.command from this disk image

Artifact: ${PKG_BASENAME}
EOF

rm -f "$OUT_PATH"
hdiutil create -volname "$VOLUME_NAME" -srcfolder "$STAGING_DIR" -ov -format UDZO "$OUT_PATH"

echo "Created DMG: $OUT_PATH"
