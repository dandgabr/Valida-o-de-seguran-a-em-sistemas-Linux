#!/usr/bin/env bash
# ==============================================================================
# Script to install / link sec-audit-linux system-wide in /usr/local/bin
# ==============================================================================
set -euo pipefail

USER_BIN_DIR="$(dirname "$(dirname "$(readlink -f "$0")")")"
CURRENT_CLI="${HOME}/.local/bin/sec-audit-linux"
CURRENT_MCP="${HOME}/.local/bin/sec-audit-mcp"

echo "[*] Target CLI binary: ${CURRENT_CLI}"
echo "[*] Target MCP binary: ${CURRENT_MCP}"

if [ ! -f "${CURRENT_CLI}" ]; then
    echo "[-] Error: ${CURRENT_CLI} not found. Running local editable install first..."
    pip install -e "${USER_BIN_DIR}"
fi

echo "[*] Creating symlinks in /usr/local/bin (requires sudo)..."
sudo ln -sf "${CURRENT_CLI}" /usr/local/bin/sec-audit-linux
sudo ln -sf "${CURRENT_MCP}" /usr/local/bin/sec-audit-mcp

echo "[+] Successfully linked!"
echo "[+] You can now run: sudo sec-audit-linux audit --all"
