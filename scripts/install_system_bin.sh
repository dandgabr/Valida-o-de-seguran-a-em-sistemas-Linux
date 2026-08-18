#!/usr/bin/env bash
# ==============================================================================
# Script to install / link sec-audit-linux system-wide in /usr/local/bin
# ==============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
BIN_CLI="${REPO_DIR}/bin/sec-audit-linux"
BIN_MCP="${REPO_DIR}/bin/sec-audit-mcp"

echo "[*] Project directory: ${REPO_DIR}"
echo "[*] Source CLI executable: ${BIN_CLI}"
echo "[*] Source MCP executable: ${BIN_MCP}"

# Ensure execute permissions
chmod +x "${BIN_CLI}" "${BIN_MCP}"

# Update ~/.local/bin as well
mkdir -p "${HOME}/.local/bin"
cp -f "${BIN_CLI}" "${HOME}/.local/bin/sec-audit-linux"
cp -f "${BIN_MCP}" "${HOME}/.local/bin/sec-audit-mcp"

# Create symlinks in /usr/local/bin (accessible by sudo and system PATH)
echo "[*] Creating symlinks in /usr/local/bin (requires sudo password)..."
sudo ln -sf "${BIN_CLI}" /usr/local/bin/sec-audit-linux
sudo ln -sf "${BIN_MCP}" /usr/local/bin/sec-audit-mcp

echo "[+] Installation complete!"
echo "[+] You can now run:"
echo "    sec-audit-linux audit --all"
echo "    sudo sec-audit-linux audit --all"
