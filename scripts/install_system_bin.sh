#!/usr/bin/env bash
# ==============================================================================
# Linux Security Assessment Platform - System & Dependencies Installer
# ==============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
BIN_CLI="${REPO_DIR}/bin/sec-audit-linux"
BIN_MCP="${REPO_DIR}/bin/sec-audit-mcp"

echo "========================================================================"
echo " 🛡️  Installing Linux Security Assessment Platform & Open-Source Tools"
echo "========================================================================"

# Check for sudo / root permissions
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# 1. Detect Package Manager and Install Native Security Tools
echo "[*] Step 1/4: Detecting OS package manager and installing native audit packages..."

if command -v apt-get >/dev/null 2>&1; then
    echo "[+] Detected Debian/Ubuntu family. Updating repositories and installing packages..."
    $SUDO apt-get update -qq
    $SUDO apt-get install -y --no-install-recommends \
        lynis \
        rkhunter \
        aide \
        checksec \
        binutils \
        auditd \
        curl \
        jq \
        ca-certificates || true

elif command -v dnf >/dev/null 2>&1; then
    echo "[+] Detected RHEL/Rocky/Alma/Fedora family. Installing packages..."
    $SUDO dnf install -y epel-release || true
    $SUDO dnf install -y \
        lynis \
        rkhunter \
        aide \
        checksec \
        binutils \
        audit \
        curl \
        jq \
        ca-certificates || true

elif command -v zypper >/dev/null 2>&1; then
    echo "[+] Detected SUSE/openSUSE family. Installing packages..."
    $SUDO zypper --non-interactive install \
        lynis \
        rkhunter \
        aide \
        binutils \
        audit \
        curl \
        jq \
        ca-certificates || true

elif command -v pacman >/dev/null 2>&1; then
    echo "[+] Detected Arch Linux family. Installing packages..."
    $SUDO pacman -Sy --noconfirm lynis rkhunter aide checksec binutils audit curl jq || true

elif command -v apk >/dev/null 2>&1; then
    echo "[+] Detected Alpine Linux. Installing packages..."
    $SUDO apk add --no-cache lynis rkhunter aide binutils curl jq || true

else
    echo "[!] Warning: Unknown package manager. Skipping native package installation."
fi

# 2. Install Standalone Modern Scanners (Trivy, Syft, Grype, Docker-Bench)
echo "[*] Step 2/4: Installing container and vulnerability scanners (Trivy, Syft, Grype)..."

# Install Aqua Trivy
if ! command -v trivy >/dev/null 2>&1; then
    echo "[*] Installing Trivy into /usr/local/bin..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | $SUDO sh -s -- -b /usr/local/bin || true
fi

# Install Anchore Syft (SBOM)
if ! command -v syft >/dev/null 2>&1; then
    echo "[*] Installing Syft (SBOM generator) into /usr/local/bin..."
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | $SUDO sh -s -- -b /usr/local/bin || true
fi

# Install Anchore Grype (Vulnerability Scanner)
if ! command -v grype >/dev/null 2>&1; then
    echo "[*] Installing Grype into /usr/local/bin..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | $SUDO sh -s -- -b /usr/local/bin || true
fi

# Install Docker Bench for Security wrapper
if ! command -v docker-bench-security >/dev/null 2>&1; then
    echo "[*] Setting up Docker Bench for Security wrapper..."
    if [ ! -d "/opt/docker-bench-security" ]; then
        $SUDO mkdir -p /opt/docker-bench-security
        $SUDO curl -sSfL https://raw.githubusercontent.com/docker/docker-bench-security/master/docker-bench-security.sh -o /opt/docker-bench-security/docker-bench-security.sh || true
        if [ -f "/opt/docker-bench-security/docker-bench-security.sh" ]; then
            $SUDO chmod +x /opt/docker-bench-security/docker-bench-security.sh
            $SUDO ln -sf /opt/docker-bench-security/docker-bench-security.sh /usr/local/bin/docker-bench-security
        fi
    fi
fi

# 3. Setup Python Executables & Local User Bins
echo "[*] Step 3/4: Setting up platform CLI and MCP executables..."
chmod +x "${BIN_CLI}" "${BIN_MCP}"

if [ -n "${HOME:-}" ]; then
    mkdir -p "${HOME}/.local/bin"
    cp -f "${BIN_CLI}" "${HOME}/.local/bin/sec-audit-linux"
    cp -f "${BIN_MCP}" "${HOME}/.local/bin/sec-audit-mcp"
fi

# 4. Create System-Wide Symlinks in /usr/local/bin
echo "[*] Step 4/4: Linking executables to /usr/local/bin..."
$SUDO ln -sf "${BIN_CLI}" /usr/local/bin/sec-audit-linux
$SUDO ln -sf "${BIN_MCP}" /usr/local/bin/sec-audit-mcp

echo "========================================================================"
echo " ✅ Installation completed successfully!"
echo "========================================================================"
echo " You can now run the security platform anywhere via:"
echo "   • Non-root audit : sec-audit-linux audit --all"
echo "   • Privileged audit: sudo sec-audit-linux audit --all"
echo "   • MCP Server     : sec-audit-mcp"
echo "========================================================================"
