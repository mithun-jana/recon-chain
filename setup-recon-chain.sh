#!/usr/bin/env bash
#
# setup-recon-chain.sh
# Installs the OS packages + Go/Rust CLI recon tools that recon-chain's
# backend looks for via `which()`. Every tool here is optional to the app
# (it falls back to a pure-Python implementation per app/tools/*.py), but
# installing them gives you the real, faster, more accurate scanners.
#
# Tested target: Debian/Ubuntu. Run as a user with sudo, NOT as root directly
# (some steps assume $HOME is set to a real user's home).
#
# Usage:
#   chmod +x setup-recon-chain.sh
#   ./setup-recon-chain.sh            # skip anything already installed
#   ./setup-recon-chain.sh --force    # reinstall/upgrade everything anyway
#
set -euo pipefail

FORCE=0
if [ "${1:-}" = "--force" ]; then
    FORCE=1
    echo ">> --force set: will reinstall/upgrade tools even if already present"
fi

echo "=== [1/6] System packages ==="
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    nmap curl git unzip build-essential libpcap-dev libpcap0.8 \
    python3 python3-pip python3-venv ca-certificates

echo "=== [2/6] Go toolchain (needed to build the ProjectDiscovery/ffuf/gau tools) ==="
if ! command -v go >/dev/null 2>&1; then
    GO_VERSION="1.23.4"
    ARCH="$(dpkg --print-architecture)"   
    curl -fsSL -o /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$HOME/.bashrc"
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
else
    export PATH=$PATH:$HOME/go/bin
fi
go version

echo "=== [3/6] Go-based recon tools -> \$HOME/go/bin ==="
export GOTOOLCHAIN=auto


install_go_tool() {
    local bin="$1"
    local pkg="$2"
    local cgo="${3:-0}"
    if [ "$FORCE" -eq 0 ] && command -v "$bin" >/dev/null 2>&1; then
        echo "  -> $bin already installed at $(command -v "$bin"), skipping"
        return
    fi
    echo "  -> installing $bin"
    if [ "$cgo" = "1" ]; then
        CGO_ENABLED=1 go install -v "$pkg" || echo "  !! WARNING: $bin failed to build - continuing without it (app falls back to Python)"
    else
        go install -v "$pkg" || echo "  !! WARNING: $bin failed to build - continuing without it (app falls back to Python)"
    fi
}

install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
install_go_tool httpx    github.com/projectdiscovery/httpx/cmd/httpx@latest
install_go_tool dnsx     github.com/projectdiscovery/dnsx/cmd/dnsx@latest
install_go_tool ffuf     github.com/ffuf/ffuf/v2@latest
install_go_tool gau      github.com/lc/gau/v2/cmd/gau@latest
install_go_tool naabu    github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 1
install_go_tool katana   github.com/projectdiscovery/katana/cmd/katana@latest 1

echo "=== [4/6] feroxbuster (prebuilt Rust binary) ==="
if [ "$FORCE" -eq 0 ] && command -v feroxbuster >/dev/null 2>&1; then
    echo "  -> feroxbuster already installed at $(command -v feroxbuster), skipping"
else
    FX_ARCH="$(dpkg --print-architecture)"
    case "$FX_ARCH" in
      amd64) FX_FILE="x86_64-linux-feroxbuster.zip" ;;
      arm64) FX_FILE="aarch64-linux-feroxbuster.zip" ;;
      *) echo "Unsupported arch for feroxbuster: $FX_ARCH - skipping"; FX_FILE="" ;;
    esac
    if [ -n "$FX_FILE" ]; then
        curl -fsSL -o /tmp/ferox.zip \
          "https://github.com/epi052/feroxbuster/releases/latest/download/${FX_FILE}" \
          || echo "  !! WARNING: feroxbuster download failed - continuing without it (app falls back to ffuf/Python)"
        if [ -f /tmp/ferox.zip ]; then
            sudo unzip -o /tmp/ferox.zip -d /usr/local/bin
            sudo chmod +x /usr/local/bin/feroxbuster
        fi
    fi
fi

echo "=== [5/7] Grant naabu/nmap raw-socket capability (no root needed to run scans) ==="
NAABU_BIN="$HOME/go/bin/naabu"
if [ -f "$NAABU_BIN" ]; then
    sudo setcap cap_net_raw,cap_net_admin=eip "$NAABU_BIN" || true
fi
NMAP_BIN="$(command -v nmap || true)"
if [ -n "$NMAP_BIN" ]; then
    sudo setcap cap_net_raw,cap_net_admin=eip "$NMAP_BIN" || true
fi

echo "=== [6/7] Python backend deps + Playwright (real screenshots) ==="
cd "$(dirname "$0")"
if [ -d "recon-chain/backend" ]; then
    cd recon-chain/backend
    if [ -d .venv ] && [ "$FORCE" -eq 0 ]; then
        echo "  -> .venv already exists, reusing it"
    else
        python3 -m venv .venv
    fi
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    pip install playwright
    playwright install --with-deps chromium
    deactivate
else
    echo "recon-chain/backend not found next to this script - skipping Python setup."
    echo "Run: pip install -r backend/requirements.txt && pip install playwright && playwright install --with-deps chromium"
fi
echo ""
echo "=== Verifying installed tools ==="
for t in nmap subfinder httpx dnsx naabu katana ffuf gau feroxbuster; do
    if command -v "$t" >/dev/null 2>&1; then
        ver="$("$t" -version 2>&1 | head -1 || true)"
        printf "  [OK]   %-12s %s\n" "$t" "${ver:-installed}"
    else
        printf "  [MISS] %-12s not found (app will use its Python fallback)\n" "$t"
    fi
done

echo ""
echo "=== Done ==="
echo "Make sure \$HOME/go/bin is on your PATH in NEW shells too - it was only"
echo "exported for this script run. Add this line to ~/.bashrc (or ~/.zshrc)"
echo "if it's not already there, then open a new terminal:"
echo "  export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin"
echo ""

