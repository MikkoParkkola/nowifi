#!/bin/bash
# Install nowifi — No WiFi? Now WiFi.
#
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/MikkoParkkola/nowifi/main/install.sh | bash
#
# Or if repo is private:
#   git clone https://github.com/MikkoParkkola/nowifi.git && cd nowifi && pip install -e .
set -e

echo ""
echo "  ┌─────────────────────────────────┐"
echo "  │  nowifi — No WiFi? Now WiFi.    │"
echo "  └─────────────────────────────────┘"
echo ""

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Darwin) PLATFORM="macOS" ;;
    Linux)  PLATFORM="Linux" ;;
    *)      echo "  Unsupported OS: $OS"; exit 1 ;;
esac

# Check Python 3.11+
if ! command -v python3 &>/dev/null; then
    echo "  Python 3 is required."
    echo ""
    if [ "$PLATFORM" = "macOS" ]; then
        echo "  Install: brew install python@3.12"
    else
        echo "  Install: sudo apt install python3 python3-pip"
    fi
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
    echo "  Python 3.11+ required (found $PY_VERSION)."
    if [ "$PLATFORM" = "macOS" ]; then
        echo "  Upgrade: brew install python@3.12"
    else
        echo "  Upgrade: sudo apt install python3.12"
    fi
    exit 1
fi
echo "  ✓ Python $PY_VERSION"

# Install nowifi
echo "  Installing nowifi..."
if [ -d ".git" ] && [ -f "pyproject.toml" ]; then
    # We're inside the repo — install in editable mode
    pip3 install -e ".[gui]" 2>&1 | tail -1
elif pip3 install nowifi 2>/dev/null; then
    # PyPI install worked
    true
else
    # Fall back to git clone
    echo "  Cloning from GitHub..."
    TMPDIR=$(mktemp -d)
    git clone --depth 1 https://github.com/MikkoParkkola/nowifi.git "$TMPDIR/nowifi" 2>&1 | tail -1
    pip3 install "$TMPDIR/nowifi" 2>&1 | tail -1
    rm -rf "$TMPDIR"
fi
echo "  ✓ nowifi installed"

# Auto-download tunnel tools
echo "  Downloading tunnel tools..."
python3 -m nowifi tools -d 2>/dev/null && echo "  ✓ Tools ready" || echo "  ⚠ Some tools unavailable (run: nowifi tools)"

# Verify
if command -v nowifi &>/dev/null; then
    VERSION=$(nowifi --version 2>&1)
    echo ""
    echo "  ✓ $VERSION"
else
    echo ""
    echo "  ✓ Installed (may need to restart terminal or add ~/.local/bin to PATH)"
fi

echo ""
echo "  Quick start:"
echo "    sudo nowifi          # auto-bypass WiFi restrictions"
echo "    nowifi diagnose      # read-only security scan"
echo "    nowifi setup         # first-time setup wizard"
echo "    nowifi doctor        # check system health"
echo ""
