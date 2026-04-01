#!/bin/bash
# Install nowifi -- No WiFi? Now WiFi.
# Usage: curl -fsSL https://raw.githubusercontent.com/MikkoParkkola/nowifi/main/install.sh | bash
set -e

echo ""
echo "  nowifi -- No WiFi? Now WiFi."
echo ""

# Check Python 3.11+
if ! command -v python3 &>/dev/null; then
    echo "Error: Python 3 is required."
    echo ""
    if [[ "$(uname)" == "Darwin" ]]; then
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
    echo "Error: Python 3.11+ required (found $PY_VERSION)."
    echo ""
    echo "  Upgrade: brew install python@3.12"
    exit 1
fi

echo "  Python $PY_VERSION OK"

# Install via pip
echo "  Installing nowifi..."
pip3 install --user git+https://github.com/MikkoParkkola/nowifi.git 2>&1 | tail -1

# Auto-download tunnel tools
echo "  Downloading tools..."
nowifi tools -d 2>/dev/null || true

echo ""
echo "  Done! Try:"
echo ""
echo "    sudo nowifi          # auto-bypass captive portal"
echo "    nowifi diagnose      # read-only assessment"
echo "    nowifi setup         # interactive setup wizard"
echo ""
