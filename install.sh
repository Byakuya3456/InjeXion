#!/bin/bash
# ============================================================
#   InjeXion (v2.0.0) Linux & Termux Installer
# ============================================================

set -e

echo "============================================================"
echo "  Installing InjeXion v2.0.0"
echo "============================================================"

# Detect Termux vs Standard Linux
if [ -n "$TERMUX_VERSION" ]; then
    echo "[*] Detected Android Termux environment."
    pkg update -y && pkg install -y python python-pip
else
    echo "[*] Detected Linux environment."
fi

# Check if uv is installed
if command -v uv &> /dev/null; then
    echo "[*] Detected uv package manager! Running fast uv sync..."
    uv sync
    echo ""
    echo "[*] Verifying installation with InjeXion doctor..."
    uv run python3 -m injexion doctor
    echo ""
    echo "============================================================"
    echo "  Installation Successful (via uv)!"
    echo "  Run InjeXion using: uv run injx scan \"http://target-url\""
    echo "  Or interactive mode: uv run python3 launcher_termux.py"
    echo "============================================================"
    exit 0
fi

# Fallback: Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed. Please install Python 3.9+ or uv."
    exit 1
fi

echo "[*] Installing Python dependencies via pip..."
pip install -e .

echo ""
echo "[*] Verifying installation with InjeXion doctor..."
python3 -m injexion doctor

echo ""
echo "============================================================"
echo "  Installation Successful!"
echo "  Run InjeXion using: injx scan \"http://target-url\""
echo "  Or interactive mode: python3 launcher_termux.py"
echo "============================================================"
