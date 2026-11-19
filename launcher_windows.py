#!/usr/bin/env python3
"""
InjeXion - Windows Interactive Console Launcher.
Provides an interactive menu wizard optimized for Windows environments.
"""
import sys
import os

# Ensure src/ is on Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

try:
    from injexion.cli.legacy import main
    if __name__ == "__main__":
        main()
except ImportError:
    print("[!] InjeXion dependencies missing. Please run:")
    print("    pip install -r requirements.txt")
    sys.exit(1)
