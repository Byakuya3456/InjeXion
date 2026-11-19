# InjeXion (`injx`)

> **Next-Gen Asynchronous Web Application Vulnerability Scanner & Payload Injector**  
> *Formerly known as PenIn2. Completely rewritten and modernized for cross-platform security testing on Android (Termux), Windows, and Linux.*

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Android%20%7C%20Windows%20%7C%20Linux-brightgreen.svg)]()
[![Async Engine](https://img.shields.io/badge/engine-httpx%20%2B%20asyncio-purple.svg)]()

```
  ___         _     __  __ _            
 |_ _|_ _  (_) ___ \ \/ /(_)___  _ _   
  | || ' \ | |/ -_) >  < | / _ \| ' \  
 |___|_||_|/ |\___|/_/\_\|_\___/|_||_| 
         |__/   [ Next-Gen Async Scanner v2.0.0 ]
```

---

## 🚀 Key Improvements in v2.0.0

- **Universal Asynchronous Engine**: Built on non-blocking `asyncio` and `httpx.AsyncClient` with adaptive connection pooling and token-bucket rate limiting.
- **Cross-Platform Dual Profiles**:
  - `mobile`: Specially tuned for Android (Termux) with low memory footprint, reduced concurrency ($\le 5$), and battery preservation.
  - `desktop`: High-throughput multi-worker engine for Windows PowerShell / Linux rigs.
- **Accurate Vulnerability Detection**:
  - **SQL Injection**: Multi-DBMS regex error matching (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) plus boolean-blind differential analysis and time-blind latency calibration.
  - **Cross-Site Scripting (XSS)**: Context-aware reflection with unique random canaries and CSP validation, eliminating false positives from JSON/API responses.
  - **Local File Inclusion (LFI)**: Systematic path traversal testing (depth 1–8) with multi-encoding and anchored OS regex checks (`/etc/passwd`, `win.ini`).
  - **Reconnaissance**: Fast async TCP port scanner and soft-404-aware sensitive directory/file discovery.
  - **Security Headers**: Evaluates HSTS, CSP, X-Frame-Options, and X-Content-Type-Options.
- **Enterprise Reporting**:
  - **HTML**: Standalone, responsive, dark-mode dashboard with KPI cards and evidence inspection (Zero CDN required).
  - **JSON**: Structured v2.0.0 machine-readable format.
  - **SARIF**: OASIS SARIF v2.1.0 for native GitHub Code Scanning integration.
- **Interactive Launchers & Compatibility**: Fully retains the interactive menu workflow through `python launcher_windows.py`, `python launcher_termux.py`, or `penin2`.

---

## 📦 Installation

### Prerequisites
- Python 3.9+ or [`uv`](https://docs.astral.sh/uv/)

### ⚡ Method 1: Using `uv` (Recommended — Ultra Fast)
If you have [uv](https://docs.astral.sh/uv/) installed, setup takes seconds with no manual virtual environment configuration:
```bash
git clone https://github.com/Byakuya3456/web-application-payloads-injector-penln2.git
cd web-application-payloads-injector-penln2

# Synchronize dependencies and virtual environment
uv sync

# Run InjeXion commands directly:
uv run injx --help
uv run injx doctor
uv run injx scan "http://testphp.vulnweb.com/listproducts.php?cat=1"

# Or run interactive launchers:
uv run python launcher_windows.py   # Windows
uv run python launcher_termux.py    # Linux / Termux
```

### 🐍 Method 2: Standard pip Installation (Windows & Linux)
```bash
git clone https://github.com/Byakuya3456/web-application-payloads-injector-penln2.git
cd web-application-payloads-injector-penln2
pip install -e .
```
Or install dependencies directly:
```bash
pip install -r requirements.txt
```

### 📱 Method 3: Android (Termux) Installation
```bash
pkg update && pkg install python
cd web-application-payloads-injector-penln2
pip install -r requirements.txt
```

---

## ⚡ Quick Start & Usage

### 1. Comprehensive Web Audit
Scan an endpoint across all detectors (SQLi, XSS, LFI, headers, and directory brute force):
```bash
python -m injexion scan "http://testphp.vulnweb.com/listproducts.php?cat=1"
```
Or using the console script:
```bash
injx scan "http://testphp.vulnweb.com/listproducts.php?cat=1"
```

### 2. Mobile Profile (Termux / Low-Memory)
```bash
injx scan "http://testphp.vulnweb.com/listproducts.php?cat=1" --profile mobile
```

### 3. Targeted Modular Scans
```bash
# SQL Injection only
injx sqli "http://testphp.vulnweb.com/listproducts.php?cat=1"

# XSS reflection & breakout
injx xss "http://testphp.vulnweb.com/search.php?test=query"

# Local File Inclusion
injx lfi "http://testphp.vulnweb.com/showimage.php?file=picture"

# Fast non-blocking port scanner
injx ports scanme.nmap.org
```

### 4. Custom Reporting
Output HTML, JSON, and SARIF reports to a custom folder:
```bash
injx scan "http://testphp.vulnweb.com/listproducts.php?cat=1" --format html,json,sarif -o ./my_reports
```

### 5. Interactive Console Mode
Run the interactive menu anytime:
```bash
python launcher_windows.py    # Windows interactive launcher
python launcher_termux.py     # Linux / Android Termux interactive launcher
penin2                        # CLI interactive wizard
```

### 6. Diagnostics
Verify environment health, terminal Unicode support, and payload datasets:
```bash
injx doctor
```

---

## 📂 Project Structure

```
injexion/
├── pyproject.toml              # PEP 621 package metadata & dependencies
├── README.md                   # Project documentation
├── requirements.txt            # Dependency manifest
├── launcher_windows.py         # Windows interactive launcher
├── launcher_termux.py          # Android Termux / Linux interactive launcher
├── sqlpayloads/                # SQL injection payload datasets
├── xss_payloads/               # XSS payload datasets
├── lfi_payloads/               # Path traversal payload datasets
├── wordlists/                  # Directory brute-force wordlists
├── src/
│   └── injexion/
│       ├── __init__.py         # Package entrypoint & version
│       ├── __main__.py         # python -m injexion runner
│       ├── cli/                # Typer & Rich CLI commands and display
│       ├── core/               # Pydantic v2 models, config, and constants
│       ├── engine/             # Async HTTP client, parameter parser, rate limiter
│       ├── detectors/          # SQLi, XSS, LFI, Headers, Dirs, Ports detectors
│       ├── payloads/           # Dynamic payload loader with fallbacks
│       └── reporters/          # Zero-CDN HTML, JSON v2, SARIF, and Console reporters
└── tests/
    └── unit/                   # Comprehensive automated test suites
```

---

## 🛡️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
