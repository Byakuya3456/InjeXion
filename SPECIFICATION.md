# InjeXion: Modernization Technical Specification & Implementation Plan
*Comprehensive Engineering Blueprint for Upgrading PenIn2 into an Enterprise-Grade Vulnerability Scanner*

**Document Version**: 2.0.1-PROD-SPEC (Post-Review Revision)  
**Author**: Project Orchestrator (teamwork_orchestrator)  
**Date**: 2026-11-07  
**Project Identifier**: `injexion` (formerly `penin2` / `web-application-payloads-injector-penln2`)  
**Status**: Authoritative Technical Architecture & Implementation Blueprint (Audited & Approved)  

---

## Table of Contents
1. [Executive Summary & Modernization Vision](#1-executive-summary--modernization-vision)
2. [Brand & Naming Overhaul](#2-brand--naming-overhaul)
3. [Legacy Codebase Audit & Defect Catalog](#3-legacy-codebase-audit--defect-catalog)
4. [Modern Architecture & Packaging Design](#4-modern-architecture--packaging-design)
5. [Async Network Engine & Universal Parameter Parser](#5-async-network-engine--universal-parameter-parser)
6. [Advanced High-Fidelity Detection Engines](#6-advanced-high-fidelity-detection-engines)
   - [6.1 Smart Multi-DBMS SQL Injection Engine](#61-smart-multi-dbms-sql-injection-engine)
   - [6.2 Context-Aware Cross-Site Scripting (XSS) Engine](#62-context-aware-cross-site-scripting-xss-engine)
   - [6.3 Systematic Path Traversal & LFI Engine](#63-systematic-path-traversal--lfi-engine)
   - [6.4 Expanded Reconnaissance & Auditing Modules](#64-expanded-reconnaissance--auditing-modules)
7. [Professional Multi-Format Reporting Engine](#7-professional-multi-format-reporting-engine)
   - [7.1 Zero-CDN Standalone Interactive HTML Report](#71-zero-cdn-standalone-interactive-html-report)
   - [7.2 Machine-Readable JSON v2.0.0 Specification](#72-machine-readable-json-v200-specification)
   - [7.3 OASIS SARIF v2.1.0 Specification](#73-oasis-sarif-v210-specification)
8. [Cross-Platform Compatibility & Installation Architecture](#8-cross-platform-compatibility--installation-architecture)
9. [Migration Guide & Backward Compatibility](#9-migration-guide--backward-compatibility)
10. [Milestone Roadmap & Implementation Schedule](#10-milestone-roadmap--implementation-schedule)

---

## 1. Executive Summary & Modernization Vision

The workspace contains "PenIn2" (also referenced in directory naming as `penln2`), an early-stage web penetration testing and payload injection script. While the original concept aimed to provide an accessible payload injection tool for mobile (Android Termux) and desktop environments, deep codebase exploration reveals foundational architectural and technical flaws that prevent reliable operational use.

### Primary Deficiencies of Legacy PenIn2:
- **Severe Code Duplication**: Two parallel monolithic scripts (`t6.py` for Windows and `tm.py` for Linux/Termux) sharing >95% identical code, creating synchronization divergence.
- **Broken Packaging & Dependencies**: `t6.py` imports `matplotlib.pyplot`, which is completely missing from `requirements.txt`. Running `t6.py` on a standard environment immediately crashes with `ModuleNotFoundError`.
- **Corrupted Project Files**: Unresolved Git merge conflict markers (`<<<<<<< HEAD` / `=======`) left in `README.md`, terminating mid-sentence at line 103.
- **Flawed Detection Heuristics**: Direct string concatenation of URLs without parameter parsing (`url + payload`), and naive substring checks (`"error"` in response triggers Critical SQLi; `"root"` triggers Critical LFI on any React single-page app containing `<div id="root">`).
- **Data Contamination**: Payload files contain unparsed Markdown documentation, unquoted explanation notes, private LAN IP addresses (`192.168.1.6`), and raw Android media store download URIs.
- **Brittle Concurrency & Zero CI/CD Support**: Thread-unsafe mutation of global data structures; blocking interactive `input()` prompts with no CLI flags.

### The Modernization Blueprint: InjeXion
This specification establishes the complete technical blueprint to modernize the tool into **InjeXion** (`injx`):
1. **Rebranding**: A distinctive, enterprise-credible identity with punchy CLI ergonomics (`injx`).
2. **Modern Architecture**: Clean `src/` layout, PEP 621 compliant `pyproject.toml` with `hatchling`, console entrypoints, and tiered dependencies.
3. **Async Network Engine**: Non-blocking `httpx` + `asyncio` engine with connection pooling, adaptive token-bucket rate limiting, dynamic probe timeouts, and dual profiles (Mobile/Termux vs Desktop).
4. **Universal Parameter Parser**: Precise injection into query parameters, HTTP headers, form-urlencoded data, and nested JSON bodies using One-Variable-at-a-Time (OVAT) isolation.
5. **High-Fidelity Detection Engines**: Anchored DBMS error regexes (MySQL, PostgreSQL, MSSQL, Oracle, SQLite), Boolean-blind relative differential analysis, calibrated time-blind verification with dynamic timeout extension, two-stage context-aware canary XSS verification, and systematic depth LFI.
6. **Multi-Format Reporting**: Standalone zero-CDN interactive HTML reports, structured JSON v2.0.0, and OASIS SARIF v2.1.0 export with full markdown help for GitHub Code Scanning.
7. **Universal Portability**: Zero-friction setup and execution on Android Termux (with Termux wheel index support), Windows PowerShell/Terminal (with VT100/UTF-8 activation), and Linux/macOS.

---

## 2. Brand & Naming Overhaul

### 2.1 Brand Defect Analysis: Legacy "PenIn2"
The name "PenIn2" poses severe branding, phonetic, and typographic liabilities:
1. **Typographic Glyphic Collision**: In sans-serif fonts, uppercase 'I' and lowercase 'l' are identical (`PenIn2` vs `penln2`). This caused the project folder to be named `...-penln2` while documentation referred to `PenIn2`.
2. **Phonetic & Colloquial Risk**: "PenIn" phonetically evokes anatomical slang, causing embarrassment and friction in formal corporate demonstrations, security audits, and board-level presentations.
3. **Semantic Limitations**: Implies a rudimentary script rather than a modern security framework.

### 2.2 Candidate Evaluation Matrix
Six candidate identities were evaluated across five weighted criteria (1.0 to 5.0 scale):

| Evaluation Dimension | Weight | InjeXion | AegisScan | PayloadForge | CerberusSec | PenPulse | Vulnix |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Security Semantics** | 25% | 5.0 | 4.0 | 4.5 | 3.5 | 3.8 | 4.2 |
| **CLI Ergonomics** | 20% | 5.0 (`injx`) | 3.5 (`aegis`) | 3.0 (`pforge`) | 2.5 (`cerb`) | 3.8 (`pulse`) | 4.5 (`vulnx`) |
| **Phonetic Clarity** | 20% | 5.0 | 4.5 | 4.5 | 3.8 | 4.0 | 4.5 |
| **Enterprise Credibility**| 20% | 4.5 | 5.0 | 4.2 | 4.5 | 3.5 | 4.0 |
| **Ecosystem Distinction** | 15% | 4.8 | 3.0 | 4.0 | 3.5 | 3.2 | 4.0 |
| **Weighted Total Score** | **100%** | **4.77** | **4.05** | **4.06** | **3.56** | **3.69** | **4.24** |

### 2.3 The Selected Identity: InjeXion
- **Official Brand Name**: **InjeXion**
- **Primary CLI Binary**: `injx`
- **Full CLI Command**: `injexion`
- **Legacy Compatibility Shim**: `penin2`
- **Official Tagline**: *High-Throughput Vulnerability Assessment & Payload Injection Engine*
- **Positioning**: An asynchronous, cross-platform security auditing engine engineered for security professionals and automated CI/CD pipelines, delivering high-speed fuzzing with mathematically rigorous, zero-false-positive detection heuristics.

#### Terminal ASCII Art Banner
```
  ___       _     __  __ _             
 |_ _|_ __ (_)___ \ \/ /(_)___  _ __   
  | || '_ \| / _ \ \  / | / _ \| '_ \  
  | || | | | |  __/ /  \ | | (_) | | | | 
 |___|_| |_|/ \___|/_/\_\|_|\___/|_| |_| 
          |__/                           
 High-Throughput Vulnerability Assessment Engine • v2.0.0
```

---

## 3. Legacy Codebase Audit & Defect Catalog

A line-by-line audit of the existing codebase identified the following critical vulnerabilities and design flaws:

```
+----------------------------------------------------------------------------------------------------+
|                                    LEGACY PENIN2 DEFECT CATALOG                                    |
+----------------------------------------------------------------------------------------------------+
  1. DUPLICATE MONOLITHS        t6.py (319 lines) and tm.py (284 lines) have 95%+ identical code.
                                Only difference is matplotlib import and static chart generation in t6.py.
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  2. MISSING DEPENDENCY         t6.py imports matplotlib.pyplot, but requirements.txt lists only
                                'requests' and 'urllib3'. Immediate crash on clean install.
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  3. CORRUPT REPOSITORY         README.md contains raw Git merge conflict markers (<<<<<<< HEAD)
                                and truncates at line 103 mid-sentence. Root contains orphan duplicate files.
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  4. ZERO PARAMETER PARSING     Injects via raw string concatenation: requests.get(url + payload).
                                Intermediate query params, POST bodies, JSON, and headers are ignored.
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  5. CATASTROPHIC FALSE SQLi    Checks if "error" in response.text or "syntax" in response.text.
                                Any normal web page with error messages triggers Critical SQLi alerts.
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  6. CONTEXT-BLIND XSS          Checks if payload in response.text. Correctly HTML-escaped tokens
                                or reflected search terms in canonical links trigger Critical XSS alerts.
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  7. BROKEN LFI LOGIC           Python list multiplication bug: ["../", "..\\"] * randint produces
                                multiple single-hop paths instead of nested traversals (e.g. ../../../../).
                                Checks if "root" in response.text, flagging any React SPA (<div id="root">).
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  8. DATA CONTAMINATION         Payload files contain raw Markdown docs, cheat sheet notes, private
                                IP addresses (192.168.1.6), and Android file manager download paths.
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  9. THREAD-UNSAFE RUNTIME      ThreadPoolExecutor(max_workers=10) concurrently mutates shared global
                                dicts and appends to report files without locks, causing race conditions.
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  10. NON-AUTOMATABLE CLI       Relies on blocking input("Enter target URL: "). Cannot be automated in
                                pipelines. Hardcoded ANSI escape sequences garble legacy Windows CMD.
```

---

## 4. Modern Architecture & Packaging Design

### 4.1 Modern `src/` Layout
To prevent import parity hazards and build pollution, InjeXion uses a strict `src/` layout:

```
web-application-payloads-injector-penln2/
├── pyproject.toml                     # PEP 621 metadata, dependencies & tool configs
├── README.md                          # Comprehensive user documentation & quickstart
├── LICENSE                            # MIT License with Attribution Retention
├── .gitignore                         # Build, environment, and cache artifacts
├── src/
│   └── injexion/
│       ├── __init__.py                # __version__ = "2.0.0"
│       ├── __main__.py                # python -m injexion entrypoint
│       ├── py.typed                   # PEP 561 typing marker
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── app.py                 # Primary Typer app initialization
│       │   ├── legacy.py              # Backward-compatible penin2 interactive wizard shim
│       │   ├── commands/              # Subcommands: scan, quick, probe, payloads, report, doctor
│       │   │   ├── scan.py
│       │   │   ├── quick.py
│       │   │   ├── probe.py
│       │   │   ├── payloads.py
│       │   │   ├── report.py
│       │   │   └── doctor.py
│       │   └── display/               # Banner, live progress, rich tables, terminal compat
│       │       ├── banner.py
│       │       ├── live.py
│       │       ├── tables.py
│       │       └── term_compat.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── config.py              # Pydantic v2 ScanConfig with profile defaults
│       │   ├── constants.py           # Severities, ports, default headers, exit codes
│       │   ├── exceptions.py          # Typed domain exceptions hierarchy
│       │   └── models.py              # Finding, HttpEvidence, InjectionTarget, ScanMetadata
│       ├── engine/
│       │   ├── __init__.py
│       │   ├── client.py              # AsyncHTTPClient wrapper (httpx, pooling, retries, dynamic timeouts)
│       │   ├── dispatcher.py          # Concurrency scheduler & semaphore manager
│       │   ├── parameter.py           # Universal request parser (query, headers, JSON, forms)
│       │   └── rate_limiter.py        # Token bucket rate limiter with adaptive backoff
│       ├── detectors/
│       │   ├── __init__.py
│       │   ├── base.py                # BaseDetector abstract contract
│       │   ├── sqli.py                # Multi-DBMS error regex, boolean blind, time blind
│       │   ├── xss.py                 # Two-stage context-aware reflection XSS
│       │   ├── lfi.py                 # Systematic depth traversal & anchored regex
│       │   ├── headers.py             # Security headers auditor (HTTPS gated HSTS)
│       │   ├── dirs.py                # Soft-404 aware directory & file brute-forcer
│       │   └── ports.py               # Async non-blocking TCP port scanner
│       ├── payloads/
│       │   ├── __init__.py
│       │   ├── manager.py             # Payload pack loader, cleaner & deduplicator
│       │   └── data/                  # Curated, sanitized standard payload packs
│       │       ├── sqli/
│       │       ├── xss/
│       │       ├── lfi/
│       │       └── wordlists/
│       └── reporters/
│           ├── __init__.py
│           ├── base.py                # BaseReporter abstract contract
│           ├── console.py             # Rich console output reporter
│           ├── json_rep.py            # Machine-readable JSON v2.0.0 exporter
│           ├── sarif.py               # OASIS SARIF v2.1.0 exporter with GitHub help markdown
│           └── html/                  # Standalone interactive HTML report generator
│               ├── generator.py
│               └── template.html
└── tests/
    ├── conftest.py                    # Pytest fixtures and mock HTTP servers
    ├── unit/                          # Unit tests for CLI, models, parsers, reporters
    └── integration/                   # Integration tests for async detection modules
```

### 4.2 Standard `pyproject.toml` Specification
InjeXion utilizes `hatchling` as the modern build backend, eliminating platform C/C++ compilation overhead and enabling pure-Python installation across Android Termux, Windows, and Linux.

```toml
[build-system]
requires = ["hatchling>=1.21.0"]
build-backend = "hatchling.build"

[project]
name = "injexion"
version = "2.0.0"
description = "High-Throughput Vulnerability Assessment & Payload Injection Engine"
readme = "README.md"
requires-python = ">=3.10"
license = { text = "MIT" }
authors = [
    { name = "InjeXion Core Team", email = "security@injexion.dev" }
]
keywords = [
    "security",
    "penetration-testing",
    "vulnerability-scanner",
    "payload-injector",
    "sqli",
    "xss",
    "lfi",
    "sarif",
    "termux"
]
dependencies = [
    "httpx>=0.27.0",
    "typer>=0.12.0",
    "rich>=13.7.0",
    "pydantic>=2.6.0",
    "anyio>=4.3.0",
]

[project.optional-dependencies]
reporting = [
    "jinja2>=3.1.3",
    "pyyaml>=6.0.1",
]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "pytest-cov>=4.1.0",
    "respx>=0.21.0",
    "ruff>=0.3.0",
    "mypy>=1.9.0",
]

[project.scripts]
injx = "injexion.cli.app:main"
injexion = "injexion.cli.app:main"
penin2 = "injexion.cli.legacy:main"

[tool.hatch.build.targets.wheel]
packages = ["src/injexion"]

[tool.hatch.build.targets.wheel.sources]
"src/injexion/payloads/data" = "injexion/payloads/data"
"src/injexion/reporters/html/template.html" = "injexion/reporters/html/template.html"

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

---

## 5. Async Network Engine & Universal Parameter Parser

### 5.1 Async Network Architecture (`httpx` + `asyncio`)
The core network subsystem replaces synchronous thread-blocking sockets and `requests` with an asynchronous connection-pooled client.

#### Adaptive Dual Profiles:
1. **Mobile / Termux Profile**:
   - Connection pool: Max 10 connections, 5 keep-alives.
   - Concurrency ceiling: 3–5 simultaneous tasks.
   - Body buffering: Stream response bodies exceeding 512 KB to avoid OOM killer on Android.
   - Timeouts: 12.0s connect/read to accommodate high-latency mobile networks.
2. **Desktop / High-Throughput Profile**:
   - Connection pool: Max 100 connections, 30 keep-alives.
   - Concurrency ceiling: 20–50 simultaneous tasks.
   - Body buffering: In-memory parsing up to 5 MB.
   - Timeouts: 5.0s connect, 8.0s read default.

#### Dynamic Probe Timeout Extension:
To prevent premature `httpx.ReadTimeout` abortions during time-blind SQL injection verification, `AsyncHTTPClient.request()` and `TimeBlindSQLiDetector` dynamically compute the request timeout for deliberate delay probes:
```python
request_timeout = max(config.timeout_read, expected_delay + baseline_mean + 5.0)
```
For example, a secondary delay probe of $7.0\text{s}$ against an endpoint with $1.5\text{s}$ baseline latency executes with a safe $13.5\text{s}$ timeout, fully preventing timeout collision while maintaining strict bounds.

#### Token-Bucket Rate Limiter & Backoff:
- Enforces user-configured rate limits (e.g. `--rate-limit 20` req/sec).
- Inspects HTTP responses for `429 Too Many Requests` or `503 Service Unavailable`.
- Respects `Retry-After` headers if present.
- Implements full-jitter exponential backoff:
  $$T_{\text{wait}} = \min(30.0, 1.0 \times 2^{\text{attempt}}) + \text{random}(0.0, 1.0)$$
- Dynamically reduces the concurrency semaphore by 50% during throttle events until 20 consecutive successful requests return.

### 5.2 Universal Parameter Parser & Mutation Engine
Unlike legacy PenIn2 which appends strings to the URL, InjeXion defines an `InjectionTarget` model that isolates and tests each request parameter independently using One-Variable-at-a-Time (OVAT) isolation.

```
Target Request Surface:
├── 1. URL Query String:   https://example.com/item?id=10&cat=shoes
│                          -> Mutates 'id' while keeping 'cat=shoes' intact
├── 2. HTTP Headers:       User-Agent, Referer, Cookie, X-Forwarded-For
│                          -> Injects into header values while preserving syntax
├── 3. Form-URLEncoded:    POST /login body: username=admin&pass=secret
│                          -> Mutates individual field values
└── 4. JSON Bodies:        POST /api body: {"user": {"profile": {"name": "alice"}}}
                           -> Recursive JSONPath traversal; mutates leaf values
                              without invalidating JSON grammar
```

---

## 6. Advanced High-Fidelity Detection Engines

### 6.1 Smart Multi-DBMS SQL Injection Engine

#### A. Multi-DBMS Error Regex Signatures
Eliminates naive substring matching (`"error"`, `"syntax"`) by requiring anchored regular expressions matching specific database engine error signatures (with unescaped alternation pipes):

| DBMS Target | Error Identification Pattern (Regular Expression) |
|---|---|
| **MySQL / MariaDB** | `(?:SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result|MySqlException|check the manual that corresponds to your (?:MySQL\|MariaDB) server version)` *(Corrected to unescaped pipe)*: `(?:SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result|MySqlException|check the manual that corresponds to your (?:MySQL|MariaDB) server version)` |
| **PostgreSQL** | `(?:PostgreSQL.*ERROR|Warning.*\bpg_.*|valid PostgreSQL result|Npgsql\.|PG::SyntaxError|unterminated quoted string at or near)` |
| **Microsoft SQL Server** | `(?:Driver.*SQL Server|OLE DB.*SQL Server|\[SQL Server\]|Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server)` |
| **Oracle Database** | `(?:ORA-\d{5}|Oracle error|Oracle.*Driver|Warning.*\boci_.*|Warning.*\bora_.*)` |
| **SQLite** | `(?:SQLite/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException|unrecognized token:|near ".*": syntax error)` |
| **Generic / ODBC** | `(?:ODBC SQL Server Driver|ODBC Driver.*for SQL Server|Microsoft Access Database Engine|Syntax error in string in query expression)` |

#### B. Boolean-Based Blind Relative Differential Analysis
Detects SQL injection where no database error messages are displayed:
1. **Baseline Capture ($R_0$)**: Send benign request to establish normal response length, HTTP status code, and content fingerprint.
2. **True Condition Probe ($T$)**: Inject a condition mathematically guaranteed to evaluate to True:
   - Numerical parameter: `10 AND 1=1` or `10 AND 5=5`
   - String parameter: `' AND '1'='1` or `' OR 'a'='a`
3. **False Condition Probe ($F$)**: Inject a condition mathematically guaranteed to evaluate to False:
   - Numerical parameter: `10 AND 1=2` or `10 AND 5=6`
   - String parameter: `' AND '1'='2` or `' OR 'a'='b`
4. **Differential Evaluation Algorithm**:
   - Strip dynamic tokens (timestamps, CSRF nonces, session nonces) and strip non-text DOM nodes (`<script>`, `<style>`, navigation boilerplate).
   - Evaluate relative differential ratio rather than rigid absolute thresholds:
     $$\text{Sim}(R_0, T) \ge 0.95 \quad \text{AND} \quad (\text{Sim}(R_0, T) - \text{Sim}(R_0, F)) \ge 0.05$$
   - This relative delta reliably detects SQL injection on modern 50KB–100KB pages where static layout boilerplate accounts for >85% of total HTML characters.

#### C. Time-Based Blind Verification with Latency Calibration
Detects vulnerabilities where application output does not reflect query results:
1. **Pre-flight Baseline Calibration**: Issue 3 consecutive un-injected requests to compute baseline network latency mean ($\mu_{\text{base}}$) and standard deviation ($\sigma_{\text{base}}$). If $\sigma_{\text{base}} > 1.5\text{s}$, the endpoint network is unstable; abort time-based testing to prevent false positives.
2. **Primary Delay Probe ($D_1 = 4.0\text{s}$)**: Inject DBMS-specific sleep function (e.g. `SLEEP(4)` for MySQL, `pg_sleep(4)` for Postgres, `WAITFOR DELAY '0:0:4'` for MSSQL) with dynamic timeout `max(timeout, D_1 + \mu_{\text{base}} + 5.0\text{s})`.
3. **Latency Verification**: Measured duration $t_1$ must satisfy:
   $$t_1 \ge \mu_{\text{base}} + D_1 - 0.5\text{s}$$
4. **Proportional Multiplier Confirmation ($D_2 = 7.0\text{s}$)**: Inject secondary delay of 7.0 seconds with dynamic timeout `max(timeout, D_2 + \mu_{\text{base}} + 5.0\text{s})`. The measured duration $t_2$ must scale proportionally ($t_2 \ge \mu_{\text{base}} + D_2 - 0.5\text{s}$). This double-check strictly eliminates random network lag spikes.

---

### 6.2 Context-Aware Cross-Site Scripting (XSS) Engine

#### A. Two-Stage Probing Architecture
Replaces contaminated payloads with a rigorous two-stage verification process:
- **Stage 1 (Reflection & Context Discovery)**:
  Inject a unique, benign alphanumeric canary token (e.g. `inx7f3a9e1b`). If reflected in the response, parse the document structure to determine the reflection context:
  1. *HTML Tag Body* (between elements)
  2. *HTML Attribute Value* (inside `value="..."`)
  3. *JavaScript Script Block* (inside `<script>...</script>`)
  4. *HTML Comment* (inside `<!-- ... -->`)
- **Stage 2 (Context-Tailored Breakout Verification)**:
  Inject a tailored test probe containing only the specific execution-break characters required for that context:
  - For HTML Body: `<b>inx7f3a9e1b</b>` -> Confirms if `<` and `>` are unescaped (not `&lt;` / `&gt;`).
  - For Attribute Value: `"inx7f3a9e1b` or `'inx7f3a9e1b` -> Confirms if enclosing quote is unescaped.
  - For Script Block: `</script><script>inx7f3a9e1b</script>` or `"-inx7f3a9e1b-"` -> Confirms tag break or string break.
  - For Comment: `-->inx7f3a9e1b<!--` -> Confirms comment delimiter closure.

#### B. Content-Type & Defensive Header Gating
- If response `Content-Type` is `application/json`, `text/plain`, or `application/octet-stream`, reflection cannot execute in standard browsers; downgrade or discard finding.
- Evaluate `Content-Security-Policy` (CSP): If strict `script-src` without `'unsafe-inline'` is enforced, reflect this mitigation in the finding severity.

---

### 6.3 Systematic Path Traversal & LFI Engine

#### A. Depth Expansion Matrix
Fixes the legacy Python multiplication bug by generating systematic directory traversal depths from 1 to 8 hops:
```python
traversal_depths = [
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../../../../../",
    "../../../../../../",
    "../../../../../../../",
    "../../../../../../../../",
]
```

#### B. Multi-Encoding Matrix
Tests multiple encoding formats to identify path normalization flaws:
1. **Standard UNIX**: `../../../../etc/passwd`
2. **Standard Windows**: `..\\..\\..\\..\\windows\\win.ini`
3. **URL-Encoded**: `%2e%2e%2f%2e%2e%2fetc%2fpasswd`
4. **Double URL-Encoded**: `%252e%252e%252f%252e%252e%252fetc%252fpasswd`
5. **Overlong UTF-8**: `%c0%ae%c0%ae%c0%afetc%c0%afpasswd`
6. **Dot-Slash-Bypass**: `....//....//etc/passwd`
7. **Null-Byte Injection** (for legacy targets): `../../../../etc/passwd%00`

#### C. Anchored Regular Expression Verification
Eliminates naive `"root"` or `"boot.ini"` substring matching:
- **UNIX Target (`/etc/passwd`)**:
  `r"(?m)^[a-z_][a-z0-9_-]*:[x*!]?:\d+:\d+:[^:]*:[^:]*:(?:/[^:]*|/[a-z0-9_-]+)$"`
  Requires strict validation of UNIX passwd structure, accounting for service accounts with `*` or `!`.
- **Windows Target (`win.ini`)**:
  `r"(?i)\[(?:fonts|extensions|mci extensions|files)\]"`
  Matches standard Windows INI sections while ignoring modern obsolete `boot.ini`.
- **Baseline Delta Check**: The response containing the matched file signature must NOT match the baseline response, preventing false positives on tutorial pages displaying `/etc/passwd` examples.

---

### 6.4 Expanded Reconnaissance & Auditing Modules

#### A. Security Headers Audit
Analyzes HTTP response headers against OWASP Secure Headers recommendations:
- **Missing Defensive Headers**: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
- **HSTS Gate**: `Strict-Transport-Security` is audited **only** when the target scheme is `https://` (per RFC 6797).
- **Information Disclosure Headers**: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`.

#### B. Soft-404 & Catch-All Redirect-Aware Directory Discovery
- **Canary Pre-flight**: Before testing wordlists, requests a random 16-character alphanumeric path (e.g. `/inx_probe_4f8a2b/`).
  * If the server returns HTTP 200, dynamic soft-404 routing is active. Fingerprints the body length and structure.
  * If the server returns a redirect (301/302/307), record the target `Location` header.
- **Suppression Logic**: Any wordlist probe returning a redirect to that identical catch-all `Location` is suppressed, eliminating up to 1,000 false positives on Next.js/WordPress catch-all setups.
- **Optimized Probing**: Utilizes `HEAD` requests first to conserve bandwidth, falling back to `GET` only upon receipt of positive status codes.

#### C. Asynchronous TCP Port Scanner
- Replaces synchronous thread-pool sockets with non-blocking `asyncio.open_connection()`.
- Supports common web and infrastructure ports (21, 22, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 27017).
- Automatically parses target hostnames from URLs (`https://example.com:8443/` -> `example.com`), preventing `TypeError: getaddrinfo() argument 1 must be string or None` crashes.
- Implements non-destructive service banner grabbing on open connections.

---

## 7. Professional Multi-Format Reporting Engine

### 7.1 Zero-CDN Standalone Interactive HTML Report
The HTML reporter generates a single, fully self-contained HTML file with embedded CSS and vanilla JavaScript. It requires **zero external network requests**, ensuring immediate rendering in air-gapped pentest environments and local filesystem browsers.

#### Key UI Components:
1. **Executive KPI Dashboard**: Total vulnerabilities, scan duration, endpoints tested, and severity count breakdown (Critical, High, Medium, Low, Info).
2. **Interactive Severity Filter**: One-click toggles to isolate Critical and High issues.
3. **Collapsible Finding Cards**:
   - Title, severity badge, affected parameter, category, and CWE / OWASP mapping.
   - Interactive side-by-side HTTP Request and HTTP Response viewer highlighting the payload and matched signature snippet.
   - Tailored remediation instructions and code mitigation snippets.
4. **Target & Scan Metadata Table**: Start/end timestamps, InjeXion version, configuration profile, target base URL.

### 7.2 Machine-Readable JSON v2.0.0 Specification
A strict, schema-validated JSON format for integration into custom security dashboards and data pipelines:

```json
{
  "$schema": "https://raw.githubusercontent.com/injexion/injexion/main/schemas/v2/report.schema.json",
  "version": "2.0.0",
  "scan_metadata": {
    "scanner_name": "InjeXion",
    "scanner_version": "2.0.0",
    "scan_profile": "desktop",
    "target_url": "https://example.com/api",
    "start_time": "2026-11-07T10:45:00Z",
    "end_time": "2026-11-07T10:48:32Z",
    "duration_seconds": 212.4,
    "total_requests": 642,
    "concurrency_limit": 30
  },
  "summary": {
    "total_findings": 3,
    "severity_counts": {
      "CRITICAL": 1,
      "HIGH": 1,
      "MEDIUM": 1,
      "LOW": 0,
      "INFO": 0
    }
  },
  "findings": [
    {
      "id": "f8a92b1c-7e3d-4c2a-9f1e-0a8b7c6d5e4f",
      "title": "SQL Injection in User Search Parameter",
      "category": "sqli",
      "severity": "CRITICAL",
      "target_url": "https://example.com/api/search",
      "parameter": "query",
      "injection_type": "query",
      "payload": "' OR 1=1--",
      "description": "The endpoint is vulnerable to error-based SQL injection, exposing internal PostgreSQL database syntax.",
      "evidence": {
        "request_url": "https://example.com/api/search?query=%27+OR+1%3D1--",
        "request_method": "GET",
        "request_headers": { "User-Agent": "InjeXion/2.0.0" },
        "request_body": null,
        "response_status": 500,
        "response_headers": { "Content-Type": "text/html; charset=utf-8" },
        "response_body_snippet": "PG::SyntaxError: unterminated quoted string at or near...",
        "matched_signature": "unterminated quoted string at or near"
      },
      "remediation": "Use parameterized queries or prepared statements (e.g. PDO, psycopg2, ORM) rather than string concatenation.",
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021-Injection",
      "cvss_score": 9.8,
      "timestamp": "2026-11-07T10:46:12Z"
    }
  ]
}
```

### 7.3 OASIS SARIF v2.1.0 Specification
InjeXion produces standard SARIF (Static Analysis Results Interchange Format) v2.1.0 JSON files ready for native upload to GitHub Code Scanning, GitLab Security Dashboard, and Azure DevOps, including full `rule.help.markdown` and `ruleIndex`:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "InjeXion",
          "semanticVersion": "2.0.0",
          "informationUri": "https://github.com/injexion/injexion",
          "rules": [
            {
              "id": "INJX-SQLI-001",
              "name": "SqlInjectionErrorBased",
              "shortDescription": { "text": "Error-based SQL Injection detected." },
              "fullDescription": { "text": "A parameter reflected database syntax error signatures upon injection of test characters." },
              "help": {
                "text": "Use parameterized queries or prepared statements to separate query logic from user input.",
                "markdown": "### Remediation Guidance\n\nEnsure that all database queries utilize parameterized inputs rather than direct string interpolation.\n\n* **Python**: Use `cursor.execute('SELECT * FROM tbl WHERE id = %s', (val,))`\n* **Node.js**: Use parameterized queries with pg or mysql2\n* **PHP**: Use PDO prepared statements with `bindParam`."
              },
              "defaultConfiguration": { "level": "error" },
              "properties": {
                "tags": ["security", "injection", "database"],
                "precision": "high",
                "problem.severity": "error"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "INJX-SQLI-001",
          "ruleIndex": 0,
          "level": "error",
          "message": {
            "text": "SQL Injection discovered at https://example.com/api/search via parameter 'query'."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "https://example.com/api/search" }
              }
            }
          ],
          "properties": {
            "parameter": "query",
            "cwe": "CWE-89",
            "cvss": 9.8
          }
        }
      ]
    }
  ]
}
```

---

## 8. Cross-Platform Compatibility & Installation Architecture

InjeXion is engineered for three primary deployment environments:

### 8.1 Android Termux (ARM64 / ARM32)
Termux environments lack precompiled wheels for `pydantic-core` (Rust). InjeXion resolves this:
1. **Prebuilt Community Wheel Installation** (Recommended, zero compile time):
   ```bash
   pkg update && pkg upgrade -y
   pkg install python clang git -y
   pip install --upgrade pip setuptools wheel
   pip install pydantic-core --extra-index-url https://eutalix.github.io/android-pydantic-core/
   pip install -e .
   injx --help
   ```
2. **Native Compilation Path** (Fallback if wheel index unreachable):
   ```bash
   pkg install python rust build-essential libffi openssl git -y
   pip install -e .
   ```
3. **Pure-Python Graceful Degradation**: In `injexion.core.models`, if `pydantic` cannot be loaded, core dataclasses fallback to standard library `dataclasses`, ensuring operational capability under all constraints.
4. **Environment Detection**: Automatically detects Termux (`PREFIX=/data/data/com.termux/files/usr`) and enforces the **Mobile Profile** (concurrency $\le 5$, reduced keep-alives, compact console layout).

### 8.2 Microsoft Windows (PowerShell / Windows Terminal / CMD)
- **Virtual Terminal Processing**: Activates VT100 mode via `ctypes.windll.kernel32.SetConsoleMode` guarded by `sys.stdout.isatty()` to ensure Rich colors and progress bars render properly without ANSI garbling.
- **Code Page**: Enforces UTF-8 (`chcp 65001` and `sys.stdout.reconfigure(encoding='utf-8')`).
- **Standard Installation**:
  ```powershell
  python -m venv .venv
  .venv\Scripts\Activate.ps1
  pip install -e .
  injx --help
  ```
- **Optional PyInstaller Standalone Binary**: Packaging configuration enables compiling a zero-dependency `injx.exe` for portable USB drive penetration testing.

### 8.3 Linux & macOS (Debian, Ubuntu, Arch, Fedora, Darwin)
- Full standard support under Python 3.10, 3.11, and 3.12:
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -e .
  injx --help
  ```

---

## 9. Migration Guide & Backward Compatibility

### 9.1 CLI Command & Flag Migration Table

| Legacy PenIn2 Workflow (`t6.py` / `tm.py`) | Modern InjeXion Command (`injx`) | Purpose / Improvement |
|---|---|---|
| `python t6.py` + interactive input | `injx scan https://target.com` | Automated, non-interactive execution |
| *Hardcoded 10 threads* | `injx scan https://target.com --concurrency 30` | Configurable throughput |
| *Hardcoded 5s timeout* | `injx scan https://target.com --timeout 10.0` | Flexible timeout control |
| *Always runs all tests* | `injx scan https://target.com --modules sqli,xss` | Selective vulnerability testing |
| *Always dumps text in root* | `injx scan https://target.com --output report.html --format html` | Standalone interactive HTML report |
| *No CI/CD format* | `injx scan https://target.com --format sarif -o results.sarif` | GitHub Code Scanning integration |
| *Interactive port check* | `injx probe https://target.com --ports` | Fast asynchronous port scan |
| *Interactive dir bruteforce* | `injx probe https://target.com --dirs -w wordlist.txt` | Soft-404 aware directory fuzzing |
| *No environment check* | `injx doctor` | Diagnostic test of terminal, Python & network |

### 9.2 Backward-Compatible Legacy Shim (`penin2`)
For users familiar with the legacy prompt-driven interface, InjeXion registers a `penin2` console entrypoint that runs an interactive wizard guiding users through target input, module selection, and concurrency profiles, delegating execution directly to the modern async engine.

---

## 10. Milestone Roadmap & Implementation Schedule

The implementation of InjeXion is partitioned into six structured milestones:

```
[ M1: Foundation & Models ]
       │
       ▼
[ M2: Async Engine & Parameter Parser ]
       │
       ├─────────────────────────────────────┐
       ▼                                     ▼
[ M3: Detection Suite ]             [ M4: Recon Modules & Payloads ]
(SQLi, XSS, LFI)                     (Headers, Dirs, Ports)
       │                                     │
       └──────────────────┬──────────────────┘
                          │
                          ▼
            [ M5: Multi-Format Reporting ]
            (HTML, JSON, SARIF v2.1.0)
                          │
                          ▼
            [ M6: CLI, Packaging & Migration ]
            (Typer/Rich CLI, Termux/Win Guides)
```

| Milestone | Deliverables | Verification Criteria |
|---|---|---|
| **M1: Foundation & Core Models** | Rebranded project layout (`src/injexion`), PEP 621 `pyproject.toml`, Pydantic models (`Finding`, `InjectionTarget`, `HttpEvidence`, `ScanConfig`, `ScanMetadata`), domain exceptions, terminal compatibility layer. | Clean package install (`pip install -e .`), zero import errors, Pydantic model serialization tests pass. |
| **M2: Async Engine & Parser** | `AsyncHTTPClient` with connection pooling, mobile/desktop profiles, token-bucket rate limiter, universal parameter mutator (query, headers, forms, JSON), dynamic probe timeouts. | Unit tests verify OVAT parameter mutation across query, JSON, and form bodies; mock HTTP server verifies rate limiting and retry backoff. |
| **M3: Core Detection Engines** | Multi-DBMS SQLi (regex, boolean blind with relative delta, time blind with calibrated timeouts), context-aware XSS with two-stage probing, systematic LFI with depth expansion and anchored regex. | High-fidelity test suite against mock HTTP endpoints verifying zero false positives on normal error text and SPA root tags. |
| **M4: Ancillary Modules & Payloads** | Security headers audit (HTTPS gated HSTS), soft-404 & redirect aware sensitive file discovery, async TCP port scanner, sanitized and curated payload assets. | Port scanner handles non-standard URLs without crashing; soft-404 preflight correctly filters catch-all server responses and redirects. |
| **M5: Multi-Format Reporting Engine** | Standalone zero-CDN interactive HTML report generator, JSON v2.0.0 exporter, OASIS SARIF v2.1.0 exporter with GitHub help markdown. | HTML opens standalone in browser with working filters; JSON conforms to v2.0.0 schema; SARIF validates against OASIS v2.1.0 schema validator. |
| **M6: CLI Commands & Packaging** | Unified Typer CLI (`scan`, `quick`, `probe`, `payloads`, `report`, `doctor`), Rich live progress displays, legacy `penin2` shim, resolved `README.md`, setup guides. | CLI commands execute seamlessly on Windows PowerShell, Linux, and Android Termux; `README.md` conflict markers resolved; legacy `penin2` launches wizard. |

---
*End of Technical Specification Artifact (Revision 2.0.1).*
