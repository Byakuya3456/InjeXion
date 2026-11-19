# Project: InjeXion (Modernization of PenIn2)

## Architecture

InjeXion refactors the legacy monolithic scripts (`t6.py` and `tm.py`) into a high-performance, asynchronous Python package structured around five decoupled subsystems:

```
[ CLI & UX Layer (Typer + Rich) ]
      │
      ├──> [ Configuration & Profile Manager (Pydantic v2) ]
      │         ├── Mobile Profile (Termux / Low-Memory / <=5 Concurrency)
      │         └── Desktop Profile (High-Throughput / HTTP/2 / 30 Concurrency)
      │
      ├──> [ Async Network Engine (httpx + asyncio) ]
      │         ├── Connection Pooling (httpx.Limits)
      │         ├── Token-Bucket Rate Limiter & Adaptive Backoff (429/503)
      │         └── Universal Parameter Injector (Query, Headers, Forms, JSON)
      │
      ├──> [ Vulnerability Detection Suite (BaseDetector Interface) ]
      │         ├── SQLi Detector (Multi-DBMS Error Regex, Boolean Blind, Time Blind)
      │         ├── XSS Detector (Safe Canary Probes, Context Analyzer, CSP Gate)
      │         ├── LFI Detector (Systematic Depth 1..8, Multi-Encoding, Anchored Regex)
      │         ├── Port Scanner (Native Non-blocking asyncio Sockets)
      │         ├── Sensitive File Discovery (Soft-404 Preflight & HEAD Probes)
      │         └── Security Headers Auditor (HSTS, CSP, X-Frame, X-Content-Type)
      │
      └──> [ Multi-Format Reporting Subsystem (BaseReporter Interface) ]
                ├── Interactive Standalone HTML Reporter (Zero-CDN, Dark Theme, KPI Cards)
                ├── Machine-Readable JSON Exporter (v2.0.0 Schema)
                └── Enterprise SARIF v2.1.0 Exporter (GitHub Code Scanning Compliant)
```

---

## Feature Inventory

Every feature identified during the Phase 0 Survey is cataloged below with its source and assigned milestone.

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Brand Overhaul & Identity | Formalize InjeXion identity, `injx` CLI command, ASCII banner, and positioning | M1 | Survey (Explorer 3) |
| 2 | Clean `src/` Packaging | PEP 621 `pyproject.toml` with `hatchling` backend, console scripts (`injx`, `injexion`, `penin2`) | M1 | Survey (Explorer 3) |
| 3 | Core Data Models & Exceptions | Pydantic v2 data models (`Finding`, `InjectionTarget`, `HttpEvidence`, `ScanConfig`, `ScanMetadata`) | M1 | Survey (Explorer 2 & 3) |
| 4 | Terminal Compatibility Layer | Windows VT100/CP65001 setup, Android Termux compact mode, `NO_COLOR` compliance | M1 | Survey (Explorer 3) |
| 5 | Async HTTP Client Engine | `httpx.AsyncClient` wrapper with connection pooling, timeouts, and proxy support | M2 | Survey (Explorer 2) |
| 6 | Mobile vs Desktop Profiles | Resource profiles adjusting concurrency, keepalives, and streaming buffers | M2 | Survey (Explorer 2) |
| 7 | Adaptive Rate Limiter | Token-bucket rate limiter with full-jitter exponential backoff on HTTP 429/503 | M2 | Survey (Explorer 2) |
| 8 | Universal Parameter Parser | Structured mutation of URL query params, HTTP headers, form data, and nested JSON keys | M2 | Survey (Explorer 2) |
| 9 | Multi-DBMS Error SQLi | Anchored regex detection for MySQL, PostgreSQL, MSSQL, Oracle, SQLite, and ODBC | M3 | Survey (Explorer 2) |
| 10 | Boolean-Blind SQLi | Differential analysis comparing True/False conditions with dynamic token stripping & relative delta | M3 | Survey (Explorer 2) |
| 11 | Time-Blind SQLi | Baseline latency calibration ($\mu, \sigma$) and dynamic timeout probe verification against jitter | M3 | Survey (Explorer 2) |
| 12 | Context-Aware XSS | Two-stage benign canary tokens, HTML lexical state machine, escaping verification, and CSP gating | M3 | Survey (Explorer 2) |
| 13 | Systematic LFI / Traversal | Depth expansion (1..8), multi-encoding matrix, and anchored regex validation for Linux/Win | M3 | Survey (Explorer 2) |
| 14 | Security Headers Auditor | Audit missing defensive headers (HSTS on HTTPS, CSP, X-Frame-Options) and information leakage | M4 | Survey (Explorer 2) |
| 15 | Soft-404 File Discovery | Pre-flight random canary path to fingerprint custom 404s & catch-all redirects; HEAD-based checking | M4 | Survey (Explorer 2) |
| 16 | Async TCP Port Scanner | Non-blocking `asyncio.open_connection()` port prober with banner grabbing | M4 | Survey (Explorer 2) |
| 17 | Payload Asset Sanitization | Purge markdown notes, local IPs (`192.168.1.6`), Android URIs; structure clean packs | M4 | Survey (Explorer 1) |
| 18 | Interactive HTML Reporter | Standalone single-file HTML report with KPI cards, severity badges, and remediation | M5 | Survey (Explorer 3) |
| 19 | JSON v2.0.0 Export | Standardized, structured JSON output with HTTP evidence and scan metadata | M5 | Survey (Explorer 3) |
| 20 | SARIF v2.1.0 Exporter | OASIS standard SARIF export with `rule.help.markdown` and `ruleIndex` for GitHub Code Scanning | M5 | Survey (Explorer 3) |
| 21 | Unified Typer/Rich CLI | `injx scan`, `quick`, `probe`, `payloads`, `report`, `doctor` commands and live displays | M6 | Survey (Explorer 3) |
| 22 | Legacy PenIn2 CLI Shim | Backward-compatible `penin2` interactive wizard forwarding to modern engine | M6 | Survey (Explorer 1 & 3) |
| 23 | Cross-Platform Installation | Setup guides for Android Termux, Windows, and Linux/macOS with dependency tiers | M6 | Survey (Explorer 3) |
| 24 | Documentation & Git Cleanup | Resolve merge conflicts in README.md, document migration, and remove orphan root files | M6 | Survey (Explorer 1 & 3) |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Package Foundation & Core Models | Rebranding, `src/` layout, `pyproject.toml`, Pydantic models, domain exceptions, and terminal abstraction | None | PLANNED |
| M2 | Async Engine & Parameter Parser | `httpx` async client, connection pool, mobile/desktop profiles, rate limiter, and universal parameter mutator | M1 | PLANNED |
| M3 | Core Vulnerability Detection Engines | Multi-DBMS SQLi (error, boolean, time), Context-aware XSS, and systematic LFI/traversal detectors | M2 | PLANNED |
| M4 | Ancillary Modules & Clean Payloads | Security headers audit, soft-404 file discovery, async port scanner, and cleaned payload repository | M2 | PLANNED |
| M5 | Multi-Format Reporting Engine | Standalone zero-CDN interactive HTML reporter, JSON v2.0.0 exporter, and SARIF v2.1.0 exporter | M1, M3, M4 | PLANNED |
| M6 | CLI Commands, UX & Cross-Platform Packaging | Typer/Rich CLI commands, live progress displays, legacy `penin2` shim, Termux/Win/Linux guides, and README | M5 | PLANNED |

---

## Interface Contracts

### 1. Core Data Models (`injexion.core.models`)
```python
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from pathlib import Path

class InjectionTarget(BaseModel):
    """Represents an isolated parameter target for injection testing."""
    url: str = Field(description="Base target URL")
    method: str = Field(default="GET", description="HTTP Method (GET, POST, PUT, etc.)")
    parameter_name: str = Field(description="Name of the targeted parameter or header key")
    parameter_type: str = Field(description="query, header, json, form, or path")
    original_value: Any = Field(description="Original un-injected value")
    json_path: Optional[str] = Field(default=None, description="JSONPath notation for nested JSON keys")
    headers: Dict[str, str] = Field(default_factory=dict)
    data: Optional[Dict[str, Any]] = Field(default=None, description="Form data dict")
    json_body: Optional[Dict[str, Any]] = Field(default=None, description="JSON body dict")

class ScanConfig(BaseModel):
    """Global configuration settings for scan execution."""
    profile: str = Field(default="desktop", description="mobile or desktop")
    concurrency_limit: int = Field(default=30, ge=1, le=100)
    rate_limit: Optional[int] = Field(default=None, description="Max requests per second")
    timeout_connect: float = Field(default=5.0)
    timeout_read: float = Field(default=8.0)
    proxy: Optional[str] = None
    verify_ssl: bool = False
    follow_redirects: bool = True
    user_agent: str = Field(default="InjeXion/2.0.0")
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    active_modules: List[str] = Field(default_factory=lambda: ["sqli", "xss", "lfi", "headers", "dirs", "ports"])

class HttpEvidence(BaseModel):
    request_url: str
    request_method: str
    request_headers: Dict[str, str]
    request_body: Optional[str] = None
    response_status: int
    response_headers: Dict[str, str]
    response_body_snippet: str
    matched_signature: Optional[str] = None

class Finding(BaseModel):
    id: str = Field(description="Unique deterministic finding hash (UUID/SHA256)")
    title: str
    category: str
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    target_url: str
    parameter: Optional[str] = None
    injection_type: Optional[str] = None  # query, header, json, form, path
    payload: Optional[str] = None
    description: str
    evidence: HttpEvidence
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: Optional[float] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ScanMetadata(BaseModel):
    scanner_name: str = "InjeXion"
    scanner_version: str = "2.0.0"
    scan_profile: str
    target_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    total_requests: int = 0
    concurrency_limit: int = 30
```

### 2. `Engine` ↔ `Detectors` (`BaseDetector`)
```python
from abc import ABC, abstractmethod
from typing import List
from injexion.core.models import Finding, InjectionTarget, ScanConfig
from injexion.engine.client import AsyncHTTPClient

class BaseDetector(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the vulnerability detector."""
        ...

    @property
    @abstractmethod
    def category(self) -> str:
        """Category identifier (sqli, xss, lfi, headers, dirs, ports)."""
        ...

    @abstractmethod
    async def run(
        self,
        target: InjectionTarget,
        client: AsyncHTTPClient,
        config: ScanConfig
    ) -> List[Finding]:
        """Execute detection routine against target injection point."""
        ...
```

### 3. `Core` ↔ `Reporters` (`BaseReporter`)
```python
from abc import ABC, abstractmethod
from typing import List
from pathlib import Path
from injexion.core.models import Finding, ScanMetadata

class BaseReporter(ABC):
    @abstractmethod
    def generate(
        self,
        findings: List[Finding],
        metadata: ScanMetadata,
        output_path: Path
    ) -> Path:
        """Write report to destination path and return resolved path."""
        ...
```

---

## Code Layout

```
web-application-payloads-injector-penln2/
├── pyproject.toml                     # PEP 621 package metadata & dependencies
├── README.md                          # Modernized documentation, badges & usage guide
├── LICENSE                            # MIT License with Attribution Retention
├── .gitignore                         # Python, OS, and build artifacts
├── src/
│   └── injexion/
│       ├── __init__.py                # Version declaration (__version__ = "2.0.0")
│       ├── __main__.py                # python -m injexion entrypoint
│       ├── py.typed                   # PEP 561 marker
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── app.py                 # Main Typer app initialization
│       │   ├── legacy.py              # Backward-compatible penin2 interactive shim
│       │   ├── commands/              # scan, quick, probe, payloads, report, doctor
│       │   └── display/               # Banner, live progress, tables, terminal compat
│       ├── core/
│       │   ├── config.py              # Pydantic ScanConfig (mobile/desktop profiles)
│       │   ├── constants.py           # Severities, ports, default headers
│       │   ├── exceptions.py          # Domain exceptions hierarchy
│       │   └── models.py              # Finding, HttpEvidence, InjectionTarget, ScanMetadata
│       ├── engine/
│       │   ├── client.py              # AsyncHTTPClient (httpx, pooling, retries)
│       │   ├── dispatcher.py          # Concurrency scheduler & semaphore manager
│       │   ├── parameter.py           # Universal request parser (query, headers, JSON, forms)
│       │   └── rate_limiter.py        # Token bucket with adaptive backoff
│       ├── detectors/
│       │   ├── base.py                # BaseDetector abstract contract
│       │   ├── sqli.py                # Error-based, Boolean-blind, Time-blind SQLi
│       │   ├── xss.py                 # Context-aware reflection XSS
│       │   ├── lfi.py                 # Systematic depth traversal & anchored regex
│       │   ├── headers.py             # Security headers audit
│       │   ├── dirs.py                # Soft-404 aware directory discovery
│       │   └── ports.py               # Async non-blocking TCP port prober
│       ├── payloads/
│       │   ├── manager.py             # Payload loader, deduplicator & cleaner
│       │   └── data/                  # Curated, cleaned payload datasets
│       └── reporters/
│           ├── base.py                # BaseReporter abstract contract
│           ├── console.py             # Rich console finding cards & summary tables
│           ├── json_rep.py            # Standard JSON v2.0.0 exporter
│           ├── sarif.py               # OASIS SARIF v2.1.0 exporter
│           └── html/                  # Standalone interactive HTML generator
└── tests/
    ├── conftest.py                    # Pytest fixtures and mock HTTP servers
    ├── unit/                          # Unit tests for CLI, models, parsers, reporters
    └── integration/                   # Integration tests for async detection modules
```
