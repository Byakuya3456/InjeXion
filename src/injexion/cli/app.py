"""
Main Typer CLI application for InjeXion.
Exposes modular commands for full audits and targeted module scans.
"""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import time
from typing import List, Optional
try:
    from typing import Annotated
except ImportError:
    from typing_extensions import Annotated
import urllib.parse
import typer

from injexion.cli.display import init_terminal, print_banner
from injexion.core.config import ScanConfig
from injexion.core.constants import VERSION
from injexion.core.models import Finding, ScanMetadata
from injexion.detectors.dirs import DirectoryBruteForcer
from injexion.detectors.headers import SecurityHeadersAuditor
from injexion.detectors.lfi import LFIDetector
from injexion.detectors.ports import AsyncPortScanner
from injexion.detectors.sqli import SQLiDetector
from injexion.detectors.xss import XSSDetector
from injexion.engine.client import AsyncHTTPClient
from injexion.engine.parameter import ParameterParser
from injexion.payloads.manager import PayloadManager
from injexion.reporters.console import ConsoleReporter
from injexion.reporters.html.generator import HTMLReporter
from injexion.reporters.json_rep import JSONReporter
from injexion.reporters.sarif import SARIFReporter

app = typer.Typer(
    name="injx",
    help="InjeXion - High-Performance Asynchronous Web Vulnerability Scanner & Injector",
    add_completion=False,
)
console = init_terminal()


def _save_reports(
    findings: List[Finding],
    metadata: ScanMetadata,
    formats_str: str,
    output_dir: Path
) -> None:
    formats = [f.strip().lower() for f in formats_str.split(",") if f.strip()]
    output_dir.mkdir(parents=True, exist_ok=True)
    slug = urllib.parse.quote(metadata.target, safe="").replace(":", "_").replace("/", "_")[:30]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if "json" in formats:
        json_path = output_dir / f"injexion_{slug}_{timestamp}.json"
        JSONReporter().generate(findings, metadata, json_path)
        console.print(f"[green]✔[/green] JSON report written: [bold]{json_path}[/bold]")

    if "sarif" in formats:
        sarif_path = output_dir / f"injexion_{slug}_{timestamp}.sarif"
        SARIFReporter().generate(findings, metadata, sarif_path)
        console.print(f"[green]✔[/green] SARIF report written: [bold]{sarif_path}[/bold]")

    if "html" in formats:
        html_path = output_dir / f"injexion_{slug}_{timestamp}.html"
        HTMLReporter().generate(findings, metadata, html_path)
        console.print(f"[green]✔[/green] HTML dashboard written: [bold]{html_path}[/bold]")


@app.command()
def scan(
    url: Annotated[str, typer.Argument(help="Target URL (e.g. http://example.com/item.php?id=1)")],
    profile: Annotated[str, typer.Option("--profile", "-p", help="Performance profile: 'desktop' or 'mobile' (Termux)")] = "desktop",
    concurrency: Annotated[Optional[int], typer.Option("--concurrency", "-c", help="Max concurrent connections")] = None,
    rate_limit: Annotated[Optional[float], typer.Option("--rate-limit", "-r", help="Max requests per second")] = None,
    timeout: Annotated[Optional[float], typer.Option("--timeout", "-t", help="HTTP timeout in seconds")] = None,
    proxy: Annotated[Optional[str], typer.Option("--proxy", help="Upstream HTTP/SOCKS proxy")] = None,
    formats: Annotated[str, typer.Option("--format", "-f", help="Output formats: console,html,json,sarif")] = "console,html,json",
    output_dir: Annotated[Path, typer.Option("--output-dir", "-o", help="Report output directory")] = Path("reports"),
    scan_ports: Annotated[bool, typer.Option("--ports", help="Also scan common open ports")] = False,
    scan_dirs: Annotated[bool, typer.Option("--dirs", help="Scan for sensitive directories/files")] = True,
    no_banner: Annotated[bool, typer.Option("--no-banner", help="Suppress ASCII banner")] = False,
):
    """Run a full, comprehensive vulnerability audit on target."""
    if not no_banner:
        print_banner(console, compact=(profile.lower() in ("mobile", "termux")))

    overrides = {}
    if concurrency:
        overrides["concurrency"] = concurrency
    if rate_limit:
        overrides["rate_limit"] = rate_limit
    if timeout:
        overrides["timeout"] = timeout
    if proxy:
        overrides["proxy"] = proxy

    config = ScanConfig.create_for_profile(profile, **overrides)

    async def _runner():
        start_time = time.monotonic()
        metadata = ScanMetadata(target=url, profile=profile)
        findings: List[Finding] = []
        payload_mgr = PayloadManager()
        console_rep = ConsoleReporter(console)

        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            console.print("[bold red]Error: Target URL must specify scheme (e.g. http:// or https://)[/bold red]")
            raise typer.Exit(1)

        targets = ParameterParser.extract_targets_from_url(url)
        console.print(f"[bold cyan]🎯 Target:[/bold cyan] {url} [dim]({len(targets)} injectable points discovered)[/dim]")
        console.print(f"[dim]Profile: {config.profile.upper()} | Concurrency: {config.concurrency} | Rate Limit: {config.rate_limit} rps[/dim]\n")

        async with AsyncHTTPClient(config) as client:
            # 1. Security Headers Audit
            console.print("[dim]→ Auditing defensive security headers...[/dim]")
            hdr_findings = await SecurityHeadersAuditor.audit(url, client, config)
            for f in hdr_findings:
                findings.append(f)
                console_rep.display_finding(f)

            # 2. Port Scanning (optional)
            if scan_ports:
                console.print(f"[dim]→ Scanning common TCP ports on {parsed.hostname}...[/dim]")
                port_scanner = AsyncPortScanner(concurrency=config.concurrency)
                open_ports = await port_scanner.scan(parsed.hostname or "localhost")
                for p in open_ports:
                    console.print(f"  [bold green]PORT OPEN:[/bold green] {p.port}/{p.service} {f'({p.banner})' if p.banner else ''}")

            # 3. Directory & File Discovery
            if scan_dirs:
                console.print("[dim]→ Checking for exposed sensitive files and directories...[/dim]")
                dir_findings = await DirectoryBruteForcer.discover(
                    url, client, config, wordlist=payload_mgr.load_wordlist()[:25]
                )
                for f in dir_findings:
                    findings.append(f)
                    console_rep.display_finding(f)

            # 4. Parameter Injection Testing (SQLi, XSS, LFI)
            sqli_detector = SQLiDetector()
            xss_detector = XSSDetector()
            lfi_detector = LFIDetector()

            sqli_payloads = payload_mgr.load_sqli_payloads()
            xss_payloads = payload_mgr.load_xss_payloads()
            lfi_payloads = payload_mgr.load_lfi_payloads()

            for target in targets:
                console.print(f"[dim]→ Testing parameter '{target.parameter}' for injections...[/dim]")

                # SQLi
                sqli_hits = await sqli_detector.scan(target, client, config, sqli_payloads)
                for f in sqli_hits:
                    findings.append(f)
                    console_rep.display_finding(f)

                # XSS
                xss_hits = await xss_detector.scan(target, client, config, xss_payloads)
                for f in xss_hits:
                    findings.append(f)
                    console_rep.display_finding(f)

                # LFI
                lfi_hits = await lfi_detector.scan(target, client, config, lfi_payloads)
                for f in lfi_hits:
                    findings.append(f)
                    console_rep.display_finding(f)

            # Finalize metadata
            metadata.duration_seconds = time.monotonic() - start_time
            metadata.total_requests = client.request_count
            metadata.total_findings = len(findings)

            console_rep.display_summary(findings, metadata)
            _save_reports(findings, metadata, formats, output_dir)

    asyncio.run(_runner())


@app.command()
def sqli(
    url: Annotated[str, typer.Argument(help="Target URL with query parameters")],
    profile: Annotated[str, typer.Option("--profile", "-p")] = "desktop",
):
    """Run dedicated SQL injection scanner."""
    config = ScanConfig.create_for_profile(profile)
    targets = ParameterParser.extract_targets_from_url(url)
    payload_mgr = PayloadManager()
    console_rep = ConsoleReporter(console)
    detector = SQLiDetector()

    async def _runner():
        async with AsyncHTTPClient(config) as client:
            console.print(f"[bold cyan]🔍 SQLi Scan:[/bold cyan] {url}")
            for t in targets:
                hits = await detector.scan(t, client, config, payload_mgr.load_sqli_payloads())
                for h in hits:
                    console_rep.display_finding(h)
    asyncio.run(_runner())


@app.command()
def xss(
    url: Annotated[str, typer.Argument(help="Target URL with query parameters")],
    profile: Annotated[str, typer.Option("--profile", "-p")] = "desktop",
):
    """Run dedicated XSS reflection & breakout scanner."""
    config = ScanConfig.create_for_profile(profile)
    targets = ParameterParser.extract_targets_from_url(url)
    payload_mgr = PayloadManager()
    console_rep = ConsoleReporter(console)
    detector = XSSDetector()

    async def _runner():
        async with AsyncHTTPClient(config) as client:
            console.print(f"[bold cyan]🔍 XSS Scan:[/bold cyan] {url}")
            for t in targets:
                hits = await detector.scan(t, client, config, payload_mgr.load_xss_payloads())
                for h in hits:
                    console_rep.display_finding(h)
    asyncio.run(_runner())


@app.command()
def lfi(
    url: Annotated[str, typer.Argument(help="Target URL with file parameter")],
    profile: Annotated[str, typer.Option("--profile", "-p")] = "desktop",
):
    """Run dedicated Local File Inclusion scanner."""
    config = ScanConfig.create_for_profile(profile)
    targets = ParameterParser.extract_targets_from_url(url)
    payload_mgr = PayloadManager()
    console_rep = ConsoleReporter(console)
    detector = LFIDetector()

    async def _runner():
        async with AsyncHTTPClient(config) as client:
            console.print(f"[bold cyan]🔍 LFI Scan:[/bold cyan] {url}")
            for t in targets:
                hits = await detector.scan(t, client, config, payload_mgr.load_lfi_payloads())
                for h in hits:
                    console_rep.display_finding(h)
    asyncio.run(_runner())


@app.command()
def ports(
    host: Annotated[str, typer.Argument(help="Target hostname or IP address")],
    timeout: Annotated[float, typer.Option("--timeout", "-t")] = 2.0,
    concurrency: Annotated[int, typer.Option("--concurrency", "-c")] = 30,
):
    """Run fast asynchronous TCP port prober."""
    # Sanitize host if user provided a URL scheme or path
    target_host = host
    if "://" in host:
        target_host = urllib.parse.urlparse(host).hostname or host
    elif "/" in host:
        target_host = host.split("/")[0]

    scanner = AsyncPortScanner(timeout=timeout, concurrency=concurrency)
    async def _runner():
        console.print(f"[bold cyan]🔍 Scanning ports on:[/bold cyan] {target_host}")
        results = await scanner.scan(target_host)
        if not results:
            console.print("[yellow]No open common ports detected.[/yellow]")
        for r in results:
            console.print(f"  [bold green]OPEN:[/bold green] Port {r.port} ({r.service})")
    asyncio.run(_runner())


@app.command()
def doctor():
    """Diagnose environment, terminal support, and network connectivity."""
    print_banner(console, compact=True)
    console.print("[bold]Diagnostic System Check:[/bold]")
    import sys
    console.print(f"  [cyan]Python Version:[/cyan] {sys.version.split()[0]}")
    console.print(f"  [cyan]Platform:[/cyan] {sys.platform}")
    console.print(f"  [cyan]Unicode Console:[/cyan] {'Supported' if console.is_terminal else 'Non-interactive'}")
    
    # Check payload folders
    pm = PayloadManager()
    console.print(f"  [cyan]SQLi Payloads Available:[/cyan] {len(pm.load_sqli_payloads())}")
    console.print(f"  [cyan]XSS Payloads Available:[/cyan] {len(pm.load_xss_payloads())}")
    console.print(f"  [cyan]LFI Payloads Available:[/cyan] {len(pm.load_lfi_payloads())}")
    console.print(f"  [cyan]Wordlist Entries Available:[/cyan] {len(pm.load_wordlist())}")
    console.print("\n[bold green]✔ InjeXion environment is healthy and operational.[/bold green]")


def main():
    app()


if __name__ == "__main__":
    main()

