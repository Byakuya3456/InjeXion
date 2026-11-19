"""
Rich console reporter and terminal formatting for InjeXion.
Supports full VT100 colors on Windows Terminal, compact mode on Termux, and NO_COLOR.
"""

from typing import List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from injexion.core.models import Finding, ScanMetadata, Severity

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold orange3",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "bold green",
}


class ConsoleReporter:
    def __init__(self, console: Console):
        self.console = console

    def display_finding(self, finding: Finding) -> None:
        style = SEVERITY_STYLES.get(finding.severity, "white")
        badge = f"[{style}][{finding.severity.value}][/{style}]"
        
        info = (
            f"{badge} [bold]{finding.title}[/bold] ({finding.cwe_id} | CVSS: {finding.cvss_score})\n"
            f"[dim]Target:[/dim] [cyan]{finding.target_url}[/cyan]\n"
            f"[dim]Param:[/dim]  [yellow]{finding.parameter or 'N/A'}[/yellow]\n"
            f"[dim]Vector:[/dim] [red]{finding.payload}[/red]"
        )
        self.console.print(Panel(info, border_style=style, expand=False))

    def display_summary(self, findings: List[Finding], metadata: ScanMetadata) -> None:
        table = Table(title="InjeXion Audit Summary", border_style="dim", header_style="bold magenta")
        table.add_column("Severity", justify="center")
        table.add_column("Count", justify="center")
        table.add_column("CVSS Range", justify="center")

        counts = {
            Severity.CRITICAL: sum(1 for f in findings if f.severity == Severity.CRITICAL),
            Severity.HIGH: sum(1 for f in findings if f.severity == Severity.HIGH),
            Severity.MEDIUM: sum(1 for f in findings if f.severity == Severity.MEDIUM),
            Severity.LOW: sum(1 for f in findings if f.severity == Severity.LOW),
            Severity.INFO: sum(1 for f in findings if f.severity == Severity.INFO),
        }

        ranges = {
            Severity.CRITICAL: "9.0 - 10.0",
            Severity.HIGH: "7.0 - 8.9",
            Severity.MEDIUM: "4.0 - 6.9",
            Severity.LOW: "0.1 - 3.9",
            Severity.INFO: "0.0",
        }

        for sev, count in counts.items():
            if count > 0:
                style = SEVERITY_STYLES[sev]
                table.add_row(f"[{style}]{sev.value}[/{style}]", str(count), ranges[sev])

        if len(findings) == 0:
            table.add_row("[green]CLEAN[/green]", "0", "N/A")

        self.console.print()
        self.console.print(table)
        self.console.print(
            f"[dim]Scan finished in {metadata.duration_seconds:.2f}s | "
            f"Requests: {metadata.total_requests} | "
            f"Total Findings: {len(findings)}[/dim]"
        )

