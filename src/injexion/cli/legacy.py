"""
Interactive Backward-Compatibility Wizard for PenIn2 users.
Routes interactive prompts into the modern InjeXion async scanning engine.
"""

import os
import sys
import urllib.parse
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt
from injexion.cli.app import scan, sqli, xss, lfi, ports, doctor
from injexion.cli.display import init_terminal, print_banner

console = init_terminal()


def main(default_profile: Optional[str] = None):
    # Determine default profile: explicit argument > environment detection (Termux) > desktop
    is_termux = "TERMUX_VERSION" in os.environ or "PREFIX" in os.environ and "termux" in os.environ.get("PREFIX", "")
    active_profile = default_profile or ("mobile" if is_termux else "desktop")

    print_banner(console, compact=False)
    console.print(
        f"[bold yellow]Notice:[/bold yellow] You are using the interactive [bold]PenIn2 compatibility mode[/bold] "
        f"[dim](Active Profile: [bold cyan]{active_profile.upper()}[/bold cyan])[/dim].\n"
        "[dim]For automation and advanced flags, use the new CLI:[/dim] [bold cyan]injx scan --help[/bold cyan]\n"
    )

    while True:
        console.print("[bold cyan]Select an Operation:[/bold cyan]")
        console.print("  [1] Comprehensive Vulnerability Scan (SQLi, XSS, LFI, Headers, Dirs)")
        console.print("  [2] SQL Injection Only")
        console.print("  [3] Cross-Site Scripting (XSS) Only")
        console.print("  [4] Local File Inclusion (LFI) Only")
        console.print("  [5] Port Scanner")
        console.print("  [6] InjeXion Environment Doctor")
        console.print(f"  [7] Switch Profile (Current: [bold cyan]{active_profile}[/bold cyan])")
        console.print("  [0] Exit")

        choice = Prompt.ask("\nEnter choice", choices=["0", "1", "2", "3", "4", "5", "6", "7"], default="1")

        if choice == "0":
            console.print("[bold green]Exiting InjeXion. Goodbye![/bold green]")
            sys.exit(0)

        if choice == "6":
            doctor()
            console.print()
            continue

        if choice == "7":
            active_profile = "mobile" if active_profile == "desktop" else "desktop"
            console.print(f"\n[green]✔ Switched active profile to:[/green] [bold cyan]{active_profile.upper()}[/bold cyan]\n")
            continue

        if choice == "5":
            raw_host = Prompt.ask("Enter target hostname/IP (e.g. scanme.nmap.org)")
            clean_host = raw_host.strip()
            if "://" in clean_host:
                clean_host = urllib.parse.urlparse(clean_host).hostname or clean_host
            elif "/" in clean_host:
                clean_host = clean_host.split("/")[0]
            ports(host=clean_host)
            console.print()
            continue

        target_url = Prompt.ask("Enter target URL (e.g. http://testphp.vulnweb.com/listproducts.php?cat=1)")

        if choice == "1":
            scan(url=target_url, profile=active_profile, no_banner=True)
        elif choice == "2":
            sqli(url=target_url, profile=active_profile)
        elif choice == "3":
            xss(url=target_url, profile=active_profile)
        elif choice == "4":
            lfi(url=target_url, profile=active_profile)

        console.print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    main()
