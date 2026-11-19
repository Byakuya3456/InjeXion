"""
Interactive Backward-Compatibility Wizard for PenIn2 users.
Routes interactive prompts into the modern InjeXion async scanning engine.
"""

import sys
from rich.console import Console
from rich.prompt import Prompt
from injexion.cli.app import scan, sqli, xss, lfi, ports, doctor
from injexion.cli.display import init_terminal, print_banner

console = init_terminal()


def main():
    print_banner(console, compact=False)
    console.print(
        "[bold yellow]Notice:[/bold yellow] You are using the interactive [bold]PenIn2 compatibility mode[/bold].\n"
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
        console.print("  [0] Exit")

        choice = Prompt.ask("\nEnter choice", choices=["0", "1", "2", "3", "4", "5", "6"], default="1")

        if choice == "0":
            console.print("[bold green]Exiting InjeXion. Goodbye![/bold green]")
            sys.exit(0)

        if choice == "6":
            doctor()
            console.print()
            continue

        if choice == "5":
            host = Prompt.ask("Enter target hostname/IP (e.g. scanme.nmap.org)")
            ports(host=host)
            console.print()
            continue

        target_url = Prompt.ask("Enter target URL (e.g. http://testphp.vulnweb.com/listproducts.php?cat=1)")
        profile = Prompt.ask("Select profile", choices=["desktop", "mobile"], default="desktop")

        if choice == "1":
            scan(url=target_url, profile=profile, no_banner=True)
        elif choice == "2":
            sqli(url=target_url, profile=profile)
        elif choice == "3":
            xss(url=target_url, profile=profile)
        elif choice == "4":
            lfi(url=target_url, profile=profile)

        console.print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    main()

