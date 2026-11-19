"""
Terminal initialization and display helpers for InjeXion.
Configures Windows VT100 / UTF-8 and Android Termux compact mode.
"""

import os
import sys
from rich.console import Console

BANNER = r"""
  ___         _     __  __ _            
 |_ _|_ _  (_) ___ \ \/ /(_)___  _ _   
  | || ' \ | |/ -_) >  < | / _ \| ' \  
 |___|_||_|/ |\___|/_/\_\|_\___/|_||_| 
         |__/   [ Next-Gen Async Scanner v2.0.0 ]
"""


def init_terminal() -> Console:
    """Initialize terminal with cross-platform Unicode and color support."""
    # Ensure UTF-8 output on Windows
    if sys.platform.startswith("win"):
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
        # Enable ANSI virtual terminal processing on Windows if possible
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass

    # Check for NO_COLOR or Termux environment
    is_termux = "TERMUX_VERSION" in os.environ or "PREFIX" in os.environ and "termux" in os.environ["PREFIX"]
    no_color = "NO_COLOR" in os.environ

    console = Console(
        no_color=no_color,
        highlight=True,
        force_terminal=True if not no_color else None
    )
    return console


def print_banner(console: Console, compact: bool = False) -> None:
    if compact:
        console.print("[bold cyan]InjeXion[/bold cyan] [dim]v2.0.0 — Next-Gen Web Scanner[/dim]")
    else:
        console.print(f"[bold cyan]{BANNER}[/bold cyan]")

