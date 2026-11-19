"""
Directory and sensitive file discovery module.
Equipped with soft-404 preflight baseline calibration to eliminate false positives.
"""

import asyncio
import uuid
from typing import List, Optional
import urllib.parse
from injexion.core.config import ScanConfig
from injexion.core.constants import VULN_METADATA
from injexion.core.models import DirResult, Finding, Severity
from injexion.engine.client import AsyncHTTPClient

DEFAULT_PROBE_PATHS = [
    ".git/HEAD",
    ".env",
    "robots.txt",
    "sitemap.xml",
    ".DS_Store",
    "backup.zip",
    "database.sql",
    "phpinfo.php",
    "config.json",
    "wp-config.php.bak",
    "server-status",
    "admin/",
    "login/",
    "api/",
    ".well-known/security.txt",
]


class DirectoryBruteForcer:
    """Discovers hidden or sensitive paths with soft-404 calibration."""

    @staticmethod
    async def discover(
        base_url: str,
        client: AsyncHTTPClient,
        config: ScanConfig,
        wordlist: Optional[List[str]] = None
    ) -> List[Finding]:
        findings: List[Finding] = []
        paths = wordlist if wordlist else DEFAULT_PROBE_PATHS

        parsed = urllib.parse.urlparse(base_url)
        root_url = f"{parsed.scheme}://{parsed.netloc}"

        # Soft-404 Calibration Preflight:
        # Request a non-existent random URL to see how server behaves on missing paths
        random_slug = f"/soft404_canary_{uuid.uuid4().hex[:12]}"
        canary_url = f"{root_url}{random_slug}"
        canary_resp, _ = await client.get(canary_url)

        canary_status = canary_resp.status_code if canary_resp else 404
        canary_len = len(canary_resp.text) if canary_resp else 0

        sem = asyncio.Semaphore(config.concurrency)

        async def probe_path(path: str) -> Optional[Finding]:
            async with sem:
                normalized = "/" + path.lstrip("/")
                target_url = f"{root_url}{normalized}"
                resp, evidence = await client.get(target_url)

                if not resp:
                    return None

                # Must not be a 404 or 400
                if resp.status_code in (404, 400, 502, 503):
                    return None

                # Check if server returns soft-404 (status 200 but matches canary status and size)
                if resp.status_code == canary_status and abs(len(resp.text) - canary_len) < 50:
                    return None

                # Specific signature checks for critical files
                matched = False
                title_suffix = ""
                sev = Severity.MEDIUM

                if ".git/HEAD" in normalized and "ref: refs/" in resp.text:
                    matched = True
                    title_suffix = " (.git repository exposure)"
                    sev = Severity.HIGH
                elif ".env" in normalized and ("APP_KEY=" in resp.text or "DB_PASSWORD=" in resp.text or "SECRET=" in resp.text):
                    matched = True
                    title_suffix = " (Environment secrets disclosure)"
                    sev = Severity.CRITICAL
                elif resp.status_code in (200, 301, 302, 403):
                    # Flag open / interesting directories
                    matched = True

                if matched:
                    meta = VULN_METADATA["sensitive_directory"]
                    return Finding(
                        id=f"dir-{uuid.uuid4().hex[:8]}",
                        vuln_type="sensitive_directory",
                        title=f"{meta['title']}: {normalized}{title_suffix}",
                        severity=sev,
                        cwe_id=meta["cwe_id"],
                        cvss_score=meta["cvss_score"],
                        target_url=target_url,
                        payload=normalized,
                        evidence=evidence,
                        description=f"{meta['description']} Endpoint {normalized} responded with HTTP {resp.status_code}.",
                        remediation=meta["remediation"],
                    )
            return None

        tasks = [probe_path(p) for p in paths]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                findings.append(r)

        return findings

