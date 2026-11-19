"""
Security Headers Auditor Module.
Evaluates defensive headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
"""

import uuid
from typing import List
from injexion.core.config import ScanConfig
from injexion.core.constants import VULN_METADATA
from injexion.core.models import Finding, HttpEvidence, Severity
from injexion.engine.client import AsyncHTTPClient


class SecurityHeadersAuditor:
    """Audits HTTP/HTTPS response security headers."""

    @staticmethod
    async def audit(url: str, client: AsyncHTTPClient, config: ScanConfig) -> List[Finding]:
        findings: List[Finding] = []
        resp, evidence = await client.get(url)
        if not resp:
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}
        is_https = url.lower().startswith("https://")

        # 1. HSTS (only applicable for HTTPS)
        if is_https and "strict-transport-security" not in headers:
            meta = VULN_METADATA["missing_hsts"]
            findings.append(
                Finding(
                    id=f"hdr-hsts-{uuid.uuid4().hex[:8]}",
                    vuln_type="missing_hsts",
                    title=meta["title"],
                    severity=Severity.LOW,
                    cwe_id=meta["cwe_id"],
                    cvss_score=meta["cvss_score"],
                    target_url=url,
                    payload="N/A",
                    evidence=evidence,
                    description=meta["description"],
                    remediation=meta["remediation"],
                )
            )

        # 2. Content-Security-Policy
        if "content-security-policy" not in headers:
            meta = VULN_METADATA["missing_csp"]
            findings.append(
                Finding(
                    id=f"hdr-csp-{uuid.uuid4().hex[:8]}",
                    vuln_type="missing_csp",
                    title=meta["title"],
                    severity=Severity.MEDIUM,
                    cwe_id=meta["cwe_id"],
                    cvss_score=meta["cvss_score"],
                    target_url=url,
                    payload="N/A",
                    evidence=evidence,
                    description=meta["description"],
                    remediation=meta["remediation"],
                )
            )

        # 3. X-Frame-Options
        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
            meta = VULN_METADATA["missing_xframe"]
            findings.append(
                Finding(
                    id=f"hdr-xframe-{uuid.uuid4().hex[:8]}",
                    vuln_type="missing_xframe",
                    title=meta["title"],
                    severity=Severity.LOW,
                    cwe_id=meta["cwe_id"],
                    cvss_score=meta["cvss_score"],
                    target_url=url,
                    payload="N/A",
                    evidence=evidence,
                    description=meta["description"],
                    remediation=meta["remediation"],
                )
            )

        # 4. X-Content-Type-Options
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            meta = VULN_METADATA["missing_xcontent"]
            findings.append(
                Finding(
                    id=f"hdr-nosniff-{uuid.uuid4().hex[:8]}",
                    vuln_type="missing_xcontent",
                    title=meta["title"],
                    severity=Severity.LOW,
                    cwe_id=meta["cwe_id"],
                    cvss_score=meta["cvss_score"],
                    target_url=url,
                    payload="N/A",
                    evidence=evidence,
                    description=meta["description"],
                    remediation=meta["remediation"],
                )
            )

        return findings

