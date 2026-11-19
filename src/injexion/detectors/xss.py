"""
Cross-Site Scripting (XSS) Detection Module.
Uses a two-phase verification approach:
1. Unique randomized canary reflection probe.
2. Context-aware breakout verification with CSP gating to eliminate false positives.
"""

import asyncio
import random
import string
import uuid
from typing import List, Optional
from injexion.core.config import ScanConfig
from injexion.core.constants import VULN_METADATA
from injexion.core.models import Finding, InjectionTarget, Severity
from injexion.detectors.base import BaseDetector
from injexion.engine.client import AsyncHTTPClient
from injexion.engine.parameter import ParameterParser


class XSSDetector(BaseDetector):
    def __init__(self):
        super().__init__("Cross-Site Scripting")

    @staticmethod
    def _generate_canary(length: int = 8) -> str:
        letters = string.ascii_lowercase + string.digits
        return "injx" + "".join(random.choice(letters) for _ in range(length))

    async def scan(
        self,
        target: InjectionTarget,
        client: AsyncHTTPClient,
        config: ScanConfig,
        payloads: List[str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        original_url = target.url

        # Phase 1: Canary probe to check reflection
        canary = self._generate_canary()
        canary_req = ParameterParser.build_mutated_request(
            target, canary, original_url, mode="replace"
        )
        canary_resp, _ = await client.send(**canary_req)

        if not canary_resp or canary not in canary_resp.text:
            # Input parameter is not reflected in response at all
            return findings

        # Check Content-Type - JSON or plain text APIs do not execute HTML/JS in browser
        content_type = canary_resp.headers.get("Content-Type", "").lower()
        if "application/json" in content_type or "text/plain" in content_type:
            return findings

        # Phase 2: Inject breakout payloads with canary markers
        breakout_templates = [
            f"<script>{canary}</script>",
            f"\"><script>{canary}</script>",
            f"'><script>{canary}</script>",
            f"<img src=x onerror={canary}>",
            f"\"><svg onload={canary}>",
            f"\" autofocus onfocus={canary} x=\"",
        ]

        sem = asyncio.Semaphore(config.concurrency)

        async def test_xss_payload(template: str) -> Optional[Finding]:
            async with sem:
                mutated = ParameterParser.build_mutated_request(
                    target, template, original_url, mode="replace"
                )
                resp, evidence = await client.send(**mutated)
                if not resp:
                    return None

                # Verify payload is reflected UNENCODED in the response body
                if template in resp.text:
                    # Check CSP for script blocking
                    csp = resp.headers.get("Content-Security-Policy", "")
                    csp_warning = ""
                    severity = Severity.HIGH
                    if "script-src" in csp and "'unsafe-inline'" not in csp:
                        csp_warning = " (Note: Content-Security-Policy is present and may mitigate execution in modern browsers)"
                        severity = Severity.MEDIUM

                    meta = VULN_METADATA["xss_reflected"]
                    return Finding(
                        id=f"xss-{uuid.uuid4().hex[:8]}",
                        vuln_type="xss_reflected",
                        title=f"{meta['title']}{csp_warning}",
                        severity=severity,
                        cwe_id=meta["cwe_id"],
                        cvss_score=meta["cvss_score"],
                        target_url=target.url,
                        parameter=target.parameter,
                        parameter_type=target.param_type,
                        payload=template,
                        evidence=evidence,
                        description=f"{meta['description']} The parameter unencoded reflection allowed payload insertion.{csp_warning}",
                        remediation=meta["remediation"],
                    )
            return None

        tasks = [test_xss_payload(tmpl) for tmpl in breakout_templates]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                findings.append(r)
                break  # Confirmed on this parameter

        return findings

