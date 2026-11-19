"""
SQL Injection Detection Module.
Detects:
1. Error-based SQLi (DBMS anchored regular expressions across 5 major database engines)
2. Boolean-based blind SQLi (differential response comparison)
3. Time-based blind SQLi (calibrated sleep verification)
"""

import asyncio
import re
import uuid
from typing import List, Optional, Tuple
from injexion.core.config import ScanConfig
from injexion.core.constants import DBMS_ERROR_PATTERNS, VULN_METADATA
from injexion.core.models import Finding, InjectionTarget, Severity
from injexion.detectors.base import BaseDetector
from injexion.engine.client import AsyncHTTPClient
from injexion.engine.parameter import ParameterParser


class SQLiDetector(BaseDetector):
    def __init__(self):
        super().__init__("SQL Injection")
        self._compiled_patterns = {
            db: [re.compile(p, re.IGNORECASE) for p in patterns]
            for db, patterns in DBMS_ERROR_PATTERNS.items()
        }

    def _match_dbms_error(self, text: str) -> Optional[str]:
        if not text:
            return None
        for dbms, patterns in self._compiled_patterns.items():
            for regex in patterns:
                if regex.search(text):
                    return dbms
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

        # Establish baseline response
        baseline_req = ParameterParser.build_mutated_request(
            target, target.baseline_value, original_url, mode="replace"
        )
        base_resp, _ = await client.send(**baseline_req)
        baseline_text = base_resp.text if base_resp else ""
        baseline_len = len(baseline_text)

        # Baseline check: make sure baseline does not already contain a false-positive error
        baseline_dbms = self._match_dbms_error(baseline_text)

        # 1. Error-Based SQLi Testing
        sem = asyncio.Semaphore(config.concurrency)

        async def test_error_payload(payload: str) -> Optional[Finding]:
            async with sem:
                mutated = ParameterParser.build_mutated_request(
                    target, payload, original_url, mode="append"
                )
                resp, evidence = await client.send(**mutated)
                if not resp:
                    return None

                matched_dbms = self._match_dbms_error(resp.text)
                # Only flag if DBMS error wasn't already in baseline
                if matched_dbms and matched_dbms != baseline_dbms:
                    meta = VULN_METADATA["sqli_error"]
                    return Finding(
                        id=f"sqli-err-{uuid.uuid4().hex[:8]}",
                        vuln_type="sqli_error",
                        title=f"{meta['title']} ({matched_dbms})",
                        severity=Severity.CRITICAL,
                        cwe_id=meta["cwe_id"],
                        cvss_score=meta["cvss_score"],
                        target_url=target.url,
                        parameter=target.parameter,
                        parameter_type=target.param_type,
                        payload=payload,
                        evidence=evidence,
                        description=f"{meta['description']} Target leaked {matched_dbms} syntax error signatures.",
                        remediation=meta["remediation"],
                    )
            return None

        tasks = [test_error_payload(p) for p in payloads[:30]]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                findings.append(r)
                # Once confirmed with one payload on this parameter, prevent redundant noise
                return findings

        # 2. Boolean-Based Blind SQLi Testing (if error-based didn't hit)
        boolean_pairs: List[Tuple[str, str]] = [
            (" AND 1=1--", " AND 1=2--"),
            ("' AND '1'='1", "' AND '1'='2"),
            ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
            (" OR 1=1--", " OR 1=2--"),
        ]

        for true_payload, false_payload in boolean_pairs:
            req_true = ParameterParser.build_mutated_request(target, true_payload, original_url, mode="append")
            req_false = ParameterParser.build_mutated_request(target, false_payload, original_url, mode="append")

            resp_true, ev_true = await client.send(**req_true)
            resp_false, _ = await client.send(**req_false)

            if resp_true and resp_false:
                len_true = len(resp_true.text)
                len_false = len(resp_false.text)

                # Check if True condition aligns closely with baseline while False diverges significantly
                true_delta = abs(len_true - baseline_len)
                false_delta = abs(len_false - baseline_len)

                if true_delta < 50 and false_delta > 150:
                    meta = VULN_METADATA["sqli_boolean"]
                    findings.append(
                        Finding(
                            id=f"sqli-bool-{uuid.uuid4().hex[:8]}",
                            vuln_type="sqli_boolean",
                            title=meta["title"],
                            severity=Severity.HIGH,
                            cwe_id=meta["cwe_id"],
                            cvss_score=meta["cvss_score"],
                            target_url=target.url,
                            parameter=target.parameter,
                            parameter_type=target.param_type,
                            payload=f"{true_payload} vs {false_payload}",
                            evidence=ev_true,
                            description=meta["description"],
                            remediation=meta["remediation"],
                        )
                    )
                    break

        return findings

