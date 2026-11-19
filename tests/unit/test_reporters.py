"""Unit tests for multi-format reporters (JSON, SARIF, HTML)."""

import json
from pathlib import Path
from injexion.core.models import Finding, HttpEvidence, ParameterType, ScanMetadata, Severity
from injexion.reporters.html.generator import HTMLReporter
from injexion.reporters.json_rep import JSONReporter
from injexion.reporters.sarif import SARIFReporter


def _sample_findings():
    evidence = HttpEvidence(
        request_method="GET",
        request_url="http://example.com/test?id=1'",
        response_status=500,
        response_snippet="You have an error in your SQL syntax near ''' at line 1",
        response_time_ms=45.2
    )
    return [
        Finding(
            id="f-sqli-01",
            vuln_type="sqli_error",
            title="SQL Injection (Error-Based)",
            severity=Severity.CRITICAL,
            cwe_id="CWE-89",
            cvss_score=9.8,
            target_url="http://example.com/test",
            parameter="id",
            parameter_type=ParameterType.QUERY,
            payload="'",
            evidence=evidence,
            description="DBMS error syntax disclosure",
            remediation="Use parameterized queries",
        ),
        Finding(
            id="f-hdr-01",
            vuln_type="missing_csp",
            title="Missing Content-Security-Policy (CSP)",
            severity=Severity.MEDIUM,
            cwe_id="CWE-1021",
            cvss_score=5.4,
            target_url="http://example.com/test",
            payload="N/A",
            description="CSP header not present",
            remediation="Configure Content-Security-Policy",
        )
    ]


def test_json_reporter(tmp_path: Path):
    findings = _sample_findings()
    metadata = ScanMetadata(target="http://example.com", total_requests=10, duration_seconds=1.2)
    out_file = tmp_path / "report.json"

    reporter = JSONReporter()
    generated = reporter.generate(findings, metadata, out_file)
    assert generated.is_file()

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["schema_version"] == "2.0.0"
    assert data["summary"]["critical"] == 1
    assert data["summary"]["medium"] == 1
    assert len(data["findings"]) == 2


def test_sarif_reporter(tmp_path: Path):
    findings = _sample_findings()
    metadata = ScanMetadata(target="http://example.com", total_requests=10, duration_seconds=1.2)
    out_file = tmp_path / "report.sarif"

    reporter = SARIFReporter()
    generated = reporter.generate(findings, metadata, out_file)
    assert generated.is_file()

    with open(out_file, "r", encoding="utf-8") as f:
        sarif = json.load(f)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "InjeXion"
    assert len(run["results"]) == 2
    rule_ids = {r["ruleId"] for r in run["results"]}
    assert "CWE-89" in rule_ids
    assert "CWE-1021" in rule_ids


def test_html_reporter(tmp_path: Path):
    findings = _sample_findings()
    metadata = ScanMetadata(target="http://example.com", total_requests=10, duration_seconds=1.2)
    out_file = tmp_path / "report.html"

    reporter = HTMLReporter()
    generated = reporter.generate(findings, metadata, out_file)
    assert generated.is_file()

    content = out_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "InjeXion Security Audit Report" in content
    assert "SQL Injection (Error-Based)" in content
    assert "CWE-89" in content
    assert "HTTP Request Evidence" in content
    assert "Content-Security-Policy" in content

