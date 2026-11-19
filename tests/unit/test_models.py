"""Unit tests for InjeXion core models and configuration."""

from pathlib import Path
from injexion.core.config import ScanConfig
from injexion.core.models import Finding, HttpEvidence, InjectionTarget, ParameterType, ScanMetadata, Severity


def test_scan_config_profiles():
    # Test desktop profile defaults
    desktop_cfg = ScanConfig.create_for_profile("desktop")
    assert desktop_cfg.concurrency == 25
    assert desktop_cfg.timeout == 6.0
    assert desktop_cfg.profile == "desktop"

    # Test mobile profile defaults (Termux)
    mobile_cfg = ScanConfig.create_for_profile("mobile")
    assert mobile_cfg.concurrency <= 5
    assert mobile_cfg.timeout == 8.0
    assert mobile_cfg.profile == "mobile"


def test_finding_model_serialization():
    evidence = HttpEvidence(
        request_method="GET",
        request_url="http://testphp.vulnweb.com/artists.php?artist=1'",
        response_status=200,
        response_snippet="You have an error in your SQL syntax;",
        response_time_ms=120.5
    )
    finding = Finding(
        id="test-sqli-01",
        vuln_type="sqli_error",
        title="SQL Injection (Error-Based)",
        severity=Severity.CRITICAL,
        cwe_id="CWE-89",
        cvss_score=9.8,
        target_url="http://testphp.vulnweb.com/artists.php",
        parameter="artist",
        parameter_type=ParameterType.QUERY,
        payload="' OR 1=1--",
        evidence=evidence,
        description="SQL syntax error detected",
        remediation="Use prepared statements",
    )
    data = finding.model_dump()
    assert data["id"] == "test-sqli-01"
    assert data["severity"] == "CRITICAL"
    assert data["evidence"]["response_status"] == 200
    assert "You have an error" in data["evidence"]["response_snippet"]


def test_scan_metadata():
    meta = ScanMetadata(target="http://example.com", profile="mobile")
    assert meta.target == "http://example.com"
    assert meta.profile == "mobile"
    assert meta.tool_version == "2.0.0"

