"""
Core data models for InjeXion scanner.
Type-safe Pydantic v2 models representing targets, findings, evidence, and configs.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ParameterType(str, Enum):
    QUERY = "query"
    HEADER = "header"
    FORM = "form"
    JSON = "json"
    PATH = "path"


class HttpEvidence(BaseModel):
    request_method: str = "GET"
    request_url: str
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: int = 0
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_snippet: str = ""
    response_time_ms: float = 0.0


class Finding(BaseModel):
    id: str
    vuln_type: str
    title: str
    severity: Severity
    cwe_id: str
    cvss_score: float = 0.0
    target_url: str
    parameter: Optional[str] = None
    parameter_type: Optional[ParameterType] = None
    payload: str
    evidence: Optional[HttpEvidence] = None
    description: str
    remediation: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class InjectionTarget(BaseModel):
    url: str
    method: str = "GET"
    parameter: str
    param_type: ParameterType = ParameterType.QUERY
    baseline_value: str = ""
    baseline_status: int = 200
    baseline_length: int = 0
    baseline_time_ms: float = 0.0
    headers: Dict[str, str] = Field(default_factory=dict)
    json_data: Optional[Dict[str, Any]] = None
    form_data: Optional[Dict[str, str]] = None


class ScanMetadata(BaseModel):
    target: str
    profile: str = "desktop"
    start_time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    total_requests: int = 0
    total_findings: int = 0
    tool_version: str = "2.0.0"


class PortResult(BaseModel):
    port: int
    service: str
    state: str = "open"
    banner: Optional[str] = None


class DirResult(BaseModel):
    path: str
    status_code: int
    content_length: int
    redirect_url: Optional[str] = None

