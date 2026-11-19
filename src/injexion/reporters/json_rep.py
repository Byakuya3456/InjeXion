"""
JSON v2.0.0 machine-readable reporter for InjeXion.
"""

import json
from pathlib import Path
from typing import List
from injexion.core.models import Finding, ScanMetadata
from injexion.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    def generate(
        self,
        findings: List[Finding],
        metadata: ScanMetadata,
        output_path: Path
    ) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report_data = {
            "schema_version": "2.0.0",
            "scanner": {
                "name": "InjeXion",
                "version": metadata.tool_version,
            },
            "metadata": metadata.model_dump(),
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
                "high": sum(1 for f in findings if f.severity == "HIGH"),
                "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
                "low": sum(1 for f in findings if f.severity == "LOW"),
                "info": sum(1 for f in findings if f.severity == "INFO"),
            },
            "findings": [f.model_dump() for f in findings],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        return output_path

