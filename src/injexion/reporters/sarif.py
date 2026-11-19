"""
OASIS SARIF v2.1.0 reporter for InjeXion.
Compliant with GitHub Code Scanning & CI/CD security gating.
"""

import json
from pathlib import Path
from typing import Any, Dict, List
from injexion.core.models import Finding, ScanMetadata
from injexion.reporters.base import BaseReporter

SEVERITY_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}


class SARIFReporter(BaseReporter):
    def generate(
        self,
        findings: List[Finding],
        metadata: ScanMetadata,
        output_path: Path
    ) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        rules: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for f in findings:
            rule_id = f.cwe_id if f.cwe_id else "SEC-001"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.vuln_type,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": SEVERITY_LEVEL_MAP.get(f.severity.value, "warning")
                    },
                    "help": {
                        "text": f"Remediation: {f.remediation}",
                        "markdown": f"### Remediation\n{f.remediation}"
                    },
                    "properties": {
                        "tags": ["security", "web", f.cwe_id],
                        "security-severity": str(f.cvss_score)
                    }
                }

            result_entry = {
                "ruleId": rule_id,
                "level": SEVERITY_LEVEL_MAP.get(f.severity.value, "warning"),
                "message": {
                    "text": f"{f.title} detected on {f.target_url} via parameter '{f.parameter or 'N/A'}'"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.target_url
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1
                            }
                        }
                    }
                ],
                "properties": {
                    "cvss": f.cvss_score,
                    "payload": f.payload
                }
            }
            results.append(result_entry)

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "InjeXion",
                            "semanticVersion": metadata.tool_version,
                            "informationUri": "https://github.com/injexion/injexion",
                            "rules": list(rules.values())
                        }
                    },
                    "results": results
                }
            ]
        }

        with open(output_path, "w", encoding="utf-8") as out:
            json.dump(sarif_doc, out, indent=2)

        return output_path

