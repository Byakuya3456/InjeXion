"""
Base Reporter abstract interface.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List
from injexion.core.models import Finding, ScanMetadata


class BaseReporter(ABC):
    @abstractmethod
    def generate(
        self,
        findings: List[Finding],
        metadata: ScanMetadata,
        output_path: Path
    ) -> Path:
        """Render report and return output file path."""
        pass

