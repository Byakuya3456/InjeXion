"""
Abstract base class contract for all InjeXion vulnerability detectors.
"""

from abc import ABC, abstractmethod
from typing import List
from injexion.core.config import ScanConfig
from injexion.core.models import Finding, InjectionTarget
from injexion.engine.client import AsyncHTTPClient


class BaseDetector(ABC):
    """Abstract vulnerability detector."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def scan(
        self,
        target: InjectionTarget,
        client: AsyncHTTPClient,
        config: ScanConfig,
        payloads: List[str]
    ) -> List[Finding]:
        """Execute detection routine against target injection point."""
        pass

