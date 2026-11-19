"""
Configuration manager and profile loader for InjeXion.
Supports 'mobile' (Termux battery/memory optimized) and 'desktop' profiles.
"""

from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    profile: str = "desktop"
    concurrency: int = 25
    timeout: float = 6.0
    rate_limit: float = 40.0  # requests per second
    max_retries: int = 2
    verify_ssl: bool = False
    follow_redirects: bool = True
    user_agent: str = "InjeXion/2.0.0 (Security Scanner; +https://github.com/injexion/injexion)"
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    proxy: Optional[str] = None
    formats: List[str] = Field(default_factory=lambda: ["console", "html", "json"])
    output_dir: Path = Field(default_factory=lambda: Path("reports"))
    custom_payload_dir: Optional[Path] = None
    stop_on_critical: bool = False
    delay_between_requests: float = 0.0

    @classmethod
    def create_for_profile(cls, profile: str = "desktop", **overrides) -> "ScanConfig":
        if profile.lower() in ("mobile", "termux", "android"):
            base = {
                "profile": "mobile",
                "concurrency": 4,
                "timeout": 8.0,
                "rate_limit": 8.0,
                "max_retries": 2,
            }
        else:
            base = {
                "profile": "desktop",
                "concurrency": 25,
                "timeout": 6.0,
                "rate_limit": 50.0,
                "max_retries": 2,
            }
        base.update(overrides)
        return cls(**base)

