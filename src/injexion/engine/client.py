"""
Asynchronous HTTP client engine for InjeXion.
Built on httpx.AsyncClient with connection pooling, retries, and timing telemetry.
"""

import asyncio
import time
from typing import Any, Dict, Optional, Tuple
import httpx

from injexion.core.config import ScanConfig
from injexion.core.models import HttpEvidence
from injexion.engine.rate_limiter import AsyncRateLimiter


class AsyncHTTPClient:
    """Production-grade asynchronous HTTP engine."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.rate_limiter = AsyncRateLimiter(rate_limit=config.rate_limit)
        
        # Configure connection limits based on profile
        if config.profile == "mobile":
            limits = httpx.Limits(
                max_connections=config.concurrency * 2,
                max_keepalive_connections=config.concurrency,
                keepalive_expiry=5.0
            )
        else:
            limits = httpx.Limits(
                max_connections=config.concurrency * 2,
                max_keepalive_connections=config.concurrency,
                keepalive_expiry=30.0
            )

        headers = {
            "User-Agent": config.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            **config.headers
        }

        self._client = httpx.AsyncClient(
            headers=headers,
            cookies=config.cookies,
            timeout=httpx.Timeout(config.timeout),
            verify=config.verify_ssl,
            follow_redirects=config.follow_redirects,
            limits=limits,
            proxy=config.proxy,
        )
        self.request_count = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self) -> None:
        if not self._client.is_closed:
            await self._client.aclose()

    async def send(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
    ) -> Tuple[Optional[httpx.Response], HttpEvidence]:
        """Send an HTTP request with rate limiting, retries, and evidence capture."""
        await self.rate_limiter.acquire()
        self.request_count += 1

        req_headers = dict(self._client.headers)
        if headers:
            req_headers.update(headers)

        body_str: Optional[str] = None
        if json_body is not None:
            import json
            body_str = json.dumps(json_body)
        elif data is not None:
            import urllib.parse
            body_str = urllib.parse.urlencode(data)

        start_time = time.monotonic()
        response: Optional[httpx.Response] = None
        attempts = 0

        while attempts <= self.config.max_retries:
            attempts += 1
            try:
                response = await self._client.request(
                    method=method,
                    url=url,
                    params=params,
                    headers=headers,
                    data=data,
                    json=json_body,
                )
                if response.status_code in (429, 503) and attempts <= self.config.max_retries:
                    await self.rate_limiter.backoff(attempt=attempts)
                    continue
                break
            except (httpx.RequestError, httpx.TimeoutException):
                if attempts <= self.config.max_retries:
                    await asyncio.sleep(0.5 * attempts)
                    continue
                response = None
                break

        elapsed_ms = (time.monotonic() - start_time) * 1000.0

        # Construct evidence
        evidence = HttpEvidence(
            request_method=method,
            request_url=str(response.url) if response else url,
            request_headers=req_headers,
            request_body=body_str,
            response_status=response.status_code if response else 0,
            response_headers=dict(response.headers) if response else {},
            response_snippet=(response.text[:2000] if response and response.text else ""),
            response_time_ms=round(elapsed_ms, 2)
        )

        return response, evidence

    async def get(self, url: str, params: Optional[Dict[str, Any]] = None, **kwargs):
        return await self.send("GET", url, params=params, **kwargs)

    async def post(self, url: str, data: Optional[Dict[str, Any]] = None, json_body: Optional[Any] = None, **kwargs):
        return await self.send("POST", url, data=data, json_body=json_body, **kwargs)

