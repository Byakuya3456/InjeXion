"""
Asynchronous TCP Port Scanner.
Uses non-blocking asyncio.open_connection for ultra-fast scanning across mobile and desktop.
"""

import asyncio
from typing import Dict, List, Optional
from injexion.core.constants import COMMON_PORTS
from injexion.core.models import PortResult


class AsyncPortScanner:
    """Non-blocking TCP port prober."""

    def __init__(self, ports: Optional[Dict[int, str]] = None, timeout: float = 2.0, concurrency: int = 30):
        self.ports = ports if ports is not None else COMMON_PORTS
        self.timeout = timeout
        self.concurrency = concurrency

    async def probe_port(self, host: str, port: int, service: str) -> Optional[PortResult]:
        try:
            connect_coro = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(connect_coro, timeout=self.timeout)
            
            banner: Optional[str] = None
            try:
                # Quick non-blocking read for banner if server speaks first
                data = await asyncio.wait_for(reader.read(128), timeout=0.8)
                if data:
                    banner = data.decode("utf-8", errors="ignore").strip()
            except (asyncio.TimeoutError, Exception):
                pass
            finally:
                writer.close()
                await writer.wait_closed()

            return PortResult(port=port, service=service, state="open", banner=banner)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    async def scan(self, host: str) -> List[PortResult]:
        open_ports: List[PortResult] = []
        sem = asyncio.Semaphore(self.concurrency)

        async def worker(port: int, svc: str):
            async with sem:
                res = await self.probe_port(host, port, svc)
                if res:
                    open_ports.append(res)

        tasks = [worker(port, svc) for port, svc in self.ports.items()]
        await asyncio.gather(*tasks)

        open_ports.sort(key=lambda x: x.port)
        return open_ports

