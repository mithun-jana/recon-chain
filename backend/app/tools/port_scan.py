"""
Port scanning.

"""
from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

from app.models import ScanConfig
from app.tools.base import ConcurrencyLimiter, RawResult, run_cmd_streaming, which

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 7001,
    8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 27017,
]

COMMON_SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 443: "https",
    3306: "mysql", 5432: "postgresql", 6379: "redis", 27017: "mongodb",
    8080: "http", 8443: "https",
}


async def _connect_check(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _via_python(ips: list[str], ports: list[int], concurrency: int) -> AsyncIterator[RawResult]:
    limiter = ConcurrencyLimiter(concurrency)

    async def check(ip: str, port: int):
        async with limiter:
            if await _connect_check(ip, port):
                return RawResult(
                    type="open_port", value=f"{ip}:{port}", source="tcp-connect",
                    parent_value=ip,
                    meta={"port": port, "ip": ip, "service": COMMON_SERVICE_NAMES.get(port, "unknown")},
                )
        return None

    tasks = [check(ip, port) for ip in ips for port in ports]
    for coro in asyncio.as_completed(tasks):
        result = await coro
        if result:
            yield result


async def _via_naabu(ips: list[str], ports: list[int]) -> AsyncIterator[RawResult]:
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
        f.write("\n".join(ips))
        path = f.name
    port_arg = ",".join(str(p) for p in ports)
    try:
        cmd = ["naabu", "-list", path, "-p", port_arg, "-json", "-silent"]
        async for line in run_cmd_streaming(cmd, timeout=300):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = obj.get("ip") or obj.get("host")
            port = obj.get("port")
            if ip and port:
                yield RawResult(
                    type="open_port", value=f"{ip}:{port}", source="naabu",
                    parent_value=ip,
                    meta={"port": port, "ip": ip, "service": COMMON_SERVICE_NAMES.get(port, "unknown")},
                )
    finally:
        os.unlink(path)


async def run(config: ScanConfig, ips: list[str]) -> AsyncIterator[RawResult]:
    if not ips:
        return
    ports = config.ports or DEFAULT_PORTS
    if which("naabu"):
        try:
            got_any = False
            async for r in _via_naabu(ips, ports):
                got_any = True
                yield r
            if got_any:
                return
        except Exception:
            pass
    async for r in _via_python(ips, ports, config.max_concurrency):
        yield r