"""
Service / version enrichment.
"""
from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from typing import AsyncIterator

from app.models import ScanConfig
from app.tools.base import ConcurrencyLimiter, RawResult, which


BANNER_PATTERNS = [
    (re.compile(rb"SSH-([\d.]+)-(\S+)"), "ssh"),
    (re.compile(rb"^220.*FTP", re.IGNORECASE), "ftp"),
    (re.compile(rb"^220.*SMTP|ESMTP", re.IGNORECASE), "smtp"),
    (re.compile(rb"^\+OK", re.IGNORECASE), "pop3"),
    (re.compile(rb"^\* OK", re.IGNORECASE), "imap"),
    (re.compile(rb"^HTTP/\d\.\d"), "http"),
    (re.compile(rb"^\x00\x00\x00.*mysql", re.IGNORECASE), "mysql"),
    (re.compile(rb"^-ERR|^\$"), "redis"),
]


async def _banner_grab(ip: str, port: int, timeout: float = 3.0) -> dict:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        for pattern, service in BANNER_PATTERNS:
            if pattern.search(data):
                return {"service": service, "banner": data.decode(errors="ignore").strip()[:200]}
        if data:
            return {"service": "unknown", "banner": data.decode(errors="ignore").strip()[:200]}
        return {}
    except Exception:
        return {}


async def _via_python(open_ports: list[tuple[str, int]], concurrency: int) -> AsyncIterator[RawResult]:
    limiter = ConcurrencyLimiter(concurrency)

    async def check(ip: str, port: int):
        async with limiter:
            info = await _banner_grab(ip, port)
            if info:
                yield_val = RawResult(
                    type="open_port", value=f"{ip}:{port}", source="banner-grab",
                    parent_value=ip, meta=info,
                )
                return yield_val
        return None

    tasks = [check(ip, port) for ip, port in open_ports]
    for coro in asyncio.as_completed(tasks):
        result = await coro
        if result:
            yield result


async def _via_nmap(open_ports: list[tuple[str, int]]) -> AsyncIterator[RawResult]:
    by_ip: dict[str, list[int]] = {}
    for ip, port in open_ports:
        by_ip.setdefault(ip, []).append(port)

    for ip, ports in by_ip.items():
        port_arg = ",".join(str(p) for p in ports)
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "--version-light", "-p", port_arg, "-oX", "-", ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        try:
            root = ET.fromstring(stdout.decode(errors="ignore"))
        except ET.ParseError:
            continue

        for host_el in root.findall("host"):
            for port_el in host_el.findall(".//port"):
                port_num = int(port_el.get("portid"))
                service_el = port_el.find("service")
                if service_el is None:
                    continue
                meta = {
                    "service": service_el.get("name", "unknown"),
                    "product": service_el.get("product", ""),
                    "version": service_el.get("version", ""),
                    "extrainfo": service_el.get("extrainfo", ""),
                }
                yield RawResult(
                    type="open_port", value=f"{ip}:{port_num}", source="nmap",
                    parent_value=ip, meta=meta,
                )


async def run(config: ScanConfig, open_ports: list[tuple[str, int]]) -> AsyncIterator[RawResult]:
    if not open_ports:
        return
    if which("nmap"):
        try:
            got_any = False
            async for r in _via_nmap(open_ports):
                got_any = True
                yield r
            if got_any:
                return
        except Exception:
            pass
    async for r in _via_python(open_ports, config.max_concurrency):
        yield r