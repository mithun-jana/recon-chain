"""
DNS resolution / validation.
"""
from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

import dns.resolver

from app.models import ScanConfig
from app.tools.base import ConcurrencyLimiter, RawResult, run_cmd_streaming, which

DANGLING_CNAME_HINTS = [
    "s3.amazonaws.com", "herokuapp.com", "github.io", "azurewebsites.net",
    "cloudapp.net", "trafficmanager.net", "readme.io", "surge.sh",
    "unbouncepages.com", "wpengine.com", "zendesk.com",
]


def _resolve_one(host: str) -> tuple[list[str], list[str]]:
    ips, cnames = [], []
    resolver = dns.resolver.Resolver()
    resolver.timeout, resolver.lifetime = 3, 3
    try:
        for rdata in resolver.resolve(host, "CNAME"):
            cnames.append(str(rdata.target).rstrip("."))
    except Exception:
        pass
    try:
        for rdata in resolver.resolve(host, "A"):
            ips.append(str(rdata))
    except Exception:
        pass
    return ips, cnames


async def _via_python(hosts: list[str], concurrency: int) -> AsyncIterator[RawResult]:
    loop = asyncio.get_event_loop()
    limiter = ConcurrencyLimiter(concurrency)

    async def resolve(host: str):
        async with limiter:
            ips, cnames = await loop.run_in_executor(None, _resolve_one, host)
            return host, ips, cnames

    for coro in asyncio.as_completed([resolve(h) for h in hosts]):
        host, ips, cnames = await coro
        if not ips and not cnames:
            continue
        dangling = any(hint in c for c in cnames for hint in DANGLING_CNAME_HINTS)
        yield RawResult(
            type="subdomain", value=host, source="dnspython",
            meta={"resolved": True, "ips": ips, "cnames": cnames, "possible_takeover": dangling},
        )
        for ip in ips:
            yield RawResult(type="ip", value=ip, source="dnspython", parent_value=host)


async def _via_dnsx(hosts: list[str]) -> AsyncIterator[RawResult]:
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
        f.write("\n".join(hosts))
        path = f.name
    try:
        async for line in run_cmd_streaming(["dnsx", "-l", path, "-a", "-cname", "-json", "-silent"], timeout=180):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = obj.get("host")
            ips = obj.get("a", []) or []
            cnames = obj.get("cname", []) or []
            dangling = any(hint in c for c in cnames for hint in DANGLING_CNAME_HINTS)
            yield RawResult(
                type="subdomain", value=host, source="dnsx",
                meta={"resolved": True, "ips": ips, "cnames": cnames, "possible_takeover": dangling},
            )
            for ip in ips:
                yield RawResult(type="ip", value=ip, source="dnsx", parent_value=host)
    finally:
        os.unlink(path)


async def run(config: ScanConfig, subdomains: list[str]) -> AsyncIterator[RawResult]:
    if not subdomains:
        return
    if which("dnsx"):
        try:
            got_any = False
            async for r in _via_dnsx(subdomains):
                got_any = True
                yield r
            if got_any:
                return
        except Exception:
            pass
    async for r in _via_python(subdomains, config.max_concurrency):
        yield r