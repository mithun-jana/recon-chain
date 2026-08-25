"""
URL / endpoint collection (passive).

"""
from __future__ import annotations

from typing import AsyncIterator

import httpx

from app.models import ScanConfig
from app.tools.base import RawResult, run_cmd_streaming, which


async def _via_wayback(domain: str) -> AsyncIterator[RawResult]:
    url = (
        "http://web.archive.org/cdx/server/cdx"
        f"?url=*.{domain}/*&output=json&collapse=urlkey&fl=original&limit=5000"
    )
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            rows = resp.json()
        except Exception:
            return

    for row in rows[1:]:
        if row and row[0].startswith(("http://", "https://")):
            yield RawResult(type="url", value=row[0], source="wayback-cdx")


async def _via_gau(domain: str) -> AsyncIterator[RawResult]:
    async for line in run_cmd_streaming(["gau", domain], timeout=180):
        line = line.strip()
        if line.startswith(("http://", "https://")):
            yield RawResult(type="url", value=line, source="gau")


def _extract_domain(host: str) -> str:
    """Strip scheme/path/port from a bare host, URL, or host:port string."""
    h = host.strip()
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/")[0]
    h = h.split(":")[0]
    return h.lower()


async def run(config: ScanConfig, hosts: list[str]) -> AsyncIterator[RawResult]:

    candidates = hosts or [t.strip() for t in config.target.split(",") if t.strip()]
    domains = list(dict.fromkeys(_extract_domain(h) for h in candidates if h.strip()))

    seen: set[str] = set()

    for domain in domains:
        if not domain:
            continue
        got_any = False
        if which("gau"):
            try:
                async for r in _via_gau(domain):
                    got_any = True
                    if r.value not in seen:
                        seen.add(r.value)
                        yield r
            except Exception:
                pass
        if got_any:
            continue

        async for r in _via_wayback(domain):
            if r.value not in seen:
                seen.add(r.value)
                yield r