"""
Active crawling + integrated JS analysis.
"""
from __future__ import annotations

import re
from typing import AsyncIterator
from urllib.parse import urljoin, urlparse

import httpx

from app.models import ScanConfig
from app.tools.base import ConcurrencyLimiter, RateLimiter, RawResult, run_cmd_streaming, which
from app.tools.js_analysis import run as js_analysis_run

LINK_RE = re.compile(r'''(?:href|src|action)=["']([^"'#\s]+)["']''', re.IGNORECASE)
JS_URL_RE = re.compile(r'\.js($|\?)', re.IGNORECASE)


async def _via_katana(base_url: str, depth: int = 3) -> AsyncIterator[RawResult]:
    cmd = ["katana", "-u", base_url, "-d", str(depth), "-silent", "-jc"]
    async for line in run_cmd_streaming(cmd, timeout=300):
        url = line.strip()
        if not url:
            continue
        
        if url.endswith(".js") or ".js?" in url:
            yield RawResult(type="js_file", value=url, source="katana", parent_value=base_url)
        else:
            yield RawResult(type="url", value=url, source="katana", parent_value=base_url)


def _same_host(url: str, host: str) -> bool:
    try:
        return urlparse(url).hostname == host
    except Exception:
        return False


async def _via_python(base_url: str, rate: RateLimiter, max_pages: int = 60) -> AsyncIterator[RawResult]:
    host = urlparse(base_url).hostname
    seen: set[str] = {base_url}
    queue: list[str] = [base_url]
    limiter = ConcurrencyLimiter(10)
    js_urls = []

    async with httpx.AsyncClient(verify=False, timeout=8) as client:
        pages_fetched = 0
        while queue and pages_fetched < max_pages:
            url = queue.pop(0)
            async with limiter:
                await rate.wait()
                try:
                    resp = await client.get(url, follow_redirects=True)
                except Exception:
                    continue
            pages_fetched += 1
            yield RawResult(
                type="url", value=str(resp.url), source="python-crawler",
                parent_value=base_url,
                meta={"status_code": resp.status_code},
            )

          
            if JS_URL_RE.search(url):
                js_urls.append(url)

            if "text/html" not in resp.headers.get("content-type", ""):
                continue

            for match in LINK_RE.findall(resp.text or ""):
                absolute = urljoin(url, match)
                absolute = absolute.split("#")[0]
                if absolute in seen or not _same_host(absolute, host):
                    continue
                seen.add(absolute)
                queue.append(absolute)


    if js_urls:
        async for js_result in js_analysis_run(config, js_urls):  # <-- FIXED
            yield js_result


async def run(config: ScanConfig, base_urls: list[str]) -> AsyncIterator[RawResult]:
    if not base_urls:
        return
    for base_url in base_urls:
        if which("katana"):
            try:
                async for r in _via_katana(base_url):
                    yield r
                continue
            except Exception:
                pass
        rate = RateLimiter(config.rate_limit_per_sec)
        async for r in _via_python(base_url, rate):
            yield r