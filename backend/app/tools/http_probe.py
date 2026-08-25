"""
HTTP probing + URL status check (fully merged).
"""
from __future__ import annotations

import json
import time
from typing import AsyncIterator

import httpx as httpx_client

from app.models import ScanConfig
from app.tools.base import RawResult, RateLimiter, run_cmd, which


async def _check_one(client: httpx_client.AsyncClient, url: str, rate: RateLimiter) -> RawResult | None:
    """Check a single URL using Python httpx."""
    await rate.wait()
    
    start_time = time.time()
    try:
        resp = await client.get(url, timeout=10, follow_redirects=True)
        response_time = time.time() - start_time
        
        return RawResult(
            type="http_service",
            value=url,
            source="http_probe",
            meta={
                "status_code": resp.status_code,
                "content_length": len(resp.content or b""),
                "title": _extract_title(resp.text or ""),
                "server": resp.headers.get("server", ""),
                "response_time_ms": round(response_time * 1000, 2),
                "final_url": str(resp.url),
                "redirected": str(resp.url) != url,
                "content_type": resp.headers.get("content-type", ""),
            },
        )
    except Exception as e:
        return RawResult(
            type="http_service",
            value=url,
            source="http_probe",
            meta={
                "status_code": 0,
                "error": str(e),
                "content_length": 0,
            },
        )


def _extract_title(html: str) -> str:
    """Extract title from HTML."""
    import re
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip()[:200] if match else ""


async def _resolve_url(client: httpx_client.AsyncClient, host: str, rate: RateLimiter) -> RawResult | None:

    if "://" in host:
        return await _check_one(client, host, rate)

    https_result = await _check_one(client, f"https://{host}", rate)
    if https_result and https_result.meta.get("status_code", 0) not in (0, None):
        return https_result

    http_result = await _check_one(client, f"http://{host}", rate)
    if http_result and http_result.meta.get("status_code", 0) not in (0, None):
        return http_result

    return https_result or http_result


async def _via_python(urls: list[str], rate: RateLimiter) -> AsyncIterator[RawResult]:
    """Check URLs using Python httpx."""
    async with httpx_client.AsyncClient(verify=False, timeout=10) as client:
        for url in urls:
            result = await _resolve_url(client, url, rate)
            if result:
                yield result   


async def _via_httpx_cli(urls: list[str]) -> AsyncIterator[RawResult]:
    """Check URLs using ProjectDiscovery's httpx CLI."""
    import tempfile, os
    
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
        f.write("\n".join(urls))
        path = f.name
    
    try:
        out = await run_cmd([
            "httpx", 
            "-l", path, 
            "-json", "-silent",
            "-title", "-server", 
            "-status-code", "-content-length",
            "-response-time", "-follow-redirects"
        ])
    finally:
        os.unlink(path)

    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        
        status_code = obj.get("status_code")
        if status_code is not None:
            status_code = int(status_code)
        
        yield RawResult(   # <-- YIELD instead of append
            type="http_service",
            value=obj.get("url", obj.get("input", "")),
            source="http_probe",
            meta={
                "status_code": status_code,
                "content_length": obj.get("content_length", 0),
                "title": obj.get("title", ""),
                "server": obj.get("webserver", ""),
                "response_time_ms": obj.get("response_time", 0),
                "final_url": obj.get("url", ""),
                "redirected": obj.get("redirected", False),
                "content_type": obj.get("content_type", ""),
            },
        )


async def run(config: ScanConfig, urls: list[str]) -> AsyncIterator[RawResult]:

    if not urls:
        print("[HTTP Probe] No URLs provided")
        return

    print(f"[HTTP Probe] Checking {len(urls)} URLs")
    
    # Try httpx CLI first if available
    if which("httpx", verify_contains="projectdiscovery"):
        try:
            async for result in _via_httpx_cli(urls):   
                yield result
            return
        except Exception as e:
            print(f"[HTTP Probe] httpx CLI failed: {e}, falling back to Python")
    
   
    rate = RateLimiter(config.rate_limit_per_sec)
    async for result in _via_python(urls, rate):   
        yield result