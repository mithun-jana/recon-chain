"""
JS file analysis.


"""
from __future__ import annotations

import asyncio
import re
from typing import AsyncIterator

import httpx

from app.models import ScanConfig
from app.tools.base import ConcurrencyLimiter, RateLimiter, RawResult

ENDPOINT_RE = re.compile(r'''["'](/[a-zA-Z0-9_\-/{}.]{2,80}?)["']''')
SECRET_PATTERNS = {
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "generic_api_key": re.compile(r"""(?i)api[_-]?key["']?\s*[:=]\s*["'][a-z0-9\-_]{16,45}["']"""),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "private_key_block": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH)? ?PRIVATE KEY-----"),
}
NOISE_EXT = re.compile(r"\.(png|jpg|jpeg|gif|svg|css|woff2?)($|\?)")


async def run(config: ScanConfig, js_urls: list[str]) -> AsyncIterator[RawResult]:
    if not js_urls:
        return
    rate = RateLimiter(config.rate_limit_per_sec)
    limiter = ConcurrencyLimiter(config.max_concurrency)

    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        async def check(url: str):
            async with limiter:
                await rate.wait()
                try:
                    resp = await client.get(url, follow_redirects=True)
                    body = resp.text or ""
                except Exception:
                    return None

            endpoints = sorted(set(m for m in ENDPOINT_RE.findall(body) if not NOISE_EXT.search(m)))[:50]
            secrets_found = [label for label, pattern in SECRET_PATTERNS.items() if pattern.search(body)]

            if endpoints or secrets_found:
                return RawResult(
                    type="js_file", value=url, source="js-regex-scan", parent_value=url,
                    meta={
                        "endpoints_found": endpoints,
                        "possible_secrets": secrets_found,
                        "severity": "high" if secrets_found else ("medium" if endpoints else "info"),
                    },
                )
            return None

        for coro in asyncio.as_completed([check(u) for u in js_urls]):
            result = await coro
            if result:
                yield result