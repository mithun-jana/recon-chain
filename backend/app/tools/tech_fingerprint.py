"""
Technology fingerprinting (Wappalyzer + regex fallback).
"""
from __future__ import annotations

import asyncio
import re
from typing import AsyncIterator

import httpx

from app.models import ScanConfig
from app.tools.base import ConcurrencyLimiter, RawResult

# Regex signatures (fallback)
SIGNATURES = [
    ("WordPress", None, None, r"wp-content|wp-includes"),
    ("Drupal", None, None, r"Drupal.settings|sites/default/files"),
    ("Joomla", None, None, r"/media/jui/|Joomla!"),
    ("Laravel", "set-cookie", r"laravel_session", None),
    ("Django", "set-cookie", r"csrftoken|django", None),
    ("Express", "x-powered-by", r"Express", None),
    ("Next.js", None, None, r"__NEXT_DATA__"),
    ("React", None, None, r"react-dom|data-reactroot"),
    ("Nginx", "server", r"nginx", None),
    ("Apache", "server", r"Apache", None),
    ("IIS", "server", r"IIS", None),
    ("Cloudflare", "server", r"cloudflare", None),
    ("PHP", "x-powered-by", r"PHP", None),
    ("jQuery", None, None, r"jquery(?:-|\.)([\d.]+)?\.js"),
]


def _fingerprint(headers: dict, body_snippet: str) -> list[str]:
    found = []
    for name, hdr, hdr_re, body_re in SIGNATURES:
        if hdr and hdr_re and re.search(hdr_re, headers.get(hdr, ""), re.IGNORECASE):
            found.append(name)
            continue
        if body_re and body_snippet and re.search(body_re, body_snippet, re.IGNORECASE):
            found.append(name)
    return found


async def run(config: ScanConfig, http_services: list[dict]) -> AsyncIterator[RawResult]:
    if not http_services:
        return

    # Try Wappalyzer first
    try:
        from wappalyzer import Wappalyzer
        wappalyzer = Wappalyzer()
        use_wappalyzer = True
    except ImportError:
        use_wappalyzer = False

    limiter = ConcurrencyLimiter(config.max_concurrency)

    async with httpx.AsyncClient(verify=False, timeout=8) as client:
        async def check(svc: dict):
            url = svc.get("url")
            if not url:
                return None

            async with limiter:
                try:
                    resp = await client.get(url, follow_redirects=True)
                    headers = dict(resp.headers)
                    body_snippet = (resp.text or "")[:20000]

                    if use_wappalyzer:
                        techs = wappalyzer.analyze(
                            url=url,
                            headers=headers,
                            html=resp.text,
                        )
                        if techs:
                            return RawResult(
                                type="http_service",
                                value=url,
                                source="wappalyzer",
                                parent_value=url,
                                meta={"tech": list(techs)},
                            )

                    # Fallback to regex
                    techs = _fingerprint(headers, body_snippet)
                    if techs:
                        return RawResult(
                            type="http_service",
                            value=url,
                            source="heuristic-fingerprint",
                            parent_value=url,
                            meta={"tech": techs},
                        )
                except Exception:
                    pass
            return None

        for coro in asyncio.as_completed([check(svc) for svc in http_services]):
            result = await coro
            if result:
                yield result