"""
DNS permutation ("mutation-based" subdomain discovery).

"""
from __future__ import annotations

import asyncio
import re
from typing import AsyncIterator

import dns.resolver

from app.models import ScanConfig
from app.tools.base import ConcurrencyLimiter, RawResult, run_cmd, run_cmd_streaming, which


DEFAULT_MUTATIONS = [
    "dev", "staging", "stage", "test", "qa", "uat", "demo", "beta",
    "internal", "int", "admin", "api", "api-internal", "backend",
    "old", "new", "v1", "v2", "preprod", "prod", "sandbox", "corp",
    "vpn", "mail", "portal", "app", "apps", "gateway", "cdn", "static",
]


def _extract_labels(subdomains: list[str]) -> set[str]:
    """Pull out the leftmost label of each known subdomain as an extra
    mutation seed word (e.g. "api" from "api.example.com")."""
    words = set()
    for s in subdomains:
        parts = s.split(".")
        if len(parts) > 2:
            label = parts[0]
            words.update(re.split(r"[-_]", label))
    return {w for w in words if w and len(w) > 1}


def _generate_candidates(subdomains: list[str], domain: str, extra_words: list[str]) -> set[str]:
    seeds = set(DEFAULT_MUTATIONS) | _extract_labels(subdomains) | set(extra_words)
    candidates = set()
    for word in seeds:
        candidates.add(f"{word}.{domain}")
        candidates.add(f"{word}-{domain.split('.')[0]}.{domain.split('.', 1)[-1] if '.' in domain else domain}")
    
    seed_list = list(seeds)[:20]  
    for a in seed_list:
        for b in seed_list:
            if a != b:
                candidates.add(f"{a}-{b}.{domain}")
    return candidates


async def _resolve(host: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout, resolver.lifetime = 2, 2
    loop = asyncio.get_event_loop()

    def _sync():
        try:
            return [str(r) for r in resolver.resolve(host, "A")]
        except Exception:
            return []

    return await loop.run_in_executor(None, _sync)


async def _via_python(domain: str, known_subdomains: list[str], extra_words: list[str], concurrency: int) -> AsyncIterator[RawResult]:
    candidates = _generate_candidates(known_subdomains, domain, extra_words)
    limiter = ConcurrencyLimiter(concurrency)

    async def check(host: str):
        async with limiter:
            ips = await _resolve(host)
            if ips:
                return RawResult(
                    type="subdomain", value=host, source="dns-permute",
                    meta={"resolved": True, "ips": ips, "generated": True},
                )
        return None

    for coro in asyncio.as_completed([check(h) for h in candidates]):
        result = await coro
        if result:
            yield result


async def _via_dnsgen_puredns(domain: str, known_subdomains: list[str]) -> AsyncIterator[RawResult]:
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
        f.write("\n".join(known_subdomains) or domain)
        input_path = f.name

    try:
        gen_out = await run_cmd(["dnsgen", input_path])
        candidates = [line.strip() for line in gen_out.splitlines() if line.strip()]
    finally:
        os.unlink(input_path)

    if not candidates:
        return

    if which("puredns"):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("\n".join(candidates))
            cand_path = f.name
        try:
            async for line in run_cmd_streaming(["puredns", "resolve", cand_path], timeout=300):
                host = line.strip()
                if host:
                    yield RawResult(
                        type="subdomain", value=host, source="dnsgen+puredns",
                        meta={"resolved": True, "generated": True},
                    )
        finally:
            os.unlink(cand_path)
    else:
        
        limiter = ConcurrencyLimiter(50)

        async def check(host: str):
            async with limiter:
                ips = await _resolve(host)
                if ips:
                    return RawResult(
                        type="subdomain", value=host, source="dnsgen",
                        meta={"resolved": True, "ips": ips, "generated": True},
                    )
            return None

        for coro in asyncio.as_completed([check(h) for h in candidates]):
            result = await coro
            if result:
                yield result


async def run(config: ScanConfig, domain: str, known_subdomains: list[str]) -> AsyncIterator[RawResult]:
    extra_words: list[str] = []
    if config.permutation_wordlist_id:
        from app.wordlists import load_wordlist_words
        extra_words = load_wordlist_words(config.permutation_wordlist_id)

    if which("dnsgen"):
        try:
            got_any = False
            async for r in _via_dnsgen_puredns(domain, known_subdomains):
                got_any = True
                yield r
            if got_any:
                return
        except Exception:
            pass

    async for r in _via_python(domain, known_subdomains, extra_words, config.max_concurrency):
        yield r