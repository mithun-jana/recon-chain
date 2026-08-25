"""
Directory / content discovery (fuzzing) — PRODUCTION READY.
"""
from __future__ import annotations

import re
import shutil
import asyncio
import uuid
import logging
from typing import AsyncIterator

import httpx

from app.models import ScanConfig
from app.tools.base import ConcurrencyLimiter, RateLimiter, RawResult, run_cmd_streaming, which
from app.wordlists import load_wordlist_words, get_wordlist_path

logger = logging.getLogger("recon.dir_fuzz")


FFUF_LINE_RE = re.compile(
    r"^(?P<word>\S+)\s+\[Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+),"
    r"\s*Words:\s*(?P<words>\d+),\s*Lines:\s*(?P<lines>\d+)"
)


FEROX_LINE_RE = re.compile(
    r"^(?P<status>\d+)\s+\S+\s+(?P<lines>\d+)l\s+(?P<words>\d+)w\s+(?P<size>\d+)c\s+(?P<url>\S+)$"
)

DEFAULT_STATUS_ALLOWLIST = {200, 201, 204, 301, 302, 307, 308, 401, 403}


async def _via_ffuf(base_url: str, wordlist_path: str, extensions: list[str]) -> AsyncIterator[RawResult]:
    cmd = [
        "ffuf", "-u", f"{base_url.rstrip('/')}/FUZZ", "-w", wordlist_path,
        "-mc", ",".join(str(c) for c in sorted(DEFAULT_STATUS_ALLOWLIST)),
        "-noninteractive", "-s",
        "-t", "20",
        "-p", "0.25",
        "-timeout", "5",
        "-ac",
    ]
    if extensions:
        cmd += ["-e", ",".join("." + e.lstrip(".") for e in extensions)]

    logger.info("dir_fuzz: running ffuf on %s with cmd: %s", base_url, " ".join(cmd))
    async for line in run_cmd_streaming(cmd, timeout=600):
        m = FFUF_LINE_RE.match(line.strip())
        if not m:
            continue
        path = m.group("word")
        yield RawResult(
            type="directory",
            value=f"{base_url.rstrip('/')}/{path}",
            source="ffuf",
            parent_value=base_url,
            meta={
                "status_code": int(m.group("status")),
                "content_length": int(m.group("size")),
            },
        )


async def _via_feroxbuster(base_url: str, wordlist_path: str, extensions: list[str]) -> AsyncIterator[RawResult]:
    status_codes = ",".join(str(c) for c in sorted(DEFAULT_STATUS_ALLOWLIST))
    cmd = [
        "feroxbuster", "-u", base_url, "-w", wordlist_path, "--no-state", "-q",
        "--insecure",
        "-s", status_codes,
        "-t", "20",
        "--rate-limit", "4",     
        "--timeout", "5",
    ]
    if extensions:
        cmd += ["-x", ",".join(e.lstrip(".") for e in extensions)]

    logger.info("dir_fuzz: running feroxbuster on %s with cmd: %s", base_url, " ".join(cmd))
    async for line in run_cmd_streaming(cmd, timeout=600):
        line = line.strip()
        if not line:
            continue
        m = FEROX_LINE_RE.match(line)
        if not m:
            continue
        yield RawResult(
            type="directory",
            value=m.group("url"),
            source="feroxbuster",
            parent_value=base_url,
            meta={
                "status_code": int(m.group("status")),
                "content_length": int(m.group("size")),
            },
        )


async def _via_python(
    base_url: str,
    wordlist_path: str,
    extensions: list[str],
    rate: RateLimiter,
    concurrency: int,
) -> AsyncIterator[RawResult]:
    
    
    def word_generator(path: str):
        with open(path) as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith("#"):
                    yield word

    async with httpx.AsyncClient(verify=False) as client:
        fake_path = f"{base_url.rstrip('/')}/__recon_nonexistent_{uuid.uuid4().hex[:12]}__"
        try:
            baseline_resp = await client.get(fake_path, timeout=5, follow_redirects=True)
            baseline_status, baseline_len = baseline_resp.status_code, len(baseline_resp.content or b"")
        except Exception:
            baseline_status, baseline_len = 0, -1

       
        baseline_location = None
        try:
            if 300 <= baseline_status < 400:
                baseline_location = baseline_resp.headers.get("location")
        except Exception:
            pass

        limiter = ConcurrencyLimiter(concurrency)
        results: list[RawResult] = []

        async def check(word: str):
            async with limiter:
                await rate.wait()
                url = f"{base_url.rstrip('/')}/{word}"
                try:
                    resp = await client.get(url, timeout=5, follow_redirects=False)
                except Exception:
                    return
                if resp.status_code not in DEFAULT_STATUS_ALLOWLIST:
                    return
                content_len = len(resp.content or b"")

                if resp.status_code == baseline_status:
                    if 300 <= resp.status_code < 400:
                      
                        if resp.headers.get("location") == baseline_location:
                            return
                    elif abs(content_len - baseline_len) < 25:
                        return

                results.append(RawResult(
                    type="directory", value=url, source="python-fuzzer",
                    parent_value=base_url,
                    meta={"status_code": resp.status_code, "content_length": content_len},
                ))

        chunk_size = concurrency * 4
        chunk = []
        for word in word_generator(wordlist_path):
            chunk.append(word)
            if len(chunk) >= chunk_size:
                for w in chunk:
                    await check(w)
                for r in results:
                    yield r
                results.clear()
                chunk.clear()
                await asyncio.sleep(0.25)
        
        for w in chunk:
            await check(w)
        for r in results:
            yield r


async def run(config: ScanConfig, base_urls: list[str]) -> AsyncIterator[RawResult]:
    if not base_urls:
        logger.warning("dir_fuzz: no base URLs to fuzz (http_probe likely disabled)")
        return

    path = get_wordlist_path(config.wordlist_id)
    logger.info("dir_fuzz: using wordlist %s", path)

    ffuf_path = shutil.which("ffuf")
    ffuf_verified = which("ffuf", verify_contains="projectdiscovery")

    ferox_path = shutil.which("feroxbuster")
    ferox_verified = which("feroxbuster", verify_contains="feroxbuster")

    for i, base_url in enumerate(base_urls):
        if i > 0:
            await asyncio.sleep(0.5)  

        logger.info("dir_fuzz: fuzzing %s (target %d/%d)", base_url, i+1, len(base_urls))

        try:
            if ffuf_verified:
                async for r in _via_ffuf(base_url, path, config.fuzz_extensions):
                    yield r
                continue

            if ferox_verified:
                async for r in _via_feroxbuster(base_url, path, config.fuzz_extensions):
                    yield r
                continue

            rate = RateLimiter(config.rate_limit_per_sec)
            async for r in _via_python(base_url, path, config.fuzz_extensions, rate, config.max_concurrency):
                yield r

        except Exception as e:
            logger.warning("dir_fuzz: failed for %s: %s (skipping)", base_url, e)
            continue