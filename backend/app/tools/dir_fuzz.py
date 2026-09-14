"""
Directory / content discovery (fuzzing) 
"""
from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess as _subprocess
import sys
import asyncio
import tempfile
import uuid
import logging
from typing import AsyncIterator, Dict, Optional

import httpx

from app.models import ScanConfig, FuzzEngine
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


SCAN_PROGRESS: Dict[int, dict] = {}


def get_progress(scan_id: int) -> Optional[dict]:
    return SCAN_PROGRESS.get(scan_id)


def clear_progress(scan_id: int) -> None:
    SCAN_PROGRESS.pop(scan_id, None)


def _chunked(items: list[str], size: int) -> list[list[str]]:
    if size <= 0:
        size = len(items) or 1
    return [items[i:i + size] for i in range(0, len(items), size)] or [[]]


def _write_chunk_wordlist(words: list[str]) -> str:
    fd, path = tempfile.mkstemp(prefix="reconchain_fuzz_", suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(words))
    return path


async def _via_ffuf(base_url: str, wordlist_path: str, extensions: list[str], threads: int = 20, scan_id: Optional[int] = None) -> AsyncIterator[RawResult]:
    safe_threads = max(1, min(threads, 80))
    cmd = [
        "ffuf", "-u", f"{base_url.rstrip('/')}/FUZZ", "-w", wordlist_path,
        "-mc", ",".join(str(c) for c in sorted(DEFAULT_STATUS_ALLOWLIST)),
        "-noninteractive", "-s",
        "-t", str(safe_threads),
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


async def _via_feroxbuster(base_url: str, wordlist_path: str, extensions: list[str], threads: int = 20, scan_id: Optional[int] = None) -> AsyncIterator[RawResult]:
    safe_threads = max(1, min(threads, 80))
    status_codes = ",".join(str(c) for c in sorted(DEFAULT_STATUS_ALLOWLIST))
    cmd = [
        "feroxbuster", "-u", base_url, "-w", wordlist_path, "--no-state", "-q",
        "--insecure",
        "-s", status_codes,
        "-t", str(safe_threads),
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


@functools.lru_cache(maxsize=1)
def _resolve_dirsearch_cmd_prefix() -> Optional[list[str]]:

    path = shutil.which("dirsearch")
    if path:
        try:
            out = subprocess_check(path)
            if out:
                return [path]
        except Exception:
            pass

    try:
        import importlib
        importlib.import_module("dirsearch")
        return [sys.executable, "-m", "dirsearch"]
    except Exception:
        return None


def subprocess_check(path: str) -> bool:
    try:
        out = _subprocess.run([path, "-h"], capture_output=True, text=True, timeout=5)
        combined = (out.stdout + out.stderr).lower()
        return "dirsearch" in combined
    except Exception:
        return False


def dirsearch_available() -> bool:
    return _resolve_dirsearch_cmd_prefix() is not None


def _parse_size_to_bytes(size_str: str) -> int:
    
    try:
        m = re.match(r"([\d.]+)\s*(B|KB|MB|GB)?", size_str.strip().upper())
        if not m:
            return 0
        val = float(m.group(1))
        mult = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}.get(m.group(2) or "B", 1)
        return int(val * mult)
    except Exception:
        return 0

DIRSEARCH_LINE_RE = re.compile(
    r"^\[\d{2}:\d{2}:\d{2}\]\s+(?P<status>\d{3})\s+-\s+(?P<size>\S+)\s+-\s+(?P<url>\S+)"
)


async def _via_dirsearch(
    base_url: str,
    wordlist_path: str,
    extensions: list[str],
    threads: int,
    rate_limit_per_sec: int,
    scan_id: Optional[int] = None,
) -> AsyncIterator[RawResult]:
   
    cmd_prefix = _resolve_dirsearch_cmd_prefix()
    if not cmd_prefix:
        raise RuntimeError(
            "dirsearch selected but not found on PATH or importable. "
            "Install it with: pip install dirsearch"
        )

    status_codes = ",".join(str(c) for c in sorted(DEFAULT_STATUS_ALLOWLIST))
    safe_threads = max(1, min(threads, 100))
    

    cmd = cmd_prefix + [
        "-u", base_url,
        "-w", wordlist_path,
        "-q",                       
        "--no-color",
        "-t", str(safe_threads),
        "-i", status_codes,        
        "--timeout", "5",
    ]
    if extensions:
        cmd += ["-e", ",".join(e.lstrip(".") for e in extensions)]

    logger.info("dir_fuzz: running dirsearch on %s with cmd: %s", base_url, " ".join(cmd))

    async for line in run_cmd_streaming(cmd, timeout=600):
        line = line.strip()
        if not line:
            continue
        m = DIRSEARCH_LINE_RE.match(line)
        if not m:
            continue
        try:
            status = int(m.group("status"))
        except ValueError:
            continue
        if status not in DEFAULT_STATUS_ALLOWLIST:
            continue

        url = m.group("url")
        if not url.startswith(("http://", "https://")):
            url = f"{base_url.rstrip('/')}/{url.lstrip('/')}"

        yield RawResult(
            type="directory",
            value=url,
            source="dirsearch",
            parent_value=base_url,
            meta={
                "status_code": status,
                "content_length": _parse_size_to_bytes(m.group("size")),
            },
        )


async def _via_python(
    base_url: str,
    words: list[str],
    extensions: list[str],
    rate: RateLimiter,
    concurrency: int,
) -> AsyncIterator[RawResult]:

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
        pending = []
        for word in words:
            pending.append(word)
            if len(pending) >= chunk_size:
                for w in pending:
                    await check(w)
                for r in results:
                    yield r
                results.clear()
                pending.clear()
                await asyncio.sleep(0.25)

        for w in pending:
            await check(w)
        for r in results:
            yield r


async def run(config: ScanConfig, base_urls: list[str], scan_id: Optional[int] = None) -> AsyncIterator[RawResult]:
    if not base_urls:
        logger.warning("dir_fuzz: no base URLs to fuzz (http_probe likely disabled)")
        return

    words = load_wordlist_words(config.wordlist_id)
    total_words = len(words)
    logger.info("dir_fuzz: using wordlist %s (%d words)", get_wordlist_path(config.wordlist_id), total_words)

    if scan_id is not None:
        SCAN_PROGRESS[scan_id] = {
            "target": base_urls[0] if base_urls else None,
            "tried": 0,
            "total": total_words * len(base_urls),
            "wordlist_total": total_words,
        }

    if total_words == 0:
        if scan_id is not None:
            clear_progress(scan_id)
        return

    engine = getattr(config, "fuzz_engine", FuzzEngine.auto)

    ffuf_verified = which("ffuf", verify_contains="ffuf")
    ferox_verified = which("feroxbuster", verify_contains="feroxbuster")
    dirsearch_verified = dirsearch_available()

    # Resolve which engine this run will actually use.
    if engine == FuzzEngine.dirsearch:
        if not dirsearch_verified:
            raise RuntimeError(
                "fuzz_engine='dirsearch' was selected but dirsearch isn't installed. "
                "Install it with: pip install dirsearch"
            )
        selected = "dirsearch"
    elif engine == FuzzEngine.ffuf:
        if not ffuf_verified:
            raise RuntimeError("fuzz_engine='ffuf' was selected but ffuf isn't installed/on PATH.")
        selected = "ffuf"
    elif engine == FuzzEngine.feroxbuster:
        if not ferox_verified:
            raise RuntimeError("fuzz_engine='feroxbuster' was selected but feroxbuster isn't installed/on PATH.")
        selected = "feroxbuster"
    elif engine == FuzzEngine.python:
        selected = "python"
    else:  

        if ferox_verified:
            selected = "feroxbuster"
        elif ffuf_verified:
            selected = "ffuf"
        else:
            selected = "python"

    logger.info("dir_fuzz: using engine=%s for this scan", selected)

    
    if selected == "dirsearch":
        
        chunk_size = max(150, total_words // 10)
    else:
       
        chunk_size = max(50, total_words // 20)
    chunks = _chunked(words, chunk_size)

    rate = RateLimiter(config.rate_limit_per_sec)

    for i, base_url in enumerate(base_urls):
        if i > 0:
            await asyncio.sleep(0.5)

        logger.info("dir_fuzz: fuzzing %s (target %d/%d)", base_url, i + 1, len(base_urls))
        if scan_id is not None:
            SCAN_PROGRESS[scan_id]["target"] = base_url

        for chunk in chunks:
            if not chunk:
                continue
            tmp_path = None
            try:
                if selected == "ffuf":
                    tmp_path = _write_chunk_wordlist(chunk)
                    async for r in _via_ffuf(base_url, tmp_path, config.fuzz_extensions, config.max_concurrency, scan_id=scan_id):
                        yield r
                elif selected == "feroxbuster":
                    tmp_path = _write_chunk_wordlist(chunk)
                    async for r in _via_feroxbuster(base_url, tmp_path, config.fuzz_extensions, config.max_concurrency, scan_id=scan_id):
                        yield r
                elif selected == "dirsearch":
                    tmp_path = _write_chunk_wordlist(chunk)
                    async for r in _via_dirsearch(
                        base_url, tmp_path, config.fuzz_extensions,
                        config.max_concurrency, config.rate_limit_per_sec, scan_id=scan_id,
                    ):
                        yield r
                else:
                    async for r in _via_python(base_url, chunk, config.fuzz_extensions, rate, config.max_concurrency):
                        yield r
            except Exception as e:
                logger.warning("dir_fuzz: chunk failed for %s: %s (skipping chunk)", base_url, e)

            finally:
                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                if scan_id is not None:
                    SCAN_PROGRESS[scan_id]["tried"] += len(chunk)
