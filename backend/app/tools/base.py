from __future__ import annotations

import asyncio
import functools
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Optional

logger = logging.getLogger("recon")


@functools.lru_cache(maxsize=64)
def which(binary: str, verify_contains: Optional[str] = None) -> Optional[str]:
 
    path = shutil.which(binary)
    if not path or not verify_contains:
        return path
    try:
        out = subprocess.run([path, "-h"], capture_output=True, text=True, timeout=5)
        combined = (out.stdout + out.stderr).lower()
        return path if verify_contains.lower() in combined else None
    except Exception:
        return None


class ToolExecutionError(RuntimeError):
    pass


async def run_cmd(cmd: list[str], timeout: int = 120) -> str:
    
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise
    if proc.returncode != 0:
        raise ToolExecutionError(
            f"{cmd[0]} exited {proc.returncode}: {stderr.decode(errors='ignore')[:300]}"
        )
    return stdout.decode(errors="ignore")


async def run_cmd_streaming(cmd: list[str], timeout: int = 600) -> AsyncIterator[str]:
    
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout

    assert proc.stdout is not None
    try:
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                proc.kill()
                raise asyncio.TimeoutError(f"{cmd[0]} exceeded {timeout}s timeout")
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
            except asyncio.TimeoutError:
                proc.kill()
                raise
            if not line:
                break
            decoded = line.decode(errors="ignore").rstrip("\n")
            if decoded:
                yield decoded
    finally:
        if proc.returncode is None:
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()

    if proc.returncode not in (0, None):
        stderr = await proc.stderr.read() if proc.stderr else b""
        
        logger.warning("%s exited %s: %s", cmd[0], proc.returncode, stderr.decode(errors="ignore")[:300])


@dataclass
class RawResult:
  
    type: str
    value: str
    source: str
    parent_value: Optional[str] = None
    meta: dict[str, Any] = field(default_factory=dict)


class RateLimiter:

    def __init__(self, per_sec: int):
        self.interval = 1.0 / max(per_sec, 1)
        self._lock = asyncio.Lock()

    async def wait(self):
        async with self._lock:
            await asyncio.sleep(self.interval)


class ConcurrencyLimiter:  

    def __init__(self, max_concurrent: int):
        self.sem = asyncio.Semaphore(max(max_concurrent, 1))

    async def __aenter__(self):
        await self.sem.acquire()
        return self

    async def __aexit__(self, *exc):
        self.sem.release()
