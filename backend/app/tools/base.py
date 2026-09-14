from __future__ import annotations

import asyncio
import functools
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Optional

logger = logging.getLogger("recon")

_ACTIVE_PROCESSES: dict[int, set] = {}


def _register_process(scan_id: Optional[int], proc) -> None:
    if scan_id is None:
        return
    _ACTIVE_PROCESSES.setdefault(scan_id, set()).add(proc)


def _deregister_process(scan_id: Optional[int], proc) -> None:
    if scan_id is None:
        return
    procs = _ACTIVE_PROCESSES.get(scan_id)
    if procs is not None:
        procs.discard(proc)
        if not procs:
            _ACTIVE_PROCESSES.pop(scan_id, None)


def register_process(scan_id: Optional[int], proc) -> None:
    _register_process(scan_id, proc)


def deregister_process(scan_id: Optional[int], proc) -> None:
    _deregister_process(scan_id, proc)


def kill_scan_processes(scan_id: int) -> int:

    procs = _ACTIVE_PROCESSES.pop(scan_id, set())
    killed = 0
    for proc in list(procs):
        try:
            if proc.returncode is None:
                proc.kill()
                killed += 1
        except ProcessLookupError:
            pass
        except Exception as e:
            logger.warning("kill_scan_processes: failed to kill a process for scan %s: %s", scan_id, e)
    if killed:
        logger.info("kill_scan_processes: killed %d active process(es) for scan %s", killed, scan_id)
    return killed


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


async def run_cmd(cmd: list[str], timeout: int = 120, scan_id: Optional[int] = None) -> str:

    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    _register_process(scan_id, proc)
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise
    finally:
        _deregister_process(scan_id, proc)
    if proc.returncode != 0:
        raise ToolExecutionError(
            f"{cmd[0]} exited {proc.returncode}: {stderr.decode(errors='ignore')[:300]}"
        )
    return stdout.decode(errors="ignore")


async def run_cmd_streaming(cmd: list[str], timeout: int = 600, scan_id: Optional[int] = None) -> AsyncIterator[str]:
    
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    _register_process(scan_id, proc)
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
        _deregister_process(scan_id, proc)
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
