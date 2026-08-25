"""
Screenshotting (CLI-first, Python fallback).

"""
from __future__ import annotations

import asyncio
import functools
import hashlib
import os
import subprocess
from typing import AsyncIterator

from app.models import ScanConfig
from app.tools.base import RawResult


SCREENSHOT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "screenshots")


MAX_CONCURRENT = 5


@functools.lru_cache(maxsize=1)
def _check_cli_installed() -> bool:

    try:
        result = subprocess.run(
            ["playwright", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


@functools.lru_cache(maxsize=1)
def _supports_wait_until() -> bool:
    """Cached for the same reason as _check_cli_installed()."""
    try:
        result = subprocess.run(
            ["playwright", "screenshot", "--help"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return "--wait-until" in result.stdout
    except Exception:
        return False


@functools.lru_cache(maxsize=1)
def _supports_ignore_https_errors() -> bool:

    try:
        result = subprocess.run(
            ["playwright", "screenshot", "--help"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return "--ignore-https-errors" in result.stdout
    except Exception:
        return False


async def _via_cli(url: str, output_path: str) -> tuple[bool, int, str]:
    """
    Take a screenshot using Playwright CLI.
    """
    try:
       
        is_js = url.endswith(".js") or ".js?" in url
        timeout_sec = 8 if is_js else 25  

     
        wait_until = "load"

        cmd = [
            "playwright", "screenshot",
            url,
            output_path,
            "--full-page",
            "--timeout", str(timeout_sec * 1000)  
        ]
        if _supports_wait_until():
            cmd.append("--wait-until")
            cmd.append(wait_until)
        if _supports_ignore_https_errors():
            cmd.append("--ignore-https-errors")

        print(f"[Screenshot] Running: {' '.join(cmd)}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec + 10)
        if proc.returncode == 0:
            print(f"[Screenshot]  Saved: {output_path}")
            return True, 200, ""
        else:
            err_text = stderr.decode(errors="ignore")
            # Only log if it's not a DNS error
            if "ERR_NAME_NOT_RESOLVED" not in err_text:
                print(f"[Screenshot]  Failed: {err_text}")
            return False, 0, err_text
    except asyncio.TimeoutError:
        return False, 408, "Timeout"
    except Exception as e:
        return False, 0, str(e)


async def _via_python(url: str, output_path: str) -> tuple[bool, int, str]:

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return False, 0, "Playwright not installed"

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        page = await browser.new_page(ignore_https_errors=True)
        try:
            try:
                response = await page.goto(url, timeout=25000, wait_until='load')
            except Exception:
              
                response = await page.goto(url, timeout=25000, wait_until='commit')
            if response and response.status >= 400:
                return False, response.status, f"HTTP {response.status}"
            await page.wait_for_timeout(1500)  
       
            await page.screenshot(path=output_path, full_page=True, timeout=30000)
            return True, response.status if response else 200, ""
        finally:
            await browser.close()


async def run(config: ScanConfig, urls: list[str]) -> AsyncIterator[RawResult]:
    """
    Takes screenshots of provided URLs using Playwright CLI 
    """
    if not urls:
        return

    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    cli_installed = _check_cli_installed()

    if cli_installed:
        print("[Screenshot] Using Playwright CLI (with Python fallback per-URL on failure)")
    else:
        print("[Screenshot] Using Python Playwright (CLI not installed)")

    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    async def process_one(url: str):
        async with semaphore:
            # Generate filename
            url_hash = hashlib.md5(url.encode()).hexdigest()
            fname = f"{url_hash}.png"
            path = os.path.join(SCREENSHOT_DIR, fname)

            print(f"[Screenshot] Taking: {url}")

            source = "playwright-cli"
            if cli_installed:
                success, status_code, error = await _via_cli(url, path)
                if not success:
                    # CLI failed - retry once via the Python API, which can
                    # handle cert errors and gives us finer timeout control.
                    print(f"[Screenshot] CLI failed for {url}, retrying via Python Playwright: {error[:200]}")
                    success, status_code, error = await _via_python(url, path)
                    source = "playwright-py-fallback"
            else:
                success, status_code, error = await _via_python(url, path)
                source = "playwright-py"

            if success:
                with open(path, "rb") as f:
                    phash = hashlib.md5(f.read()).hexdigest()[:12]

                return RawResult(
                    type="finding",
                    value=url,
                    source=source,
                    parent_value=url,
                    meta={
                        "screenshot_path": path,
                        "visual_hash": phash,
                        "status_code": status_code,
                    },
                )
            else:
                return None

  
    tasks = [asyncio.create_task(process_one(url)) for url in urls]

   
    for task in asyncio.as_completed(tasks):
        result = await task
        if result:
            yield result
