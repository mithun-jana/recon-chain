"""
Subdomain enumeration + DNS resolution (merged).
"""
from __future__ import annotations

import json
from typing import AsyncIterator

import httpx

from app.models import ScanConfig
from app.tools.base import RawResult, run_cmd_streaming, which
from app.tools.dns_resolve import run as dns_resolve_run  # reuse the original dns_resolve logic


async def _via_crtsh(domain: str) -> AsyncIterator[RawResult]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            rows = json.loads(resp.text)
        except Exception:
            return

    seen = set()
    for row in rows:
        for name in str(row.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.")
            if not name or name in seen or " " in name:
                continue
            seen.add(name)
            yield RawResult(
                type="subdomain", value=name, source="crt.sh",
                meta={"cert_issuer": row.get("issuer_name")},
            )


async def _via_subfinder(domain: str) -> AsyncIterator[RawResult]:
    async for line in run_cmd_streaming(["subfinder", "-d", domain, "-silent", "-json"], timeout=180):
        try:
            host = json.loads(line).get("host")
        except json.JSONDecodeError:
            host = line.strip()
        if host:
            yield RawResult(type="subdomain", value=host, source="subfinder")


async def _via_amass(domain: str) -> AsyncIterator[RawResult]:
    cmd = ["amass", "enum", "-passive", "-d", domain, "-silent"]
    async for line in run_cmd_streaming(cmd, timeout=300):
        host = line.strip()
        if host:
            yield RawResult(type="subdomain", value=host, source="amass")


async def run(config: ScanConfig) -> AsyncIterator[RawResult]:

    first_target = config.target.split(",")[0].strip()
    domain = first_target.split("://")[-1].split("/")[0].split(":")[0].strip()

    # Phase 1: collect subdomains
    subdomains = []
    seen = set()

    async for r in _via_crtsh(domain):
        if r.value not in seen:
            seen.add(r.value)
            subdomains.append(r.value)
            yield r

    if which("subfinder"):
        try:
            async for r in _via_subfinder(domain):
                if r.value not in seen:
                    seen.add(r.value)
                    subdomains.append(r.value)
                    yield r
        except Exception:
            pass

    if which("amass"):
        try:
            async for r in _via_amass(domain):
                if r.value not in seen:
                    seen.add(r.value)
                    subdomains.append(r.value)
                    yield r
        except Exception:
            pass

    if domain not in seen:
        subdomains.append(domain)
        yield RawResult(type="subdomain", value=domain, source="target")

    async for ip_result in dns_resolve_run(config, subdomains):
        yield ip_result