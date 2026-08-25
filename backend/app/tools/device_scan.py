"""
Device discovery for CIDR scans.

"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import AsyncIterator, Optional

from app.models import ScanConfig
from app.tools.base import ConcurrencyLimiter, RawResult


MAX_CIDR_HOSTS = 1024


_PROBE_PORTS = (80, 443, 22, 445, 139, 3389, 135, 21, 23, 8080)


def expand_cidr(target: str) -> list[str]:
    """Return every usable host IP in a CIDR block. Falls back to
    returning the target unchanged if it isn't valid CIDR notation (e.g.
    it's already a bare single IP)."""
    target = target.strip()
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return [target] if target else []

    if network.num_addresses <= 2:
       
        return [str(network.network_address)]

    hosts = [str(ip) for ip in network.hosts()]
    if len(hosts) > MAX_CIDR_HOSTS:
        hosts = hosts[:MAX_CIDR_HOSTS]
    return hosts


async def _icmp_ping(ip: str, timeout: float = 1.0) -> bool:
    
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", str(max(int(timeout), 1)), ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        returncode = await asyncio.wait_for(proc.wait(), timeout=timeout + 1)
        return returncode == 0
    except Exception:
        return False


async def _tcp_probe(ip: str, timeout: float = 1.0) -> bool:
    for port in _PROBE_PORTS:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            continue
    return False


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _read_arp_entry(ip: str) -> Optional[str]:
    
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
    except Exception:
        pass
    return None


async def run(config: ScanConfig, targets: list[str]) -> AsyncIterator[RawResult]:
    
    all_hosts: list[str] = []
    for t in targets:
        all_hosts.extend(expand_cidr(t))
    all_hosts = list(dict.fromkeys(h for h in all_hosts if h))  # de-dupe, keep order

    if not all_hosts:
        return

    limiter = ConcurrencyLimiter(config.max_concurrency)
    loop = asyncio.get_event_loop()

    async def probe(ip: str):
        async with limiter:
            ping_ok, tcp_ok = await asyncio.gather(_icmp_ping(ip), _tcp_probe(ip))
      
            await asyncio.sleep(0.05)
            mac = await loop.run_in_executor(None, _read_arp_entry, ip)

            alive = ping_ok or tcp_ok or mac is not None
            if not alive:
                return None

            hostname = await loop.run_in_executor(None, _reverse_dns, ip)
            return RawResult(
                type="device", value=ip, source="device-scan",
                meta={
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "alive": True,
                    "responded_to": "ping" if ping_ok else ("tcp" if tcp_ok else "arp-only"),
                },
            )

    tasks = [probe(ip) for ip in all_hosts]
    for coro in asyncio.as_completed(tasks):
        result = await coro
        if result:
            yield result
