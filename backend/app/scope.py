"""
Scope enforcement.
"""
from __future__ import annotations

import fnmatch
import functools
import ipaddress
import logging
import re
import socket
from urllib.parse import urlparse

from app.models import ScanConfig, ScopeMode

logger = logging.getLogger("recon.scope")


def _hostname_matches(pattern: str, hostname: str) -> bool:
    """Support glob patterns (*.example.com) and plain substrings/regex."""
    pattern = pattern.strip().lower()
    hostname = hostname.strip().lower()
    if not pattern:
        return False
    if "*" in pattern:
        return fnmatch.fnmatch(hostname, pattern)
    if hostname == pattern or hostname.endswith("." + pattern):
        return True
    try:
        if re.search(pattern, hostname):
            return True
    except re.error:
        pass
    return False


def _extract_hostname(value: str) -> str:
    """Asset values can be bare hosts, host:port, or full URLs."""
    v = value.strip()
    if "://" in v:
        v = urlparse(v).hostname or v
    else:
        v = v.split(":")[0]
    return v.lower()


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@functools.lru_cache(maxsize=512)
def _resolve_domain_to_ips_cached(domain: str) -> tuple[str, ...]:
  
    try:
        addrinfo = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = tuple(dict.fromkeys(addr[4][0] for addr in addrinfo))
        logger.debug("resolved %s -> %s", domain, ips)
        return ips
    except Exception as e:
        logger.debug("could not resolve %s: %s", domain, e)
        return ()


def _parse_targets(target: str) -> list[str]:
    """Scope now supports comma-separated multi-target strings."""
    if not target:
        return []
    return [t.strip() for t in target.split(",") if t.strip()]


def _in_cidr(ip_str: str, cidr_list: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for c in cidr_list:
        try:
            if ip in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _target_matches(host: str, is_ip: bool, target: str, mode: ScopeMode) -> bool:
    target_host = _extract_hostname(target)
    target_is_ip = _is_ip_address(target_host)

    if mode == ScopeMode.wildcard:
        if is_ip:
            return host in _resolve_domain_to_ips_cached(target_host)
        return host == target_host or host.endswith("." + target_host)

    if mode == ScopeMode.single_host:
        if is_ip:
            if target_is_ip:
                return host == target_host
            return host in _resolve_domain_to_ips_cached(target_host)
        return host == target_host

    if mode == ScopeMode.cidr:
        return _in_cidr(host, [target])

    return False


def is_in_scope(value: str, config: ScanConfig, parent_value: str | None = None) -> bool:

    host = _extract_hostname(value)
    is_ip = _is_ip_address(host)

    for pat in config.exclude_patterns:
        if _hostname_matches(pat, host):
            return False

    if config.include_patterns:
        return any(_hostname_matches(pat, host) for pat in config.include_patterns)

    if config.scope_mode == ScopeMode.url_list:
        allowed_hosts = {_extract_hostname(u) for u in (config.url_list or [])}
        return host in allowed_hosts

    for target in _parse_targets(config.target):
        if _target_matches(host, is_ip, target, config.scope_mode):
            return True

    return False