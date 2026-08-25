"""
Orchestrator with parallel scan support and stop controls.
"""
from __future__ import annotations

import asyncio
import logging
import time
import socket
from datetime import datetime
from typing import AsyncIterator, Dict, Set

from sqlmodel import Session, select

from app.models import (
    Asset, AssetType, Scan, ScanConfig, ScanStatus, Stage,
    STAGE_DEPENDENCIES, WILDCARD_ONLY_STAGES, CIDR_ONLY_STAGES, ScopeMode,
)
from app.scope import is_in_scope
from app.tools import (
    subdomain_enum, http_probe, port_scan, nmap_enrich,
    screenshot, url_collect, katana_crawl, dir_fuzz,
    js_analysis, device_scan,
)
from app.tools.base import RawResult

logger = logging.getLogger("recon.orchestrator")

COMMIT_BATCH_SIZE = 15
COMMIT_BATCH_INTERVAL = 0.4


CHAIN_ORDER = [
    Stage.subdomain_enum,
    Stage.url_collect,
    Stage.katana_crawl,
    Stage.dir_fuzz,
    Stage.device_scan,
    Stage.port_scan,
    Stage.http_probe,
    Stage.screenshot,
]


_running_scans: Dict[int, 'ReconOrchestrator'] = {}
_scan_stop_events: Dict[int, asyncio.Event] = {}


def get_scan_control(scan_id: int):
    """Get stop controls for a scan."""
    return {
        "stop_event": _scan_stop_events.get(scan_id),
    }


def _resolve_stage_order(enabled: list[Stage]) -> list[Stage]:

    if len(enabled) == 1:
        stage = enabled[0]
        deps = STAGE_DEPENDENCIES.get(stage, [])
        return [stage] + [d for d in deps if d in enabled]

    ordered = [s for s in CHAIN_ORDER if s in enabled]
    needed = set(ordered)
    changed = True
    while changed:
        changed = False
        for s in list(needed):
            for dep in STAGE_DEPENDENCIES.get(s, []):
                if dep not in needed:
                    needed.add(dep)
                    changed = True

    final_order = []
    visited = set()
    def visit(s: Stage):
        if s in visited:
            return
        visited.add(s)
        for dep in STAGE_DEPENDENCIES.get(s, []):
            if dep in needed:
                visit(dep)
        final_order.append(s)

    for s in needed:
        visit(s)

    return final_order


class ReconOrchestrator:
    def __init__(self, session: Session, scan: Scan, config: ScanConfig):
        self.session = session
        self.scan = scan
        self.config = config
        self._cache: dict[AssetType, list[Asset]] = {}
        self._targets = [t.strip() for t in config.target.split(",") if t.strip()]
        self._is_stopped = False
        self._current_stage = None
        self._stop_event = asyncio.Event()
        self._running_tasks: Set[asyncio.Task] = set()
        
        # Register this scan in the global registry
        _running_scans[scan.id] = self
        _scan_stop_events[scan.id] = self._stop_event

    def stop(self):
        """Stop the scan immediately."""
        self._is_stopped = True
        self._stop_event.set()
        # Cancel all running tasks
        for task in list(self._running_tasks):
            if not task.done():
                task.cancel()
        logger.info("scan %s: stop requested", self.scan.id)

    async def _check_control(self):
        """Check stop state."""
        if self._is_stopped:
            raise asyncio.CancelledError("Scan stopped by user")
        await asyncio.sleep(0)

    def _track_task(self, task: asyncio.Task):
        """Track a task for cancellation on stop."""
        self._running_tasks.add(task)
        task.add_done_callback(lambda t: self._running_tasks.discard(t))

    async def _store_stream(self, stage: Stage, results: AsyncIterator[RawResult], default_type: AssetType):
        batch: list[Asset] = []
        last_commit = time.monotonic()
        seen_keys = set()

        async def flush():
            if not batch:
                return
            self.scan.asset_count += len(batch)
            self.session.add(self.scan)
            self.session.commit()
            for a in batch:
                self._cache.setdefault(a.type, []).append(a)
            batch.clear()

        try:
            async for r in results:
                await self._check_control()
                
                parent = r.parent_value if stage == Stage.port_scan else None
                if not is_in_scope(r.value, self.config, parent):
                    continue

                asset_type = AssetType(r.type) if r.type else default_type

                key = f"{asset_type}:{r.value}"
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                asset = Asset(
                    scan_id=self.scan.id, stage=stage, source=r.source, type=asset_type,
                    value=r.value, parent_value=r.parent_value, meta=r.meta, in_scope=True,
                )
                self.session.add(asset)
                batch.append(asset)

                now = time.monotonic()
                if len(batch) >= COMMIT_BATCH_SIZE or (now - last_commit) >= COMMIT_BATCH_INTERVAL:
                    await flush()
                    last_commit = now

            await flush()
        except asyncio.CancelledError:
            await flush()
            raise

    async def _merge_meta(self, results: AsyncIterator[RawResult]):
        count = 0
        try:
            async for r in results:
                await self._check_control()
                existing = self.session.exec(
                    select(Asset).where(Asset.scan_id == self.scan.id, Asset.value == r.value)
                ).first()
                if existing:
                    existing.meta = {**existing.meta, **r.meta}
                    self.session.add(existing)
                    count += 1
                    if count % 5 == 0:
                        self.session.commit()
                    for i, cached in enumerate(self._cache.get(existing.type, [])):
                        if cached.id == existing.id:
                            self._cache[existing.type][i] = existing
                            break
            self.session.commit()
        except asyncio.CancelledError:
            self.session.commit()
            raise

    def _cached(self, t: AssetType) -> list[str]:
        return [a.value for a in self._cache.get(t, [])]

    async def _run_stage(self, stage: Stage):
        await self._check_control()
        self._current_stage = stage
        cfg = self.config
        logger.info("scan %s: running stage %s", self.scan.id, stage.value)

        if stage == Stage.subdomain_enum:
            if cfg.scope_mode != ScopeMode.wildcard:
                return
            for target in self._targets:
                await self._check_control()
                sub_cfg = cfg.model_copy(update={"target": target})
                await self._store_stream(stage, subdomain_enum.run(sub_cfg), AssetType.subdomain)

        elif stage == Stage.http_probe:
            cached_subs = self._cached(AssetType.subdomain)
  
            targets_are_full_urls = bool(self._targets) and all("://" in t for t in self._targets)
            hosts = self._targets if targets_are_full_urls else (cached_subs or self._targets)
            await self._store_stream(stage, http_probe.run(cfg, hosts), AssetType.http_service)

        elif stage == Stage.port_scan:
            ips = self._cached(AssetType.ip) or [d.value for d in self._cache.get(AssetType.device, [])]
            if not ips:
                resolved_ips = []
                loop = asyncio.get_event_loop()
                for target in self._targets:
                    if cfg.scope_mode == ScopeMode.cidr:
       
                        resolved_ips.extend(device_scan.expand_cidr(target))
                        continue
         
                    clean_target = target.split("://")[-1].split("/")[0].split(":")[0]
                    try:
        
                        addrinfo = await loop.run_in_executor(
                            None, socket.getaddrinfo, clean_target, None, socket.AF_INET
                        )
                        for addr in addrinfo:
                            ip = addr[4][0]
                            if ip not in resolved_ips:
                                resolved_ips.append(ip)
                    except Exception:
                        continue
                ips = list(dict.fromkeys(resolved_ips))

            if not ips:
                logger.warning("scan %s: no IPs to scan — skipping port_scan", self.scan.id)
                return

            await self._store_stream(stage, port_scan.run(cfg, ips), AssetType.open_port)
            open_ports = [
                (a.meta.get("ip"), a.meta.get("port"))
                for a in self._cache.get(AssetType.open_port, [])
                if a.meta.get("ip") and a.meta.get("port")
            ]
            if open_ports:
                await self._merge_meta(nmap_enrich.run(cfg, open_ports))

        elif stage == Stage.device_scan:
         
            if cfg.scope_mode != ScopeMode.cidr:
                logger.info("scan %s: device_scan skipped (scope_mode is not cidr)", self.scan.id)
                return
            await self._store_stream(stage, device_scan.run(cfg, self._targets), AssetType.device)

        elif stage == Stage.screenshot:
            urls = self._cached(AssetType.http_service)
            js_urls = self._cached(AssetType.js_file)
            if js_urls:
                urls.extend(js_urls)
            if not urls:
                urls = self._targets
            if urls:
                await self._store_stream(stage, screenshot.run(cfg, urls), AssetType.finding)

        elif stage == Stage.url_collect:
            hosts = self._cached(AssetType.subdomain)
            if not hosts:
                hosts = self._targets
            await self._store_stream(stage, url_collect.run(cfg, hosts), AssetType.url)
            if Stage.url_collect in self.config.enabled_stages:
                await self._run_stage(Stage.js_analysis)

        elif stage == Stage.katana_crawl:
            base_urls = self._cached(AssetType.http_service) or self._targets
            await self._store_stream(stage, katana_crawl.run(cfg, base_urls), AssetType.url)
            await self._run_stage(Stage.js_analysis)

        elif stage == Stage.dir_fuzz:
            base_urls = self._cached(AssetType.http_service) or self._targets
            await self._store_stream(stage, dir_fuzz.run(cfg, base_urls), AssetType.directory)

        elif stage == Stage.js_analysis:
            js_urls = [u for u in self._cached(AssetType.url) if u.endswith(".js")]
            await self._store_stream(stage, js_analysis.run(cfg, js_urls), AssetType.js_file)

    async def run(self):
        self.scan.status = ScanStatus.running
        self.session.add(self.scan)
        self.session.commit()

        try:
            order = _resolve_stage_order(self.config.enabled_stages)
            logger.info("scan %s: stage order %s", self.scan.id, [s.value for s in order])
            
            for stage in order:
                await self._check_control()
                if stage in WILDCARD_ONLY_STAGES and stage not in self.config.enabled_stages:
                    continue
                if stage in CIDR_ONLY_STAGES and stage not in self.config.enabled_stages:
                    continue
                await self._run_stage(stage)
                
            if not self._is_stopped:
                self.scan.status = ScanStatus.completed
            
        except asyncio.CancelledError:
            self.scan.status = ScanStatus.failed
            self.scan.error = "Stopped by user"
            logger.info("scan %s: stopped by user", self.scan.id)
        except Exception as e:
            self.scan.status = ScanStatus.failed
            self.scan.error = str(e)
            logger.exception("scan %s failed", self.scan.id)
        finally:
            self.scan.finished_at = datetime.utcnow()
            self.session.add(self.scan)
            self.session.commit()
            # Clean up global registry
            _running_scans.pop(self.scan.id, None)
            _scan_stop_events.pop(self.scan.id, None)
            logger.info("scan %s finished: %s", self.scan.id, self.scan.status)