from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime
from typing import Dict, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlmodel import Session, select

from app.auth import auth_enabled, require_api_key
from app.database import get_session, init_db, engine
from app.models import Asset, Scan, ScanConfig, ScanStatus, Wordlist
from app.orchestrator import ReconOrchestrator
from app.wordlists import save_uploaded_wordlist

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("recon.api")

app = FastAPI(title="Recon Chain API")

# Allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("recon-chain API started (auth %s)", "ENABLED" if auth_enabled() else "DISABLED - local dev only")


_scan_tasks: Dict[int, asyncio.Task] = {}


async def _execute_scan(scan_id: int, config: ScanConfig):
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        orchestrator = ReconOrchestrator(session, scan, config)
        await orchestrator.run()


@app.get("/health")
def health():
    return {"status": "ok", "auth_enabled": auth_enabled()}


@app.post("/scans", response_model=Scan, dependencies=[Depends(require_api_key)])
async def create_scan(
    config: ScanConfig,
    session: Session = Depends(get_session),
    name: Optional[str] = None,
):
    scan = Scan(
        name=name or config.target,
        target=config.target,
        scope_mode=config.scope_mode,
        config_json=config.model_dump(mode="json"),
        status=ScanStatus.queued,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    task = asyncio.create_task(_execute_scan(scan.id, config))
    _scan_tasks[scan.id] = task
    task.add_done_callback(lambda t, sid=scan.id: _scan_tasks.pop(sid, None))

    return scan

@app.post("/scans/{scan_id}/stop", dependencies=[Depends(require_api_key)])
async def stop_scan(scan_id: int, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    if scan.status == ScanStatus.completed or scan.status == ScanStatus.failed:
        raise HTTPException(400, "scan is already finished")

    from app.orchestrator import _running_scans
    orchestrator = _running_scans.get(scan_id)
    if orchestrator:
        orchestrator.stop()

    task = _scan_tasks.get(scan_id)
    if task and not task.done():
    
        task.cancel()

    scan.status = ScanStatus.failed
    scan.error = "Stopped by user"
    scan.finished_at = datetime.utcnow()
    session.add(scan)
    session.commit()

    return {"status": "stopped"}

@app.delete("/scans", dependencies=[Depends(require_api_key)])
def clear_scans(session: Session = Depends(get_session)):

    scans = session.exec(select(Scan)).all()
    deleted = 0
    skipped_running = 0
    for scan in scans:
        if scan.status in (ScanStatus.running, ScanStatus.queued):
            skipped_running += 1
            continue
        for asset in session.exec(select(Asset).where(Asset.scan_id == scan.id)).all():
            session.delete(asset)
        session.delete(scan)
        deleted += 1
    session.commit()
    return {"deleted": deleted, "skipped_running": skipped_running}

@app.delete("/scans/{scan_id}", dependencies=[Depends(require_api_key)])
def delete_scan(scan_id: int, session: Session = Depends(get_session)):
    """Delete a single scan (and its assets). Refuses to delete a scan
    that's still running/queued - stop it first."""
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    if scan.status in (ScanStatus.running, ScanStatus.queued):
        raise HTTPException(400, "stop the scan before deleting it")
    for asset in session.exec(select(Asset).where(Asset.scan_id == scan_id)).all():
        session.delete(asset)
    session.delete(scan)
    session.commit()
    return {"deleted": True}

@app.get("/scans", response_model=list[Scan], dependencies=[Depends(require_api_key)])
def list_scans(session: Session = Depends(get_session)):
    return session.exec(select(Scan).order_by(Scan.created_at.desc())).all()


@app.get("/scans/{scan_id}", response_model=Scan, dependencies=[Depends(require_api_key)])
def get_scan(scan_id: int, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    return scan


@app.get("/scans/{scan_id}/assets", response_model=list[Asset], dependencies=[Depends(require_api_key)])
def get_assets(
    scan_id: int,
    session: Session = Depends(get_session),
    type: Optional[str] = None,
    stage: Optional[str] = None,
    source: Optional[str] = None,
    status_code: Optional[int] = None,
    search: Optional[str] = Query(None, description="substring match on value"),
    tech: Optional[str] = Query(None, description="filter http_service rows containing this tech"),
    min_severity: Optional[str] = Query(None, description="for js_file/finding rows: info|medium|high"),
    is_new: Optional[bool] = None,
    since_id: Optional[int] = Query(None, description="only return assets with id > since_id, for incremental polling"),
):
    query = select(Asset).where(Asset.scan_id == scan_id)
    if type:
        query = query.where(Asset.type == type)
    if stage:
        query = query.where(Asset.stage == stage)
    if source:
        query = query.where(Asset.source == source)
    if is_new is not None:
        query = query.where(Asset.is_new == is_new)
    if since_id is not None:
        query = query.where(Asset.id > since_id)
    if search:
        query = query.where(Asset.value.contains(search))

    assets = session.exec(query.order_by(Asset.id)).all()

    if status_code is not None:
        assets = [a for a in assets if a.meta.get("status_code") == status_code]
    if tech:
        assets = [a for a in assets if tech.lower() in [t.lower() for t in a.meta.get("tech", [])]]
    if min_severity:
        order = {"info": 0, "medium": 1, "high": 2}
        threshold = order.get(min_severity, 0)
        assets = [a for a in assets if order.get(a.meta.get("severity", "info"), 0) >= threshold]

    return assets


@app.get("/scans/{scan_id}/summary", dependencies=[Depends(require_api_key)])
def get_summary(scan_id: int, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    assets = session.exec(select(Asset).where(Asset.scan_id == scan_id)).all()
    by_type: dict[str, int] = {}
    for a in assets:
        by_type[a.type] = by_type.get(a.type, 0) + 1
    return {
        "scan_id": scan_id,
        "status": scan.status if scan else None,
        "total_assets": len(assets),
        "by_type": by_type,
        "max_asset_id": max((a.id for a in assets), default=0),
    }


@app.get("/assets/{asset_id}/screenshot", dependencies=[Depends(require_api_key)])
def get_screenshot(asset_id: int, session: Session = Depends(get_session)):
    asset = session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "asset not found")
    screenshot_path = asset.meta.get("screenshot_path")
    if not screenshot_path:
        raise HTTPException(404, "no screenshot found for this asset")
    return FileResponse(screenshot_path, media_type="image/png")


@app.post("/wordlists", response_model=Wordlist, dependencies=[Depends(require_api_key)])
async def upload_wordlist(
    file: UploadFile = File(...),
    session: Session = Depends(get_session),
):
    content = await file.read()
    if not content:
        raise HTTPException(400, "uploaded file is empty")
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(400, "wordlist too large (10MB limit)")
    record = save_uploaded_wordlist(session, file.filename or "wordlist.txt", content)
    logger.info("wordlist uploaded: %s (%d lines)", record.wordlist_id, record.line_count)
    return record


@app.get("/wordlists", response_model=list[Wordlist], dependencies=[Depends(require_api_key)])
def list_wordlists(session: Session = Depends(get_session)):
    return session.exec(select(Wordlist).order_by(Wordlist.uploaded_at.desc())).all()