"""
Core data models.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


class ScopeMode(str, Enum):
    wildcard = "wildcard"
    single_host = "single_host"
    url_list = "url_list"
    cidr = "cidr"


class Stage(str, Enum):
    subdomain_enum = "subdomain_enum"
    http_probe = "http_probe"
    port_scan = "port_scan"
    screenshot = "screenshot"
    url_collect = "url_collect"
    katana_crawl = "katana_crawl"
    dir_fuzz = "dir_fuzz"
    js_analysis = "js_analysis"
    device_scan = "device_scan"


STAGE_DEPENDENCIES: dict[Stage, list[Stage]] = {
    Stage.subdomain_enum: [],
    Stage.http_probe: [Stage.subdomain_enum],
    Stage.port_scan: [Stage.subdomain_enum],
    Stage.screenshot: [Stage.http_probe],
    Stage.url_collect: [Stage.http_probe],
    Stage.katana_crawl: [Stage.http_probe],
    Stage.dir_fuzz: [Stage.http_probe],
    Stage.js_analysis: [Stage.url_collect],
    Stage.device_scan: [],
}

WILDCARD_ONLY_STAGES = {Stage.subdomain_enum}

# device_scan (host discovery + MAC/hostname lookup across a CIDR block)
# only makes sense - and is only allowed to run - when scope_mode is cidr.
CIDR_ONLY_STAGES = {Stage.device_scan}


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    paused = "paused"
    completed = "completed"
    failed = "failed"


class ScanConfig(SQLModel):
    target: str
    scope_mode: ScopeMode = ScopeMode.wildcard
    url_list: Optional[list[str]] = None
    include_patterns: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=list)
    enabled_stages: list[Stage] = Field(default_factory=lambda: list(Stage))
    ports: Optional[list[int]] = None
    rate_limit_per_sec: int = 20
    max_concurrency: int = 40
    wordlist_id: Optional[str] = None
    fuzz_extensions: list[str] = Field(default_factory=list)


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: Optional[str] = None  # <-- ADD THIS
    target: str
    scope_mode: ScopeMode
    config_json: dict = Field(sa_column=Column(JSON))
    status: ScanStatus = ScanStatus.queued
    created_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    asset_count: int = 0


class AssetType(str, Enum):
    subdomain = "subdomain"
    ip = "ip"
    http_service = "http_service"
    open_port = "open_port"
    url = "url"
    directory = "directory"
    js_file = "js_file"
    finding = "finding"
    url_status = "url_status"
    device = "device"


class Asset(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    stage: Stage
    source: str
    type: AssetType
    value: str
    parent_value: Optional[str] = None
    meta: dict = Field(default_factory=dict, sa_column=Column(JSON))
    in_scope: bool = True
    is_new: bool = True
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Wordlist(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    wordlist_id: str = Field(index=True, unique=True)
    original_filename: str
    line_count: int
    uploaded_at: datetime = Field(default_factory=datetime.utcnow)