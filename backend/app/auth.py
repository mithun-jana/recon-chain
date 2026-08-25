"""
Authentication.

Deliberately minimal: this is a self-hosted tool, not a multi-tenant SaaS,
so a single shared bearer token (set via the RECON_API_KEY env var) is the
right amount of auth for v1 - not a full user/session system.

Behavior:
- RECON_API_KEY unset -> auth is OFF. Fine for local dev (localhost only).
  A warning is logged at startup so this is never silently insecure.
- RECON_API_KEY set -> every request (except health/docs) must send
  `Authorization: Bearer <token>` matching it, or gets 401.
"""
from __future__ import annotations

import logging
import os
import secrets

from fastapi import Header, HTTPException

logger = logging.getLogger("recon.auth")

_API_KEY = os.environ.get("RECON_API_KEY", "").strip() or None

if _API_KEY is None:
    logger.warning(
        "RECON_API_KEY is not set - authentication is DISABLED. This is fine "
        "for local development, but do not bind this server to a non-localhost "
        "address without setting RECON_API_KEY: this tool sends live traffic "
        "to whatever target a caller configures, so an unauthenticated, "
        "network-reachable instance can be used to scan arbitrary targets "
        "through your IP."
    )


def auth_enabled() -> bool:
    return _API_KEY is not None


async def require_api_key(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency. No-op when RECON_API_KEY isn't set (local dev
    mode); otherwise enforces a matching bearer token."""
    if _API_KEY is None:
        return

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing or malformed Authorization header (expected 'Bearer <token>')")

    token = authorization.removeprefix("Bearer ").strip()
    if not secrets.compare_digest(token, _API_KEY):
        raise HTTPException(401, "invalid API key")
