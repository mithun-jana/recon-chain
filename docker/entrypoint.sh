#!/usr/bin/env bash

set -euo pipefail

DATA_DIR="/app/data"
mkdir -p "$DATA_DIR/screenshots" "$DATA_DIR/wordlists_uploads"
if [ ! -L /app/backend/app/screenshots ]; then
  rm -rf /app/backend/app/screenshots
  ln -s "$DATA_DIR/screenshots" /app/backend/app/screenshots
fi
mkdir -p /app/backend/wordlists
if [ ! -L /app/backend/wordlists/uploads ]; then
  rm -rf /app/backend/wordlists/uploads
  ln -s "$DATA_DIR/wordlists_uploads" /app/backend/wordlists/uploads
fi

if [ -z "${RECON_API_KEY:-}" ]; then
  echo "[entrypoint] WARNING: RECON_API_KEY is not set - the API is running with auth DISABLED."
  echo "[entrypoint]          Fine for local/trusted use; set RECON_API_KEY before exposing this beyond localhost."
fi

echo "[entrypoint] starting frontend on :${RECON_FRONTEND_PORT:-8080}"
python3 -m http.server "${RECON_FRONTEND_PORT:-8080}" --directory /app/frontend &
FRONTEND_PID=$!

echo "[entrypoint] starting backend on :${RECON_BACKEND_PORT:-8000}"
(cd /app/backend && exec uvicorn app.main:app --host 0.0.0.0 --port "${RECON_BACKEND_PORT:-8000}") &
BACKEND_PID=$!

shutdown() {
  echo "[entrypoint] shutting down..."
  kill -TERM "$FRONTEND_PID" "$BACKEND_PID" 2>/dev/null || true
  wait "$FRONTEND_PID" "$BACKEND_PID" 2>/dev/null || true
}
trap shutdown TERM INT

set +e
wait -n "$FRONTEND_PID" "$BACKEND_PID"
exit_code=$?
set -e

shutdown
exit "$exit_code"
