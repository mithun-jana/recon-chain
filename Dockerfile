# syntax=docker/dockerfile:1
#
# Single image containing BOTH the FastAPI backend and the static
# frontend, plus the recon CLI tools the backend prefers when available
# (subfinder, httpx, naabu, katana, dnsx, ffuf, gau, feroxbuster, nmap).
#
# Every one of those tools is OPTIONAL from the app's point of view - each
# stage in app/tools/*.py checks `which("toolname")` and transparently
# falls back to a pure-Python implementation if the binary isn't found.
# That means this image degrades gracefully even if a particular tool
# fails to build on some exotic platform; nothing here is a hard
# requirement for the app to run.
#
# This builds NATIVELY for whatever architecture `docker build` runs on -
# amd64 on Windows/Linux/Intel Mac Docker Desktop, arm64 on Apple Silicon
# Mac or an ARM Linux host/server. Docker automatically pulls the matching
# base image variant for each, and Go/Rust compile for the host's own
# architecture by default, so no cross-compilation flags are needed for
# ordinary `docker build` usage. See DOCKER.md for multi-arch `buildx`
# notes if you specifically want to build one image for multiple
# architectures at once (e.g. to push to a registry for both).
#
# NOTE on "Windows Docker": Docker Desktop on Windows runs Linux
# containers (via WSL2/Hyper-V) by default and almost everyone uses it
# that way - this image targets that mode, which is what "docker on
# Windows" means in the vast majority of real-world setups. True native
# Windows containers (Windows Server Core base images) are a separate,
# rarely-used Docker mode that these Linux-only recon binaries can't run
# under; if you deliberately switched Docker Desktop to "Windows
# containers" mode, switch it back to "Linux containers" (the default) to
# use this image.

########################################
# Stage 1: build the Go-based recon tools
########################################
FROM golang:1.23-bookworm AS gotools

# naabu and katana link against libpcap via CGO; everything else here is
# pure Go and doesn't strictly need these, but installing once up front is
# simpler than special-casing each RUN line.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpcap-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV GOBIN=/out
# Let `go install` automatically download whatever toolchain version a
# module declares as its minimum (e.g. subfinder now requires Go 1.25+),
# instead of hard-failing when it's newer than this base image's Go. This
# is the officially supported mechanism for exactly this situation and
# means future minimum-Go-version bumps in these tools won't break the
# build again - Go just fetches the right toolchain on demand.
ENV GOTOOLCHAIN=auto
RUN mkdir -p /out

# Pure-Go tools - fast, no CGO required.
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/ffuf/ffuf/v2@latest
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest

# CGO-based tools. If either of these fails to build on some future Go/
# toolchain combination, comment the line out - the app falls back to its
# Python port-scan/crawl implementations automatically (see app/tools/
# port_scan.py and katana_crawl.py).
RUN CGO_ENABLED=1 go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN CGO_ENABLED=1 go install -v github.com/projectdiscovery/katana/cmd/katana@latest


########################################
# Stage 2: fetch feroxbuster (Rust - prebuilt binary, no cargo build here)
########################################
FROM debian:bookworm-slim AS feroxbuster

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /out && set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) fname="x86_64-linux-feroxbuster.zip" ;; \
      arm64) fname="aarch64-linux-feroxbuster.zip" ;; \
      *) echo "[feroxbuster] unsupported arch '$arch' - skipping, dir_fuzz will use ffuf/Python fallback instead" ; exit 0 ;; \
    esac; \
    curl -fsSL -o /tmp/ferox.zip \
      "https://github.com/epi052/feroxbuster/releases/latest/download/${fname}"; \
    unzip -o /tmp/ferox.zip -d /out; \
    chmod +x /out/feroxbuster


########################################
# Stage 3: final runtime image
########################################
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="recon-chain" \
      org.opencontainers.image.description="Self-hosted multi-stage recon/asset-discovery tool"

# - nmap: service/version enrichment stage
# - libpcap0.8: naabu's runtime dependency (SYN scan mode)
# - curl: container healthcheck + tini download below
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl ca-certificates libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# tini (PID 1 init) - fetched as a static binary rather than via apt, since
# the package name/availability varies across base-image distros and this
# way is verified to work regardless. Used for correct signal handling /
# zombie reaping across the two processes entrypoint.sh supervises.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) tfile="tini-static-amd64" ;; \
      arm64) tfile="tini-static-arm64" ;; \
      *) echo "unsupported arch '$arch' for tini" && exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/bin/tini \
      "https://github.com/krallin/tini/releases/download/v0.19.0/${tfile}"; \
    chmod +x /usr/bin/tini

# Recon CLI tools compiled/fetched in the stages above. Copying only the
# built binaries (not the Go toolchain or build deps) keeps this final
# image far smaller than building everything in one stage would.
COPY --from=gotools /out/ /usr/local/bin/
COPY --from=feroxbuster /out/ /usr/local/bin/

WORKDIR /app

# --- Python deps (cached separately from app code so code-only changes
#     don't bust this layer and force a full reinstall) ---
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt \
    && pip install --no-cache-dir playwright \
    && playwright install --with-deps chromium

# --- App code ---
COPY backend/app /app/backend/app
COPY backend/wordlists /app/backend/wordlists
COPY frontend /app/frontend
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Everything the app writes at runtime (SQLite DB, screenshots, uploaded
# wordlists) gets symlinked into this one directory by entrypoint.sh, so
# mounting a single volume here (`-v recon_data:/app/data`) is enough to
# persist all of it across `docker rm`/upgrades.
RUN mkdir -p /app/data

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend \
    RECON_API_KEY="" \
    RECON_DATABASE_URL="sqlite:////app/data/recon.db" \
    RECON_FRONTEND_PORT=8080 \
    RECON_BACKEND_PORT=8000

EXPOSE 8000 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD curl -fsS "http://localhost:${RECON_BACKEND_PORT}/health" || exit 1

# tini as PID 1 correctly forwards SIGTERM/SIGINT from `docker stop` to
# entrypoint.sh's children and reaps any zombie processes the scan tools
# leave behind - without it, `docker stop` on this multi-process image
# would just hang until the timeout and get SIGKILLed instead of shutting
# down cleanly.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/entrypoint.sh"]
