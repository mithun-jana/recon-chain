# Running recon-chain in Docker

One image, one container, running both the backend API and the frontend
UI. Works the same way on Docker Desktop for Windows, Docker Desktop for
Mac, and native Docker on Linux.

> **A note on "Windows Docker":** Docker Desktop on Windows runs Linux
> containers by default (via WSL2), and that's what almost everyone means
> by "running Docker on Windows" - this image is a normal Linux image and
> works there exactly like it does on Linux or Mac. Native *Windows
> containers* (a separate Docker Desktop mode using Windows Server Core
> base images) are a different, much less common setup that these
> Linux-only recon tools (nmap, subfinder, etc.) can't run under. If
> `docker build` fails with something like "no matching manifest for
> windows/amd64", your Docker Desktop is switched to Windows containers
> mode - right-click the Docker icon in the system tray and switch to
> "Linux containers", then try again.

## Quick start

```bash
# from the project root (where Dockerfile lives)
docker compose up --build
```

Then open **http://localhost:8080** in your browser. The API itself is at
http://localhost:8000 (http://localhost:8000/docs for the interactive API
docs).

Without Compose:

```bash
docker build -t recon-chain .
docker run -d --name recon-chain \
  -p 8000:8000 -p 8080:8080 \
  -v recon_data:/app/data \
  --cap-add NET_RAW \
  recon-chain
```

## Ports

| Port | What |
|------|------|
| 8080 | Frontend (open this in your browser) |
| 8000 | Backend API (the frontend talks to this automatically) |

Change them with `RECON_FRONTEND_PORT` / `RECON_BACKEND_PORT` env vars if
you need to (remember to update the `-p` mappings to match).

## Persistent data

Everything the app writes - the scan database, screenshots, and uploaded
wordlists - lives under `/app/data` inside the container. Mount a volume
there (as both `docker-compose.yml` and the `docker run` example above
do) and it survives `docker rm` / image upgrades. Skip the volume and
you'll get a clean slate every time the container is recreated - fine for
a quick throwaway test.

## Authentication

The API runs with **auth disabled** by default (fine for local,
single-user use on your own machine). If you expose this beyond
localhost - a shared server, a VM reachable from your network, etc. - set
`RECON_API_KEY` to a real secret first:

```bash
docker run -e RECON_API_KEY=$(openssl rand -hex 32) ... recon-chain
```

or in `docker-compose.yml` / a `.env` file next to it:

```
RECON_API_KEY=your-long-random-secret
```

Without this, anyone who can reach the container's port 8000 can launch
scans against arbitrary targets through your IP.

## What's inside

Besides the app itself, the image builds/installs the recon CLI tools the
backend prefers when present (each one is optional - the app
transparently falls back to a pure-Python implementation if a tool is
missing, so nothing here is a hard requirement):

- **subfinder, httpx, naabu, katana, dnsx** (ProjectDiscovery, built from source via Go)
- **ffuf, gau** (Go)
- **feroxbuster** (prebuilt binary)
- **nmap** (apt)
- **Playwright + headless Chromium** (for the screenshot stage)

## Networking capabilities (nmap / naabu SYN scans)

`nmap`'s and `naabu`'s SYN-scan modes need `CAP_NET_RAW`. Docker grants
this by default on most setups without any extra flags, but
`docker-compose.yml` and the `docker run` example above request it
explicitly (`cap_add: [NET_RAW]`) so it also works on hosts/CI runners
that have tightened Docker's default capability set. Without it, those
two stages just fall back to their connect-scan / Python equivalents -
scans still work, just slightly slower for large port ranges.

## Multi-architecture builds (optional, advanced)

Building with a plain `docker build` (as above) targets whatever
architecture your machine actually is - that's all you need for normal
use, including on Apple Silicon or ARM servers. If you specifically want
to build *one* image that supports multiple architectures at once (e.g.
to push to a registry for others to pull on either amd64 or arm64):

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t you/recon-chain:latest --push .
```

This cross-compiles the pure-Go tools cleanly. `naabu` and `katana` use
CGO, which complicates true cross-compilation - if you hit build errors
for those two specifically in a `buildx --platform` cross build, it's
safe to comment out their `RUN` lines in the Dockerfile; the app falls
back to its Python equivalents automatically.

## Rebuilding after you change app code

```bash
docker compose up --build
```

or

```bash
docker build -t recon-chain . && docker compose up -d
```

## Troubleshooting

- **"Cannot connect to the Docker daemon"** - Docker Desktop isn't
  running. Start it and wait for it to say "Docker Desktop is running".
- **Build fails on the `playwright install --with-deps chromium` step**
  with an apt/network error - that step needs internet access during the
  build; check your network/proxy settings and retry.
- **Frontend loads but nothing works / "Could not reach the API"** -
  make sure port 8000 is published (`-p 8000:8000`) and reachable; check
  `docker logs recon-chain` for backend errors.
- **Scans always use the Python fallback, never the fast Go tools** -
  check `docker logs recon-chain` for `go install` failures during build
  (some corporate networks block the Go module proxy). The app still
  works either way, just slower for subdomain enum / port scanning.
