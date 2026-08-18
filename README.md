# Nuclei Dashboard

Internal multi-tenant control plane for authorized client network discovery and Nuclei vulnerability scans.

Staff log in (admins, users, viewers). **Tenants are clients you manage**, not self-service accounts. LAN scans run on approved site agents. WAN scans run from the central scanner.

## Architecture

- **Caddy** terminates HTTP/HTTPS and routes `/api` to FastAPI and everything else to the React UI
- **API** (FastAPI + PostgreSQL) stores tenants, agents, jobs, devices, findings, and alerts
- **WAN scanner** claims WAN jobs and runs naabu → httpx → nuclei
- **Site agent** (same image) enrolls with a UUID, waits for approval, then polls for LAN jobs

Agents only make **outbound HTTPS**. After approval they authenticate with an Ed25519 key bound to that UUID. A stolen UUID without the private key is rejected and raises an impersonation alert.

## Quick start

```bash
cp .env.example .env
# set SECRET_KEY, SCANNER_TOKEN, ADMIN_PASSWORD, PUBLIC_URL
docker compose up -d --build
```

Copy the **whole repo** to the server (`backend/`, `frontend/`, `scan_runtime/`, `Caddyfile`, `certs/`). The agent/scanner image is built locally — it is not on Docker Hub. On first start use `--build` so Compose does not try to pull `nuclei-dashboard-agent`.

Open `https://localhost:8118` and sign in with `ADMIN_USERNAME` / `ADMIN_PASSWORD`. The first visit will warn about Caddy's internal certificate — continue past it. Set `SITE_ADDRESS` and `PUBLIC_URL` to `https://your-hostname:8118` if the dashboard is reached by a name other than localhost.

## Typical workflow

1. Create a tenant (client)
2. Add WAN and/or LAN CIDRs
3. Create a site agent, download its `docker-compose.yml`, and start it on the remote LAN
4. Approve the agent once it appears as `pending approval`
5. Create a scan (manual or interval) and run it
6. Review devices (new / known / stale), findings, and alerts

New devices and impersonation attempts create in-app alerts and email staff when SMTP is configured under Admin → Settings.

## Site agent

The UI generates a compose file per agent. Build/push the shared image first:

```bash
docker compose build scanner
# tags nuclei-dashboard-agent:latest
```

Copy that image to the site (registry or `docker save` / `docker load`), then run the downloaded compose file. Linux sites should keep `network_mode: host` so LAN subnets are reachable.

The agent stores its private key on a Docker volume. Losing that volume after approval means the agent cannot be reused — create a new agent.

## Scan profiles

- **Discovery only** — naabu + httpx, inventory only
- **Discovery + Nuclei** — same, then nuclei JSONL findings

Set `SCAN_DRY_RUN=1` on the scanner (or agent) to emit sample results without touching the network.

## Roles

| Role   | Access |
|--------|--------|
| Admin  | System settings, users, everything a user can do |
| User   | Tenants, subnets, agents, scans, classification, acknowledge alerts |
| Viewer | Read-only inventory, findings, reports |

## Local UI development

```bash
# API + Postgres from compose, or run uvicorn locally
cd frontend && npm install && npm run dev
```

Vite proxies `/api` to `http://127.0.0.1:8000`.
