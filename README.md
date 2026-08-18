# Nuclei Dashboard

Internal multi-tenant control plane for authorized client network discovery and Nuclei vulnerability scans.

Staff log in (admins, users, viewers). **Tenants are clients you manage**, not self-service accounts. LAN scans run on approved site agents. WAN scans run from the central scanner.

`MASTER_PLAN.md` is the canonical architecture source of truth. Contributor and upgrade notes (Alembic, TLS, Viewer limits) are in `docs/DEVELOPMENT.md`.

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

The **central** stack is this repo (`backend/`, `frontend/`, `scan_runtime/`, `Caddyfile`, `certs/`). On first start use `--build`. Site agents do **not** need a copy of the whole tree — they build `scan_runtime` from GitHub.

Open `https://localhost:8118` and sign in with `ADMIN_USERNAME` / `ADMIN_PASSWORD`. The first visit will warn about Caddy's internal certificate — continue past it. Set `SITE_ADDRESS` and `PUBLIC_URL` to `https://your-hostname:8118` if the dashboard is reached by a name other than localhost.

Agent TLS verification is **on** by default. For Caddy's internal certificate, either install a publicly trusted certificate, point the agent at Caddy's local CA (`TLS_CA_FILE`), or set `AGENT_TLS_VERIFY=0` for lab use only. See `docs/DEVELOPMENT.md`.

## Typical workflow

1. Create a tenant (client)
2. Add WAN and/or LAN CIDRs
3. Create a site agent, download its compose (or `.env` + `agent/docker-compose.yml`), and start it on the remote LAN with `--build`
4. Approve the agent once it appears as `pending approval`
5. Create a scan (manual or interval) and run it
6. Review devices (new / known / stale), findings, and alerts

New devices and impersonation attempts create in-app alerts and email staff when SMTP is configured under Admin → Settings.

## Site agent

The UI generates a compose file per agent. On the site host:

```bash
docker compose up -d --build
```

Docker clones [`scan_runtime`](https://github.com/JustinTDCT/nuclei-dashboard/tree/main/scan_runtime) from the public repo and builds `nuclei-dashboard-agent:latest`. No image copy or `docker save` is required. After we push agent changes, run the same `--build` again.

Alternatively, download only the `.env` from the dashboard and use the compose file in the repo:

```bash
curl -fsSL -o docker-compose.yml \
  https://raw.githubusercontent.com/JustinTDCT/nuclei-dashboard/main/agent/docker-compose.yml
docker compose --env-file agent.env up -d --build
```

Linux sites should keep `network_mode: host` so LAN subnets are reachable. The first build downloads naabu/httpx/nuclei and takes several minutes.

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
| Viewer | Read-only inventory, findings, agent status. Cannot download enrollment secrets or agent compose/env |

## Local UI development

```bash
# API + Postgres from compose, or run uvicorn locally
cd frontend && npm install && npm run dev
```

Vite proxies `/api` to `http://127.0.0.1:8000`.
