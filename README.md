# Nuclei Dashboard

Internal multi-tenant control plane for authorized client network discovery and Nuclei vulnerability scans.

Staff log in (admins, users, viewers). **Tenants are clients you manage**, not self-service accounts. LAN scans run on approved site agents. WAN scans run from the central scanner.

`MASTER_PLAN.md` is the canonical architecture source of truth. Contributor and upgrade notes (Alembic, TLS, Viewer limits) are in `docs/DEVELOPMENT.md`.

## Architecture

- **Caddy** terminates HTTP/HTTPS and routes `/api` to FastAPI and everything else to the React UI
- **API** (FastAPI + PostgreSQL) stores tenants, agents, jobs, devices, findings, alerts, and raw-artifact metadata
- **scan-artifacts volume** holds gzip JSONL scanner output on the API host (not in PostgreSQL)
- **WAN scanner** claims WAN jobs and runs naabu → httpx → nuclei, then uploads raw evidence to the API
- **Site agent** (same image) enrolls with a UUID, waits for approval, then polls for LAN jobs and uploads raw evidence over HTTPS

Agents only make **outbound HTTPS**. After approval they authenticate with an Ed25519 key bound to that UUID. A stolen UUID without the private key is rejected and raises an impersonation alert.

## Quick start

```bash
cp .env.example .env
# set SECRET_KEY, SCANNER_TOKEN, ADMIN_PASSWORD, PUBLIC_URL
docker compose up -d --build
```

The **central** stack is this repo (`backend/`, `frontend/`, `scan_runtime/`, `Caddyfile`, `certs/`). On first start use `--build`. Site agents do **not** need a copy of the whole tree — they build `scan_runtime` from GitHub.

Open `https://localhost:8118` and sign in with `ADMIN_USERNAME` / `ADMIN_PASSWORD`. Caddy serves HTTPS with `./certs/cert.pem` and `./certs/key.pem`. Set `SITE_ADDRESS` and `PUBLIC_URL` to `https://your-hostname:8118` if the dashboard is reached by a name other than localhost.

Agent TLS verification is **on** by default. Publicly trusted certificates need no extra agent files. For a private/internal CA, copy the CA PEM to `./agent-certs/ca.pem` on the agent host and set `TLS_CA_FILE=/certs/ca.pem` (container path; host `./agent-certs` is bind-mounted). Do not reuse Caddy's `./certs` directory, which holds `cert.pem` / `key.pem`. Lab opt-out only: `AGENT_TLS_VERIFY=0` / `TLS_VERIFY=0`. See `docs/DEVELOPMENT.md`.

## Typical workflow

1. Create a tenant (client)
2. Create one or more Sites (physical localities). Optional: set a Site timezone override
3. Add LAN Networks under a Site (overlapping RFC1918 ranges are valid across Sites)
4. Create Agents for a Site, authorize them on the Networks they may scan, and choose Any Available or Preferred + Failover
5. Add WAN targets under the tenant Subnets tab
6. Download agent compose (or `.env` + `agent/docker-compose.yml`) and start it on the remote LAN with `--build`
7. Approve the agent once it appears as `pending approval`
8. Create a scan (manual or interval) and run it
9. Review devices (new / known / stale), findings, and alerts

CVE findings can be enriched from NVD, FIRST EPSS, and CISA KEV by the central API. Set optional `NVD_API_KEY` in the environment; never commit a real key. No tenant or Asset data is sent to those sources. P1–P4 is Nuclei Dashboard operational priority, not an NVD/CISA/FIRST rating.

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

Linux sites should keep `network_mode: host` so LAN subnets are reachable. The first build downloads the pinned Naabu, httpx, Nuclei, and nuclei-templates releases and takes several minutes. Pins are in `scan_runtime/pinned_versions.json`. The build does not follow ProjectDiscovery `latest`.

Admin → Settings has the centrally approved scanner versions. A mismatch in the Agent list or Agent Health report does **not** upgrade the remote Agent. Rebuild/redeploy the image on the site host (`docker compose up -d --build`) when you intend to pick up a new pin. Existing `nuclei-templates` volumes are not replaced automatically.

Verify inside the agent container: `nuclei -version`, `nuclei -tv -disable-update-check`, `naabu -version`, `pd-httpx -version`. Older Agents that have not been rebuilt show **Not Reported**. Historical Scan Runs keep the versions recorded for that run.

The agent stores its private key on a Docker volume. Losing that volume after approval means the agent cannot be reused — create a new agent.

## Scan profiles

- **Discovery only** — naabu + httpx, inventory only
- **Discovery + Nuclei** — same, then nuclei JSONL findings

Set `SCAN_DRY_RUN=1` on the scanner (or agent) to emit sample results without touching the network. Dry-run jobs do not fabricate genuine scanner artifacts.

Raw scanner JSONL is retained on the central `scan-artifacts` volume for 365 days by default (Admin → Settings). Normalized findings and scan history remain after raw files expire. Viewer download access follows Tenant grants. Include the artifact volume in backups if raw evidence must survive host failure.

## Roles

| Role   | Access |
|--------|--------|
| Admin  | System settings, users, everything a user can do |
| User   | Tenants, sites, networks, WAN targets, agents, scans, classification, acknowledge alerts |
| Viewer | Read-only inventory, findings, reports, and history for **explicitly granted** tenants only. Existing Viewer upgrades start with no tenant access. Optional expiration is checked on every request. Cannot download enrollment secrets or agent compose/env. All-tenant Viewer is still not Admin. |

Physical Tenant deletion is disabled (`DELETE /api/tenants/{id}` returns 409) so historical evidence cannot be cascaded away. Tenant create/update, Agent enroll/approve/revoke/deployment-material access, and login success/denial are audited.

## Local UI development

```bash
# API + Postgres from compose, or run uvicorn locally
cd frontend && npm install && npm run dev
```

Vite proxies `/api` to `http://127.0.0.1:8000`.
