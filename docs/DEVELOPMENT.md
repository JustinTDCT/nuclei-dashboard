# Development and deployment notes

`MASTER_PLAN.md` is the canonical architecture and phase contract. Do not implement later phases from it unless the current task says so.

## Database migrations (Alembic)

Schema changes belong in versioned Alembic revisions under `backend/alembic/versions/`. Do not add new `ALTER TABLE` statements to application startup.

`0001_baseline` is a **frozen** Phase 0 snapshot. It does not import live SQLAlchemy models. When models change, add a new revision; do not edit `0001`.

From `backend/`, with `DATABASE_URL` set:

```bash
alembic current
alembic upgrade head
alembic history
alembic revision -m "describe the change"
```

Current head revision: `0004_asset_observation_integrity` (after frozen `0001_baseline`, `0002_sites_networks`, and `0003_assets_observations`).

`0001_baseline`, `0002_sites_networks`, and `0003_assets_observations` are immutable. Phase 1B corrective schema lives in `0004_asset_observation_integrity`.

`alembic downgrade` from `0001_baseline` drops the application schema and **destroys data**. There is no non-destructive downgrade from the baseline.

`alembic downgrade` from `0002_sites_networks` is **refused**. It would destroy Site, Network, authorization, and audit rows. Restore from backup instead of pretending a destructive downgrade is safe.

`alembic downgrade` from `0003_assets_observations` is **refused**. It would destroy Asset, identifier, address, service, observation, and tag history.

`alembic downgrade` from `0004_asset_observation_integrity` is **refused**. It would restore over-coarse observation idempotence and undo expected-lifecycle / identifier hygiene.

### Fresh install

No application tables. API startup runs `apply_schema()` → `alembic upgrade head`, then seeds the first admin.

Do not delete the PostgreSQL volume as a normal operation.

### Existing install (complete pre-Alembic schema)

A recognized legacy database has all Phase 0 tables (`users`, `tenants`, `subnets`, `agents`, `scans`, `scan_jobs`, `devices`, `findings`, `alerts`, `settings`), no `alembic_version`, and **none** of the Phase 1A tables (`sites`, `networks`, `network_agents`, `audit_logs`) or marker columns (`agents.site_id`, `subnets.site_id`, `subnets.network_id`).

1. Deploy this version **without** removing the `postgres-data` volume.
2. Restart the API.

Startup runs `ensure_columns()`, validates the schema, stamps `0001_baseline`, then upgrades to head. Existing rows are not dropped.

Manual adoption (only for a complete current-schema database):

```bash
cd backend
alembic stamp 0001_baseline
alembic upgrade head
```

### Partial or unknown schema

Startup **fails closed** and refuses to stamp or upgrade when:

- some Phase 0 tables exist but the complete Phase 0 set does not, or
- any Phase 1A/1B table or marker column is present and `alembic_version` is missing (including a database that only has `sites`/`networks`, `assets`, or `devices.asset_id`).

Do not guess. Inspect the database and repair or restore it before retrying.

### Tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest
```

Frontend typecheck and production build:

```bash
cd frontend
npm ci
npx tsc --noEmit
npm run build
```

Migration tests start an isolated PostgreSQL on `127.0.0.1:55432` via Docker, or use `TEST_DATABASE_URL` if you set it.

## Phase 1A locality and WAN compatibility

`0002_sites_networks` introduces Site, Network, Network-Agent authorization, dispatch configuration, and a minimal append-only `audit_logs` table.

Existing databases are upgraded in place:

- Each tenant that already has LAN subnets or agents receives one deterministic compatibility Site named **Imported Site**. Topology is not guessed.
- LAN subnet rows become Networks on that Site. The original `subnets` row remains as an ID-stable companion (`subnets.network_id`) so existing `scans.subnet_ids` keep working.
- Every Agent on that tenant is assigned to Imported Site.
- Every Agent on that Site is authorized for every imported LAN Network (preserving the previous “any tenant agent may scan tenant LAN subnets” behavior).
- WAN subnet rows are **not** converted into Networks. WAN scans keep using `subnets` with `scope=wan`.

This companion `subnets` mapping for LAN is an intentional compatibility shim. Remove it when Phase 1D replaces scan targeting with Scan Definition scope and authorized WAN targets.

## Phase 1B assets and observations

`0003_assets_observations` introduces Tenant-scoped Assets with identifier, address, service, and observation history, plus generic Tags for Assets, Sites, and Networks.

Existing Device rows are mapped one-to-one to Assets (`devices.asset_id`, indexed, not unique). Findings continue to reference Device.

LAN Site during backfill:

1. `Device.last_scan_job_id` → ScanJob → Scan → Agent → Site when that chain is complete.
2. Otherwise reuse the tenant's **Imported Site** if it exists.
3. Otherwise create a deterministic **Unassigned Assets** Site for that Tenant.

WAN Devices keep `site_id` NULL. IP is not used to guess Site.

Each migrated Device gets one observation with `source = legacy_migration`. That is a snapshot of the current Device row, not a fabricated scanner timeline.

Scanner ingestion still uses the legacy Device resolver. After a Device is matched or created, the mapped Asset is reused, an `AssetObservation` is appended, and identifier/address/service facts are upserted. Repeated observations do not change `Asset.disposition`. Matching another Asset by IP/hostname/MAC is Phase 1C and is not implemented.

Observation snapshots record only the facts in that `DeviceReport`. Empty `report.ports` does not copy stale Device ports into the snapshot and does not advance `AssetService.last_seen`. Existing positive service rows are retained; they are not closed.

Agent and central scanner `/jobs/{id}/devices` posts can be retried. Observation idempotence is `(scan_job_id, asset_id, observation_key)`, where `observation_key` is a SHA-256 fingerprint of the normalized report hostname/IP/scope/ports. The same exact report is a no-op: no second observation and no Asset/identifier/address/service timestamp advance. A different IP or port set for the same Asset in the same job is a new observation. Hostname/IP are not Asset identity keys.

Expected Assets can be created manually (`is_expected`, `first_seen`/`last_seen` NULL, `lifecycle_state` NULL). Discovery does not auto-attach to them in Phase 1B.

`0004_asset_observation_integrity` is a corrective revision after the already-shipped `0003`. It adds `observation_key`, allows NULL lifecycle for expected Assets, and removes hostname identifiers that are only IP/placeholder values.

IP-as-hostname placeholders are not stored as hostname identifiers. The corresponding `AssetAddress` is retained.

Archived Sites/Networks are soft-deleted (`archived_at`). Do not physically delete them in the normal technician workflow.

## TLS verification

Generated agent compose/env and production defaults verify central-server TLS (`TLS_VERIFY=1` / `AGENT_TLS_VERIFY=1`).

Caddy terminates HTTPS using `./certs/cert.pem` and `./certs/key.pem` (see `Caddyfile`). It does not auto-issue a certificate.

Publicly trusted certificates need no extra agent configuration.

Internal CA: keep verification **on**. The CA file must be visible **inside the agent container**.

1. On the agent host, next to `docker-compose.yml`:
   `mkdir -p agent-certs && cp /path/on/host/your-ca.pem agent-certs/ca.pem`
2. In `agent.env` (or the environment):
   `TLS_CA_FILE=/certs/ca.pem`
3. The stock/generated compose bind-mounts `${TLS_CA_HOST_DIR:-./agent-certs}` to `/certs`.

Keep agent trust material in `./agent-certs`. Caddy's `./certs` directory is only for the server `cert.pem` / `key.pem` and must not be mounted into the agent.

`TLS_CA_FILE` is a container path. A host path such as `/home/tech/ca.pem` is not visible unless that file is mounted into the container. `--env-file` only sets variables that the compose file passes through; the stock file passes `TLS_CA_FILE`.

Do not embed environment-specific CA material in the repository.

Development opt-out only: `AGENT_TLS_VERIFY=0` or `TLS_VERIFY=0`.

## Viewer / Auditor

Viewer is read-only. A Viewer may list agents and see status. A Viewer must not create/approve/revoke agents and must not download compose or env files that can contain an active enrollment secret. Admin and User remain the deployment roles.
