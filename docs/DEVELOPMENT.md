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

Current head revision: `0009_phase2a_detector_identity_partition` (after frozen `0001_baseline` through `0008_phase2a_finding_identity_repair`).

`0001_baseline`, `0002_sites_networks`, `0003_assets_observations`, `0004_asset_observation_integrity`, `0005_asset_correlation_lifecycle`, `0006_scan_definition_execution`, `0007_vulnerability_finding_lifecycle`, and `0008_phase2a_finding_identity_repair` are immutable. Phase 2A identity-partition repair lives in `0009_phase2a_detector_identity_partition`.

`alembic downgrade` from `0001_baseline` drops the application schema and **destroys data**. There is no non-destructive downgrade from the baseline.

`alembic downgrade` from `0002_sites_networks` is **refused**. It would destroy Site, Network, authorization, and audit rows. Restore from backup instead of pretending a destructive downgrade is safe.

`alembic downgrade` from `0003_assets_observations` is **refused**. It would destroy Asset, identifier, address, service, observation, and tag history.

`alembic downgrade` from `0004_asset_observation_integrity` is **refused**. It would restore over-coarse observation idempotence and undo expected-lifecycle / identifier hygiene.

`alembic downgrade` from `0005_asset_correlation_lifecycle` is **refused**. It would destroy correlation decisions, domain events, merge lineage, and identifier correction history.

`alembic downgrade` from `0006_scan_definition_execution` is **refused**. It would destroy authorized WAN targets, scan definition associations, exclusions, execution snapshots, and schedule history.

`alembic downgrade` from `0007_vulnerability_finding_lifecycle` is **refused**. It would destroy vulnerability catalog identity, Asset Finding lifecycle history, and Detection Evidence linkage.

`alembic downgrade` from `0008_phase2a_finding_identity_repair` is **refused**. It would destroy Run detector-coverage evidence and reintroduce inconsistent catalog/mapping identity.

`alembic downgrade` from `0009_phase2a_detector_identity_partition` is **refused**. It would rejoin partitioned detector evidence onto the wrong Vulnerability and restore incorrect CVE identity from mixed multi-CVE history.

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
- any Phase 1A/1B/1C/1D table or marker column is present and `alembic_version` is missing (including a database that only has `sites`/`networks`, `assets`, `devices.asset_id`, `devices.site_id`, `assets.merged_into_asset_id`, `asset_identifiers.validity`, `authorized_wan_targets`, or `scans.definition_revision`).

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

Expected Assets can be created manually (`is_expected`, `first_seen`/`last_seen` NULL, `lifecycle_state` NULL).

## Phase 1C correlation and lifecycle

`0005_asset_correlation_lifecycle` makes Asset correlation authoritative. Incoming DeviceReports are normalized, scored against a bounded candidate set (indexed identifiers/addresses, never every Tenant Asset), then either linked, left ambiguous, or used to create a new Asset. Device rows are a compatibility projection written after that decision. The legacy Tenant+hostname+scope Device unique constraint now includes `site_id` and `asset_id` so two LAN systems with the same hostname at different Sites stay distinct.

Hard rules: Tenant mismatch is impossible; LAN auto-match is Site-local; IP alone cannot auto-match; a hostname/uniqueness bonus cannot auto-match by itself; automatic correlation requires a strong stable identifier (MAC/serial/device ID) or independent corroboration (name plus address/service/TLS/DNS) *and* `score >= AUTO_MATCH_THRESHOLD`; `linked_existing` can never have `confidence=low`; placeholder hostnames contribute no hostname evidence; identifiers marked `incorrect` are ignored; WAN↔LAN joins require a strong unique identifier. Explicit merge and Asset Site moves reconcile colliding Device compatibility rows so Findings stay valid.

`observation_key` is a SHA-256 of the complete evidence-bearing report (hostname, IP, scope, ports, MAC, serial, device identifier, FQDN, TLS name, DNS name, title, tech, classification, auto_label). Identical report replay dedupes; the same host/IP with different identity evidence is a new observation and correlation decision.

Exact scanner retries reuse the stored `AssetCorrelationDecision` (`scan_job_id`, `observation_key`) and do not duplicate observations, decisions, or events.

Manual operations (`asset.merge`, `asset.split`, `asset.identifier_correct`, `asset.move_site`, `asset.observation_reassociate`) are audited. Merged Assets are retained with `merged_into_asset_id`. Split/reassign/merge rebuild scanner-derived identifier/address/service projections from remaining observation snapshots, including MAC/serial/FQDN/TLS/DNS. Duplicate Device compatibility rows are consolidated during an explicit merge. A discovered Asset with no remaining observations does not keep stale first/last-seen or active lifecycle.

`asset_inactive_days` is a new Admin setting and is intentionally separate from Device `stale_days`. Expected / not-yet-observed Assets do not become inactive. Domain events persist `new_asset`, `asset_became_inactive`, and `previously_inactive_asset_returned` only. Alert email/webhook/Teams routing remains Phase 3B.

`post_correlation_asset_policy_hook` is the Phase 3A seam. Phase 1C never auto-approves by observation count or age.

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

## Phase 1D scan definitions and immutable runs

`0006_scan_definition_execution` evolves existing `scans` into editable Scan Definitions and `scan_jobs` into immutable Scan Runs. New Runs store `execution_snapshot` JSONB. Historical pre-1D jobs keep `snapshot_version = legacy_pre_1d` and a NULL snapshot.

WAN Subnet rows are copied to `authorized_wan_targets`. LAN `subnet_ids` become `scan_network_targets`. Site is taken only from the Agent/Site relationship. Invalid legacy LAN scans are preserved, disabled, and marked `needs_review`.

Workers execute the snapshot. Agent dispatch uses the common authorized pool, Any Available or Preferred + Failover, atomic claim, and `waiting_for_agent` / `missed`. `scan_missed_unavailable_agent` is a DomainEvent only; no alert routing.

## Viewer / Auditor

Viewer is read-only. A Viewer may list agents and see status. A Viewer must not create/approve/revoke agents and must not download compose or env files that can contain an active enrollment secret. Admin and User remain the deployment roles.
