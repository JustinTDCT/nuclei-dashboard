# Development and deployment notes

`MASTER_PLAN.md` is the canonical architecture and phase contract. Do not implement later phases from it unless the current task says so.

The defined implementation roadmap is complete through Phase 3C, Scale S3, and Sec H9 (`3f702b8`). **V1A** is ACCEPT / CLOSED (`a06e455` on audited baseline `3f702b8`). Current tranche is **V1B — Operational Release Readiness** (`docs/V1B_OPERATIONS.md`, `docs/V1B_CLOSURE.md`): no product features, no `0018`, no Agent pin change, no V1A PARTIAL fixes.

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

Current head revision: `0017_security_h6_h8` (after frozen `0001_baseline` through `0016_scanner_runtime_inventory`).

`0001_baseline` through `0016_scanner_runtime_inventory` are immutable. Do not edit 0016. `0017_security_h6_h8` adds durable Agent challenges, login/challenge lockouts, and ScanJob deadline/cancel columns.

`alembic downgrade` from `0001_baseline` drops the application schema and **destroys data**. There is no non-destructive downgrade from the baseline.

`alembic downgrade` from `0002_sites_networks` is **refused**. It would destroy Site, Network, authorization, and audit rows. Restore from backup instead of pretending a destructive downgrade is safe.

`alembic downgrade` from `0003_assets_observations` is **refused**. It would destroy Asset, identifier, address, service, observation, and tag history.

`alembic downgrade` from `0004_asset_observation_integrity` is **refused**. It would restore over-coarse observation idempotence and undo expected-lifecycle / identifier hygiene.

`alembic downgrade` from `0005_asset_correlation_lifecycle` is **refused**. It would destroy correlation decisions, domain events, merge lineage, and identifier correction history.

`alembic downgrade` from `0006_scan_definition_execution` is **refused**. It would destroy authorized WAN targets, scan definition associations, exclusions, execution snapshots, and schedule history.

`alembic downgrade` from `0007_vulnerability_finding_lifecycle` is **refused**. It would destroy vulnerability catalog identity, Asset Finding lifecycle history, and Detection Evidence linkage.

`alembic downgrade` from `0008_phase2a_finding_identity_repair` is **refused**. It would destroy Run detector-coverage evidence and reintroduce inconsistent catalog/mapping identity.

`alembic downgrade` from `0009_phase2a_detector_identity_partition` is **refused**. It would rejoin partitioned detector evidence onto the wrong Vulnerability and restore incorrect CVE identity from mixed multi-CVE history.

`alembic downgrade` from `0010_cve_intelligence_priority` is **refused**. It would destroy normalized NVD/EPSS/KEV intelligence and AssetFinding operational priority explanations.

`alembic downgrade` from `0011_phase2c_treatments_compliance` is **refused**. It would destroy treatment history, compensating controls, framework/control catalog rows, and evidence-to-control mappings.

`alembic downgrade` from `0012_policy_engine` is **refused when `policy_rules` contains rows**. Configured policy history is not silently dropped. An empty `policy_rules` table may downgrade.

`alembic downgrade` from `0013_event_alert_engine` is **refused when Phase 3B history exists** (queue, deliveries, routes, alerting policies, or populated new event/alert columns). Empty Phase 3B tables and unused new columns may downgrade.

`alembic downgrade` from `0014_reports_auditor_access` is **refused when Viewer authorization is configured** (`viewer_all_tenants = TRUE`, any `viewer_expires_at`, or any `viewer_tenant_grants` rows). An empty/unconfigured 0014 may downgrade.

`alembic downgrade` from `0015_raw_scan_evidence` is **refused when `scan_artifacts` contains rows**. Empty metadata may downgrade to 0014. Downgrade never deletes filesystem artifact bytes.

`alembic downgrade` from `0016_scanner_runtime_inventory` is **refused when any Agent has `runtime_inventory` or `runtime_inventory_reported_at`**. An empty inventory (all NULL) may downgrade to 0015. Downgrade never fabricates or silently destroys recorded version evidence.

`alembic downgrade` from `0017_security_h6_h8` is **refused when `agent_challenges` or `auth_throttles` contain rows, or any ScanJob has `deadline_at` / `cancel_requested_at`**. Empty security-control state may downgrade to 0016.

## Raw scan evidence

The central API owns raw scanner artifacts. PostgreSQL stores metadata only (`scan_artifacts`). Artifact bytes are gzip JSONL files on a dedicated Docker volume.

- `RAW_ARTIFACT_DIR` defaults to `/var/lib/nuclei-dashboard/raw-artifacts`.
- `RAW_ARTIFACT_MAX_BYTES` defaults to 268435456 (256 MiB). Oversized uploads are rejected; artifacts are never silently truncated.
- Compose volume `scan-artifacts` is mounted on every API replica and on the scheduler (retention deletes bytes). Remote LAN agents upload over HTTPS; they do not receive the volume. Replicas that do not share this volume cannot serve downloads of artifacts another replica ingested.
- Default retention is 365 days (`raw_scan_artifact_retention_days` in Admin → Settings). The value at upload time sets that artifact's `retention_expires_at`. Changing the setting does not bulk-delete existing artifacts.
- Successful `complete?ok=true` requires an explicit raw-evidence declaration (`captured`, `dry_run`, `none_executed`, or `skipped_no_targets`). The declaration is checked against the immutable execution snapshot: a normal scan with an unconditional scanner stage cannot claim `none_executed`, `dry_run` is accepted only when the snapshot itself is a dry-run, and `captured` must persist and declare every expected artifact for those stages (`port_discovery.naabu` / `discovery.naabu`, `fingerprint.httpx`, `vulnerability.nuclei`). `skipped_no_targets` is only for `port_scope=detected` discovery that found no hosts: discovery.naabu must still be persisted, downstream httpx/Nuclei/port artifacts must not exist, and the job must have ingested no observations, findings, or detector coverage (so it cannot become CLEAN). A successful real run must also persist the required scanner version provenance for that snapshot (`runtime_version`, plus `naabu_version` / `httpx_version` / `nuclei_version` / `nuclei_templates_version` when those stages executed). A stale client that omits the declaration, required evidence, or required versions is rejected and the run is not marked successful. Failed completes remain optional and may keep partial artifacts and partial provenance. Dry-run jobs must not fabricate Nuclei/Naabu/httpx/template execution versions.
- Client-supplied artifact provenance is allowlisted to scalar runtime/tool/template version strings. Secret-bearing keys and nested objects are rejected.
- Read-time expiry is enforced even before hourly cleanup. Expired artifacts are not downloadable. Missing pre-expiry bytes are `unavailable`, not `expired`.
- Hourly cleanup deletes expired bytes, keeps the metadata row, and records `scan_artifact.retention_delete`. Normalized Assets, Observations, Findings, history, and ScanJobs are untouched.
- Viewer access follows Tenant grants. Direct IDs for other tenants fail closed as 404. Successful downloads record `scan_artifact.download`.
- Existing Scan Runs created before 0015 have no artifact rows because raw bytes were never retained. Do not treat that as “the scanner produced no output”.
- Backup operators who need recoverable raw evidence after host failure must include the `scan-artifacts` volume as well as `postgres-data`.

## Scanner runtime pinning and version inventory

Pinned scanner build inputs live in `scan_runtime/pinned_versions.json`. The API copy `backend/app/pinned_scanner_versions.json` must match that file. Image construction downloads exact Nuclei, Naabu, ProjectDiscovery httpx, and nuclei-templates releases and SHA-256-verifies each archive against `checksums_sha256`. It does not resolve ProjectDiscovery `releases/latest`. A missing pin or checksum mismatch fails the build instead of falling back.

Generated Agent compose must pin a 40-character `AGENT_GIT_CONTEXT` commit SHA. Tags and `refs/heads/main` are rejected. The API container does not install `git` and does not resolve tags; resolve a tag to its commit on the operator host if needed. After merging Agent/runtime changes, bump the pin to that commit. LAN Agents keep `network_mode: host` so site RFC1918 is reachable. They run as uid 1000 with `cap_drop: ALL` and `cap_add: NET_RAW` because Naabu SYN/host-discovery needs raw sockets; do not add `privileged: true`. The WAN scanner uses the same user/capability set on the Docker bridge. `security_opt: no-new-privileges:true` is required.

The scanner runtime release ID (`runtime_version`) is a scanner-image identifier, not the overall application version. Ordinary Nuclei scans pass `-duc` so template releases do not change during a job. Fresh images bake templates under `/opt/nuclei-templates`. Existing `nuclei-templates` volumes are not deleted or rewritten by this upgrade; they may show mismatch until an operator rebuilds/redeploys the agent image.

Admin → Settings holds the centrally approved versions. Changing those values updates match/mismatch status only. It does not upgrade Agents, rebuild containers, replace template volumes, or start a remote deployment. Auto-update remains deferred.

Agents report current installed inventory on authenticated heartbeat (`runtime_version`, `nuclei_version`, `nuclei_templates_version`, `naabu_version`, `httpx_version`). Inventory is sent on startup, when it changes, and on the hourly refresh — not on every heartbeat. An ordinary heartbeat may be empty or include only `job_id` / `activity`. The Agent keeps an independent control/heartbeat loop while a single scan worker executes, so a long scan does not make a healthy Agent appear Offline. Pre-Tranche-C Agents stay usable and display **Not Reported** until they run a Tranche-C image. Derived comparison is computed at read time from current inventory plus current approved settings; it is not stored on the Agent row.

`GET /api/agent/jobs` selects queued LAN jobs this Agent is snapshot-eligible for in SQL. It inspects up to 25 candidates and returns the first job that is actually claimable. An Agent that already has a running ScanJob is treated as busy and is not offered another job.

`POST /api/agent/jobs/{id}/start` serializes claims with `SELECT Agent ... FOR UPDATE` before the per-job atomic claim. Two concurrent starts for the same Agent identity cannot both succeed. No schema change.

Pinned httpx v1.10.0 initializes a DIT page classifier on `-json` and would otherwise download ~92MB from Hugging Face. Image build seeds `$HOME/.dit/model.json` (`/home/scanner/.dit/model.json`) with `{}` so runtime stays offline. We do not consume PageType. Do not add `-no-classify`; that flag is not in v1.10.0.

`ScanJob.runtime_provenance` is historical evidence for that run. Never infer it from the Agent's current inventory. Pre-Tranche-C Scan Runs display **Not Recorded**.

Verify installed tools inside a scanner/agent container:

```bash
nuclei -version
nuclei -tv -disable-update-check
naabu -version
pd-httpx -version
```

Rebuild a site agent after pin changes (or after pulling this repo) with the existing technician workflow:

```bash
docker compose up -d --build
```

Do not delete `postgres-data`, `scan-artifacts`, or existing `nuclei-templates` volumes as part of a normal upgrade.

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

Frontend typecheck, lint, focused tests, and production build:

```bash
cd frontend
npm ci
npm run typecheck
npm run lint
npm run test
npm run build
```

Staff bearer tokens are stored in `sessionStorage` so they do not survive a browser restart. They remain XSS-readable in page JavaScript; httpOnly cookies are a later control-plane change. MFA remains deferred.

`SETTINGS_ENCRYPTION_KEY` must be a generated Fernet key and must differ from `SECRET_KEY`, `SCANNER_TOKEN`, and the database password. It may be empty only when no SMTP password is stored. If an SMTP password exists, startup migrates leftover plaintext and refuses to start when the key is missing or cannot decrypt. The API still masks the password on read. A blank save keeps the existing secret.

GitHub Actions runs backend pytest plus the frontend typecheck/lint/test/build. Job names are `backend` and `frontend`. Frontend CI needs Node **22.10+** because jsdom 30’s undici requires `worker_threads.markAsUncloneable` (absent on Node 20). V1B policy: `main` is protected so those two checks are required on pull requests; force-push and deletion are forbidden; **direct pushes to `main` are prohibited** (`enforce_admins` on), including for repository admins. Land changes through a PR after both checks are green. That protection is a GitHub setting, not application code; enable it only after CI is green on the candidate SHA. Do not protect a red `main`.

Migration tests start an isolated PostgreSQL on `127.0.0.1:55432` via Docker, or use `TEST_DATABASE_URL` if you set it.

### Scale S2A ingest harness

S2A froze ingest semantics against the S1 checkpoint (`312e0d0`). S2B (`d9afc55`, ACCEPT) collapsed Device/Asset lookups with `ScanIngestContext`. S2C (`fa67a89`, ACCEPT) adds one `FindingRunIndex` per Finding/coverage/finalize batch so current-run observations, Devices, coverage, evidence keys, mappings, evaluations, and detector CVE unions are not reloaded per finding. S2D is ACCEPT: implementation `c59e144`, list-boundary correction `1040549`, Agent pin / live HEAD `5a5f922` pointing generated Agents at `1040549`. Device/Finding/coverage HTTP requests are bounded by row count and encoded bytes (`INGEST_MAX_ROWS` / `INGEST_MAX_BYTES`, defaults 500 / 1 MiB). A single record is rejected when it cannot fit as a JSON list (`2 + size > max_bytes`). Whole-list clients still use the same endpoints if they fit; oversized batches and oversized single records return 413. Schema head remains `0017_security_h6_h8`; no 0018 migration. The S2C gate still allows one set-based historical `Finding.raw_json` query for the batch's detector keys; the old hotspot is a high repeated Finding SELECT count, not zero raw-JSON access.

S2E is ACCEPT at implementation `3cdb52c` (generated Agents pin that SHA, not the pin-bump commit). After S2D the server already accepts bounded chunks; the Agent must not accumulate the whole normalized scan in RAM before upload. Scanner output is streamed through a per-job disk spool under `AGENT_DATA_DIR/spool` (LAN default `/data/spool`, mode 0700/0600), sealed at the S2D row/byte limits, uploaded Device → Finding → coverage, and deleted only after ACK. Peak Agent RSS must stay within a bounded margin as result count grows; it must not scale approximately linearly with findings. Do not build giant `result["devices"]` / `result["findings"]` lists and then write those lists to disk. Restart recovery must discover local `pipeline.done` jobs before polling queued work and resume upload without `/start` while the server job is still running and owned. The WAN scanner mounts `scanner-data:/data` with `AGENT_DATA_DIR=/data` so a Compose recreate keeps the spool; do not reuse `agent-keys`. Completed raw `.jsonl.gz` artifacts are written under the same job directory (`$AGENT_DATA_DIR/spool/jobs/{job_id}/raw`) so `pipeline.done` can resume upload after recreate; do not stage them only in container `/tmp`. An artifact upload failure must retain that directory for retry; delete it only after the server ACKs every raw artifact. Live LAN Agent and central WAN scanner recreate/resume gates passed. No 0018 unless measurement says so. S2 is complete / frozen.

### Scale S3A startup Device refresh

S3A is ACCEPT at implementation `75034d7` plus concurrency correction `901f159`. It removes `refresh_discovery_metadata` from API process startup. That call used to `query(Device).all()` and rewrite classification / `auto_label` / tech from the current heuristics, so startup cost grew with inventory size. Live ingest already applies the same heuristics per DeviceReport. Leftover catch-up for rows that have not been re-observed is one keyset page (`Device.id > after_id ORDER BY id LIMIT N`) per scheduler tick (`discovery-metadata`, every 5 minutes, `DISCOVERY_METADATA_BATCH_SIZE` default 250). The page uses `FOR UPDATE SKIP LOCKED`: catch-up does not wait on a Device ingest already owns, and if catch-up holds the lock first, ingest's UPDATE waits and still commits last. Do not loop the whole table in one tick, and do not put this work back in `lifespan`. Device field semantics stay the former startup-refresh rules. Schema head remains `0017_security_h6_h8`; do not add `0018`. Agent pin stays `3cdb52c`.

```bash
cd backend
pytest tests/test_scale_s3a.py
```

### Scale S3B scheduler process

S3B is ACCEPT at implementation `c6ccc7f` plus leader-fencing correction `cca2ea2`. It moves APScheduler out of the API process into Compose service `scheduler` (`python -m app.scheduler_process`). API `lifespan` only applies schema, `ensure_columns`, and `seed`; it must not start or stop the scheduler. Two API replicas therefore cannot create duplicate scheduler ownership. The scheduler process takes a session-level PostgreSQL advisory lock (`SCHEDULER_LEADER_LOCK_KEY`) before calling `start_scheduler()`. While leading, it re-reads `pg_backend_pid()` on that same connection every two seconds; if the query fails or the backend pid changes, APScheduler is stopped with `wait=True` and the process exits without reacquiring. Graceful SIGTERM also uses `stop_scheduler(wait=True)` and only then releases the advisory lock, so a standby cannot start jobs while the old leader still has a worker in flight. A second scheduler replica waits on the lock and does not start APScheduler. Job ids and intervals stay the S3A catalog (including `discovery-metadata` at 5 minutes). The scheduler mounts `scan-artifacts` so raw-artifact retention can delete bytes.

This is a single-active scheduler design, not a claim of zero-overlap HA under every network partition. The intended deployment remains one Compose `scheduler` service; the advisory lock and PID probe are fail-closed protection against accidental duplicate ownership. Do not `docker compose up --scale scheduler=2` as the operating model. Schema stays `0017_security_h6_h8`. This tranche does not add a second API replica.

```bash
cd backend
pytest tests/test_scale_s3a.py tests/test_scale_s3b.py
```

### Scale S3C EventAlertQueue stale reclaim

S3C is ACCEPT at `07d883c`. It reclaims `EventAlertQueue` rows left `processing` after a crash. Claim already used `FOR UPDATE SKIP LOCKED` and `ALERT_ROUTE_BATCH_SIZE`; it only selected `pending` due now, so a committed `processing` row stayed stuck. Reclaim uses existing `updated_at` (set at claim) as the lease clock after `ALERT_QUEUE_LEASE_SECONDS` (120s, same duration as delivery leases). A recently claimed row is not stolen. Max-attempt rules still apply: a stale row whose attempts already reached the cap fails without creating another Alert. Reclaim runs inside the existing `alert-routing` tick; the 12-job catalog and intervals stay frozen. Schema stays `0017_security_h6_h8`; do not add `0018`. Agent pin stays `3cdb52c`. This tranche does not add a second API replica.

The pending index remains `(status, next_attempt_at)`. Stale reclaim filters `(status='processing', updated_at <= cutoff)` and can use the indexed status prefix. `processing` is meant to be a small transient set and the claim is capped, so do not invent `0018` for a dedicated `(status, updated_at)` index unless a large-queue plan shows a real problem.

```bash
cd backend
pytest tests/test_scale_s3a.py tests/test_scale_s3b.py tests/test_scale_s3c.py
```

### Scale S3D true API pagination

S3D is ACCEPT at implementation `782f072` plus UI correction `fcc47e5`. It pages the staff collection GETs that grow with inventory and scan volume. It is not a broad router rewrite.

Classification at the start of this tranche:

- **Already bounded:** Agent/scanner job poll (`limit` 5 / first claimable), dashboard recent rows (`limit` 8), ingest POSTs (S2D row/byte caps), `alert-routing` / `alert-delivery` claim batches, S3A discovery-metadata keyset page. Asset history endpoints (`/assets/{id}/observations|events|identifiers|addresses|services|correlation`) and `/audit-history` / `/domain-events` already return `HistoryPage` with `limit`/`offset`/`total`. Report preview already has `page`/`page_size`.
- **Nominally capped, not pageable:** these returned a JSON array with a silent `.limit(N)` and no way to fetch the rest. Highest production risk, changed this tranche: `GET /tenants/{id}/asset-findings` (was 2000), `GET /tenants/{id}/findings` (was 2000), `GET /tenants/{id}/assets` (was 1000), `GET /tenants/{id}/devices` (was 1000), `GET /alerts` (was 500), `GET /tenants/{id}/jobs` (was 100), `GET /jobs` (was 50). They now return `HistoryPage` (`items`, `total`, `limit`, `offset`), default 50, max 200. Filters still apply before the limit.
- **Fully unbounded / deferred to S3E:** CSV compatibility exports (`/assets/export`, `/findings/export`, `/devices/export`) and report CSV/PDF export iteration. Device detail still embeds up to 2000 findings. Per-parent evidence/history/treatments/control-references load that subject's rows. Config lists (tenants, users, sites, networks, agents, scans, policies, tags, exclusions, WAN targets, subnets, compliance frameworks/controls) stay unpaged; they are not inventory-scale.

Assets search Enter resets to offset 0, matching the Search button. Do not change Agent/scanner poll contracts. Do not add `0018`. Agent pin stays `3cdb52c`. This tranche does not add a second API replica.

```bash
cd backend
pytest tests/test_scale_s3a.py tests/test_scale_s3b.py tests/test_scale_s3c.py tests/test_scale_s3d.py
```

### Scale S3E keyset report/export iteration

S3E is ACCEPT at implementation `b241ee9` plus correction `a6eabbe`. It streams report CSV/PDF exports and the three compatibility CSV exports so a large inventory cannot force the API to hold the full result set in Python memory. Full-result semantics stay: same columns, same filters, same deterministic order, every matching row. Preview and staff list GETs stay on the S3D `HistoryPage` / `page`/`page_size` offset contract.

Do not use `OFFSET n` or `query.all()` for export iteration. Walk keyset batches (`(sort keys, id)` seek, default 200 rows, `REPORT_EXPORT_BATCH_SIZE`) and drop the batch from the Session after it is serialized. Equivalence is first row, last row, and total row count against the former full-load exporter. Peak RSS must not grow linearly with row count; SELECT count may grow with batch count.

The correction keeps two export paths from loading or skipping rows. `_open_age_buckets()` computes the six open-age bands in PostgreSQL (`CASE` + `GROUP BY`, at most six grouped rows) with `greatest(0, age)` so future/negative age clamps to zero: 0–30, 31–60, 61–90, 91–180, 181–365, 365+. `executive_summary()` must not `query(AssetFinding.first_seen)...all()`. Resolved-finding export selects `sort_at = COALESCE(AssetFinding.resolved_at, latest resolution-history timestamp)` and keysets `(sort_at ASC, id ASC)`; the cursor reads `row.sort_at` and must not substitute `row.first_seen`. Preview keeps the existing entity/offset query.

Do not add `0018`. Agent pin stays `3cdb52c`. This tranche does not add a second API replica.

```bash
cd backend
pytest tests/test_scale_s3a.py tests/test_scale_s3b.py tests/test_scale_s3c.py tests/test_scale_s3d.py tests/test_scale_s3e.py
```

### Scale S3F replica-readiness inventory and two-API gate

S3F is **ACCEPT / FROZEN**. Governing implementation chain: `ab9fa42` (base), `a856af8` (Caddy failover), `fd697a6` (drop ineffective `health_uri` on dynamic upstreams). Docs checkpoint `4735e57` remains the intermediate pre-live record. Sec H9 is **CLOSED**. One or two API replicas are a supported operating model; Compose default remains one API. Do not `--scale scheduler=2`.

Live Compose `--scale api=2` passed on operator-provided secdock evidence at HEAD `fd697a6`: two healthy APIs against shared PostgreSQL and `scan-artifacts`; exactly one scheduler leader (advisory lock `91304701`); Caddy `dynamic a api 8000`; public `/api/internal*` 404; staff JWT and DB writes through Caddy; LAN Agent heartbeats in the two-API topology. Stopping `api-1` while 100 `/api/health` plus 100 authenticated `GET /api/auth/me` overlapped the stop produced **200/200** with zero 502/503/timeouts (max 269 ms on the first failover GET). New LAN job 10 (`S2E recreate gate LAN`, Nuclei-Pi4) and WAN job 11 (`S2E recreate gate WAN`, `claimed_by=central`) both reached `done`; expected discovery-profile artifacts (`discovery.naabu`, `port_discovery.naabu`, `fingerprint.httpx`) uploaded and downloaded through Caddy; zero findings because those definitions have no Nuclei stage. Schema stayed `0017`; Agent pin stayed `3cdb52c`.

Closing H9 does not qualify arbitrary N-replica scaling, zero interruption under every network partition, replay of an already-transmitted POST/PATCH after an ambiguous upstream failure, a scaled scheduler, PostgreSQL HA, or Caddy retry on the scanner's direct `http://api:8000` path.

Active `health_uri` checks do not run for `dynamic a` upstreams; do not leave them in the Caddyfile as if they probe API containers. Effective protection is 1s Docker DNS refresh, 500ms `transport http` `dial_timeout` (not `dynamic a` `dial_timeout`, which is the DNS resolver), 2s `lb_try_duration`, and 2s passive `fail_duration`. Dial failure may fail over any method; after a connected round-trip Caddy retries GET only.

The local pytest gate is process-level shared-filesystem semantics. The live gate is Compose `--scale api=2`, the named `scan-artifacts` volume, and Caddy `dynamic a api 8000` with `lb_try_duration` so a dead replica is not a client 502.

**Replica-safe (shared PostgreSQL / image / request scope):**

- Staff JWT is signed with shared `SECRET_KEY` and bound to the current password hash (H5). The browser holds the token in `sessionStorage`.
- Agent JWT is likewise stateless. Challenge nonces are durable `agent_challenges` rows; consume uses `SELECT ... FOR UPDATE`.
- Login and Agent-challenge rate limits / lockouts are PostgreSQL `auth_throttles` UPSERT + `FOR UPDATE` (H8).
- Settings, job claim (`SELECT Agent ... FOR UPDATE` then atomic `UPDATE ... WHERE unclaimed`), alert-queue claim (`FOR UPDATE SKIP LOCKED`), and ingest write-through caches (`ScanIngestContext`, `FindingRunIndex`, `PolicyResolver`) are request/run scoped, not process globals.
- Report CSV/PDF spool files are per-response `tempfile.SpooledTemporaryFile` objects. They never replace `RAW_ARTIFACT_DIR`.
- Compliance catalog JSON and `pinned_scanner_versions.json` are read-only files in the image.

**Must stay single-active (scheduler process):**

- `_discovery_metadata_after_id` is a scheduler-process catch-up cursor. The dedicated `scheduler` service remains one replica. A second scheduler waits on the PostgreSQL leader lock and does not start APScheduler; that is fail-closed protection, not the operating model.

**Filesystem / Compose assumptions:**

- Artifact bytes live under `RAW_ARTIFACT_DIR` (`scan-artifacts` volume). Every API replica and the scheduler must mount the same volume. Incoming writes use a UUID `.part` then rename; same-key ingest locks the metadata row.
- LAN Agents and staff reach the API through Caddy (`PUBLIC_URL`). Caddy must DNS-resolve every healthy `api` task (`dynamic a api 8000`), not pin a single container IP at start. When a replica disappears, Caddy must try another upstream (`lb_try_duration`, `transport http` `dial_timeout`, passive `fail_duration`). Do not use `health_uri` here; active health checks do not run for dynamic upstreams. Do not replay POST/PATCH after a connected round-trip.
- The WAN scanner calls `http://api:8000` on the Docker network (Caddy still 404s `/api/internal*`). Compose DNS for a scaled `api` service can return more than one address.
- Every API lifespan runs `apply_schema()` + `seed()`. Concurrent replica start serializes that work with a session-level PostgreSQL advisory lock on a dedicated engine so `apply_schema()`'s `engine.dispose()` cannot drop the lock session. The lock key is not the scheduler leader key.
- Agent/scanner spools stay on the worker (`AGENT_DATA_DIR`). They are not API-replica state.

The pytest gate starts two uvicorn processes against the test PostgreSQL and shared `RAW_ARTIFACT_DIR`, then exercises login, staff reads/writes, Agent challenge/token, scanner poll, and artifact upload-on-one / download-on-the-other. Compose default remains one API; `--scale api=2` is the supported two-replica topology.

Do not add `0018`. Agent pin stays `3cdb52c`. Do not reopen S2 / S3A–S3F.

```bash
cd backend
pytest tests/test_scale_s3a.py tests/test_scale_s3b.py tests/test_scale_s3c.py tests/test_scale_s3d.py tests/test_scale_s3e.py tests/test_scale_s3f.py
```

S2B tenant-wide prefetch row counts are recorded on ingest metrics (`prefetch_identifier_rows`, `prefetch_address_rows`, `prefetch_device_rows`) plus Device-stage wall time, SELECT count, and peak API RSS. S2D records `finding_index_preloads`, `finding_index_preload_selects`, `finding_index_preload_wall_ms`, and `finding_index_preload_peak_rss_bytes` when Finding/coverage/finalize each build a `FindingRunIndex`. Use medium/large sizes with `--chunk-rows` / `--chunk-bytes` when measuring per-chunk preload cost. If preload RSS dominates, that is evidence for a later request/run-scoped optimization — do not automatically redesign S2C, and do not return to per-report queries.

```bash
cd backend
pytest tests/test_scale_s2a.py tests/test_scale_s2b.py tests/test_scale_s2c.py tests/test_scale_s2d.py tests/test_scale_s2e.py
python scripts/scale_s2a_benchmark.py --size small --out /tmp/s2a-small.json
python scripts/scale_s2a_benchmark.py --size small --chunk-rows 10 --chunk-bytes 16384 --out /tmp/s2d-small.json
```

`--size medium` and `--size large` are for volume measurement only. Do not treat those as required CI. The harness compares normalized Assets, identifiers, addresses, services, observations, correlation decisions, Devices, Vulnerabilities, mappings, Findings, AssetFindings, evaluations, history, DomainEvents, Alerts, and ScanJob counters. Replaying an identical Device/Finding chunk must equal a single ingest.

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

`post_correlation_asset_policy_hook` applies Asset Handling policy after correlation identity is resolved. Phase 1C correlation never auto-approves by observation count or age; only an explicit matching Phase 3A disposition action may set `approved`.

`0004_asset_observation_integrity` is a corrective revision after the already-shipped `0003`. It adds `observation_key`, allows NULL lifecycle for expected Assets, and removes hostname identifiers that are only IP/placeholder values.

IP-as-hostname placeholders are not stored as hostname identifiers. The corresponding `AssetAddress` is retained.

Archived Sites/Networks are soft-deleted (`archived_at`). Do not physically delete them in the normal technician workflow.

## TLS verification

Generated agent compose/env and production defaults verify central-server TLS (`TLS_VERIFY=1` / `AGENT_TLS_VERIFY=1`).

Caddy terminates HTTPS using `./certs/cert.pem` and `./certs/key.pem` (see `Caddyfile`). It does not auto-issue a certificate. Caddy answers `/api/internal*` with 404; the central scanner calls `http://api:8000` on the Docker network and never needs that namespace on the public listener.

The API refuses to start when `SECRET_KEY`, `SCANNER_TOKEN`, or the database password is empty, a known placeholder, or reused across those credentials. `ADMIN_PASSWORD` is required only while the user table is empty. Compose requires `SECRET_KEY`, `SCANNER_TOKEN`, and `POSTGRES_PASSWORD` to be set in `.env`.

Publicly trusted certificates need no extra agent configuration.

Internal CA: keep verification **on**. The CA file must be visible **inside the agent container**.

1. On the agent host, next to `docker-compose.yml`:
   `mkdir -p agent-certs && cp /path/on/host/your-ca.pem agent-certs/ca.pem`
2. In `agent.env` (or the environment):
   `TLS_CA_FILE=/certs/ca.pem`
3. The stock/generated compose bind-mounts `${TLS_CA_HOST_DIR:-./agent-certs}` to `/certs`.

Keep agent trust material in `./agent-certs`. Caddy's `./certs` directory is only for the server `cert.pem` / `key.pem` and must not be mounted into the agent.

`TLS_CA_FILE` is a container path. A host path such as `/home/tech/ca.pem` is not visible unless that file is mounted into the container. `--env-file` only sets variables that the compose file passes through; the stock file passes `TLS_CA_FILE`.

LAN Agent rebuild/recreate on NUCLEI-AGENT (and any generated site Agent) must use `docker compose --env-file agent.env ...`. A plain `docker compose up` without that file can recreate a running container that still cannot verify the central certificate because `TLS_CA_FILE` was never interpolated into the container environment.

Do not embed environment-specific CA material in the repository.

Development opt-out only: `AGENT_TLS_VERIFY=0` or `TLS_VERIFY=0`.

## Phase 1D scan definitions and immutable runs

`0006_scan_definition_execution` evolves existing `scans` into editable Scan Definitions and `scan_jobs` into immutable Scan Runs. New Runs store `execution_snapshot` JSONB. Historical pre-1D jobs keep `snapshot_version = legacy_pre_1d` and a NULL snapshot.

WAN Subnet rows are copied to `authorized_wan_targets`. LAN `subnet_ids` become `scan_network_targets`. Site is taken only from the Agent/Site relationship. Invalid legacy LAN scans are preserved, disabled, and marked `needs_review`.

Workers execute the snapshot. Agent dispatch uses the common authorized pool, Any Available or Preferred + Failover, atomic claim, and `waiting_for_agent` / `missed`. `scan_missed_unavailable_agent` is a DomainEvent only; no alert routing.

## Phase 2B vulnerability intelligence and operational priority

`0010_cve_intelligence_priority` adds scanner-independent CVE enrichment and a transparent P1–P4 operational priority on each Asset Finding.

Sources (central backend only; no tenant, Asset, IP, hostname, or tag data is sent):

- **NVD CVE API 2.0** — CVSS, CWE, status, references. Optional `NVD_API_KEY` in environment/secrets. The Admin UI shows only whether a key is configured.
- **FIRST EPSS** daily CSV (`https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`) — exploit probability and percentile, not severity.
- **CISA KEV** JSON catalog — official known-exploited membership only. KEV is never inferred from Nuclei tags, CVSS, or EPSS.

Refresh is scheduled from the dedicated Compose `scheduler` process (not the API). Sources self-gate: EPSS daily, NVD/KEV every six hours. PostgreSQL advisory locks prevent overlapping refresh of the same source. A source outage records `last_error`, updates `last_attempt_at`, and preserves `last_success_at` plus last known-good intelligence. NVD batch updates share one transaction; a later batch failure rolls back the entire refresh, including priority projections. EPSS applies rows present in a valid file and does not treat absence as authority to clear existing scores unless completeness is proven. KEV is three-state: confirmed member, confirmed absent after a complete catalog, or unknown/not synchronized. Failed refreshes do not change finding identity or lifecycle. Vulnerability detail requires a tenant and a linked Asset Finding.

Admin endpoints:

- `GET /api/admin/vulnerability-intelligence/status`
- `POST /api/admin/vulnerability-intelligence/refresh`

Viewer is read-only and cannot refresh or change intelligence settings.

P1–P4 is **Nuclei Dashboard operational priority** (model `2b.1`), not an NVD, FIRST, or CISA risk rating. The finding detail surface shows the scored factors. Two Assets with the same CVE can have different priorities. NULL priority means not yet calculated; unknown risk is never silently labeled P4.

This product uses the NVD API but is not endorsed or certified by the NVD.

## Phase 2C treatments and compliance frameworks

`0011_phase2c_treatments_compliance` turns `AssetFinding.treatment_state` into a projection of documented treatment records. Technical state and treatment stay separate.

- **Technical state** (`open` / `resolved`) is scanner-independent lifecycle. Treatments never set `technical_state = resolved`.
- **Treatment projection** is `unaddressed` when there is no currently effective treatment.
- **Mitigation** may become active immediately when rationale is supplied. Compensating controls are optional documentation.
- **Accepted risk** and **false positive** start as `pending_review`. They do not change the projection until an Admin or User explicitly approves them. The reviewer is recorded. Separation of duties is not required.
- A finding has at most one `active` treatment. Activating a new treatment supersedes the previous active record. A pending record does not supersede an active one. A treatment whose `expires_at` is already due cannot be created or approved; it is never made `active`.
- **Revoke** and **expire** preserve history. The projection returns to `unaddressed` unless another effective treatment remains. Scheduler expiration runs every 15 minutes; GET endpoints compute `review_overdue` / `expired` display status without mutating rows. Treatment writes also expire any active row whose `expires_at` has already passed, so the persisted history records `expired` rather than `superseded` during the scheduler gap.
- **Review due** is not expiration. Past `review_due_at` with a future `expires_at` stays active and is marked review overdue.
- **Compensating controls** belong to a treatment. They are retired, not deleted.
- **Framework / Control** is a generic catalog. Framework version is part of identity (`slug` + `version`). NIST SP 800-171 Rev. 3 is bundled from the official NIST OSCAL catalog and imported offline. DoD CMMC Level 2 is **not** bundled and is **not** aliased to Rev. 3: current official CMMC Level 2 self-assessment still uses NIST SP 800-171 Rev. 2.
- Evidence objects (Asset, Asset Finding, Detection Evidence, Treatment, Scan Run) may reference controls. A mapping means related evidence only. It does **not** mean compliant, certified, implemented, or control satisfied. Asset Finding merge audits automatic mapping moves and duplicate removals.
- Admin may create/edit/archive custom frameworks and controls and import built-ins. User may manage treatments, compensating controls, and tenant evidence mappings. Viewer is read-only.
- Phase 2B P1–P4 scoring is unchanged. Treatment remains 0 priority points. `PRIORITY_MODEL_VERSION` stays `2b.1`.

Built-in catalog files live under `backend/app/data/compliance/`. Import is idempotent, transactional, and does not require live Internet access. The importer verifies the recorded control count and SHA-256 provenance checksums before applying a bundle.

## Phase 3A policy engine

`0012_policy_engine` adds UI-driven, deterministic policies. Evaluation is separate from application. Policies never change Asset correlation identity, scores, or confidence.

Categories:

- **Asset Handling** — optional `classification` and/or `disposition`.
- **Asset Inactivity** — `inactive_after_days` (mark inactive after N days without observation).
- **Finding Lifecycle** — `resolution_clean_scans` (resolve after N consecutive *applicable* clean scans).

Scope inheritance is always:

`Network > Site > Tenant > Global`

A more-specific matching rule wins for the **same action**. Priority does not let a Global rule beat a Network rule.

Within the same scope, higher integer priority wins. Equal priority uses the lowest stable PolicyRule ID.

Per-action override: a Site rule that sets only disposition leaves a broader classification in effect.

Conditions are AND. Supported fields:

- Asset: hostname (`equals`, `glob` such as `LT-*`), tag (`has` / `lacks`), criticality, expected asset, observed port.
- Finding lifecycle also: severity, operational priority (P1–P4), has CVE.

No regex, SQL, or executable expressions.

Fallbacks when no matching action exists:

- Classification: existing `infer_class` / current value.
- Disposition: current value, default `unreviewed`. Repeated observation never approves an Asset.
- Inactivity: Admin `asset_inactive_days`.
- Clean-scan resolution: Admin `finding_resolution_clean_scans`.

Those global settings are not copied into PolicyRule rows.

Authorization:

- Admin: create/edit/archive Global and scoped policies.
- User: read all; create/edit/archive Tenant/Site/Network only.
- Viewer: read only.

Automatic Asset classification/disposition changes are audited (`asset.policy_classification_changed`, `asset.policy_disposition_changed`) only when the value actually changes. Policy CRUD is audited. Viewing an evaluation does not mutate or audit.

Reconciliation of existing Assets runs on APScheduler every 20 minutes in bounded batches. It applies current rules forward; it does not invent historical values.

## Phase 3B events and alerts

Domain events are facts. Alerts are a policy-driven operational projection of those facts. AuditLog remains a separate actor/security record.

```text
Domain transition → DomainEvent + routing queue
                 → Alert Policy Resolver
                 → Dashboard Alert / Email / Webhook
```

Asset, Finding, Treatment, Scan, and Agent code emit a DomainEvent only. They do not send email, create dashboard alerts, or POST webhooks.

Supported event types:

- Asset: New Asset, Asset Became Inactive, Inactive Asset Returned, Asset Disposition Changed
- Finding: New Vulnerability / Finding, Vulnerability Resolved, Vulnerability Reopened
- Treatment: Finding Treatment Created, Finding Treatment Expired
- Scan: Scan Failed, Scan Missed — No Available Agent
- Security: Agent Identity Mismatch, WAN Target Changed, Policy Changed

Service open/closed and Agent online/offline are later coverage; current lifecycle does not yet provide a trustworthy transition.

Alert policies reuse the Phase 3A PolicyRule engine with category `alerting`. Scope remains Network > Site > Tenant > Global, resolved independently per action. Within the same scope, higher priority wins, then lowest PolicyRule ID.

Conditions are AND and require an explicit event type. Supported fields: event type, classification, disposition, criticality, tag, expected asset, finding severity, priority, has CVE, treatment state, source. No executable expressions.

Actions: severity, dashboard, email (`off` / `staff` / `admins`), webhook (`enabled` + http(s) URL, no embedded credentials), `suppress_for_minutes` (0 disables coalescing; max 30 days).

System defaults, represented as `source = system_default` rather than seeded PolicyRule rows:

- `new_asset`: dashboard yes, email staff, severity high
- `agent_identity_mismatch`: dashboard yes, email admins, severity critical

Other events notify only when a matching alert policy sets an action. A routing-history row still records why no notification occurred.

Suppression/dedupe is per tenant + event type + logical subject + route identity. It never deletes DomainEvents. An acknowledged Alert never swallows a later matching event. Coalesce/create is serialized with a transaction advisory lock on the dedupe key so concurrent routers cannot create two open Alerts for the same subject.

Disposition-change events use the AuditLog row ID as the per-transition identity. Repeating unreviewed → approved after an intervening change is a new event; retrying the same AuditLog remains idempotent.

A delivery left in `processing` after a crash becomes reclaimable after `DELIVERY_LEASE_SECONDS`. A recently claimed row is not stolen. Max-attempt rules still apply.

An `EventAlertQueue` row left in `processing` after a crash becomes reclaimable after `ALERT_QUEUE_LEASE_SECONDS` using `updated_at` (set at claim). A recently claimed row is not stolen. Max-attempt rules still apply. No extra lease column.

Event emission fail-closes on Tenant/Site/Network/Asset/Finding/Agent/ScanJob/Treatment/Policy mismatches. Scan and finding events persist trusted Site/Network from the run snapshot or that run's observation; Network is not inferred from an IP.

Upgrade never queues historical DomainEvents. Only events emitted through the Phase 3B outbox path are routed.

SMTP and webhook I/O run in a separate APScheduler delivery worker. Core domain transactions stay free of network I/O. Email and webhook retries are bounded; permanent 4xx webhook failures do not retry forever. Webhooks POST a small JSON payload of identifiers and never include secrets, enrollment material, or raw scan blobs.

Acknowledgement is audited (`alert.acknowledged`, `alert.acknowledged_all`). Repeat acknowledgement is a no-op and is not re-audited. Alerts are not physically deleted.

Read-only evaluation: `GET /api/events/{event_id}/alert-policy-evaluation`.

## Viewer / Auditor

Viewer is read-only. A Viewer may list agents and see status. A Viewer must not create/approve/revoke agents and must not download compose or env files that can contain an active enrollment secret. Admin and User remain the deployment roles.

Phase 3C adds **explicit Tenant grants** and optional **expiration**. This is fail-closed.

### Viewer Tenant scope

A Viewer may have one of:

- **No Tenant access** — default. The account can authenticate but Tenant-scoped lists, dashboards, reports, alerts, and history are empty. Direct IDs for other Tenants return 404.
- **Selected Tenants** — relational grants in `viewer_tenant_grants`. The Viewer sees exactly those Tenants.
- **All Tenants** — `viewer_all_tenants = TRUE` and no selected grant rows. The Viewer sees current and future Tenant-scoped operational data. This is **not** Admin: user management, SMTP, enrollment secrets, intelligence refresh, and `tenant_id IS NULL` global AuditLog rows remain hidden.

Ambiguous configuration (all-Tenant plus selected grants) is rejected.

If an account is changed from Viewer to Admin/User, Viewer grant state is cleared so old grants cannot reactivate later. Changing back to Viewer starts with no Tenant access until an Admin grants it again.

### Existing Viewer upgrade (0013 → 0014)

**Existing Viewer accounts are not grandfathered into all-Tenant access.**

On upgrade:

- `viewer_all_tenants = FALSE`
- no `viewer_tenant_grants` rows
- `viewer_expires_at = NULL`

The Viewer can log in but sees **no Tenant data** until an Admin assigns selected Tenants or all-Tenant access. Admin and User behavior is unchanged.

### Viewer expiration

`viewer_expires_at` is stored in UTC. `NULL` means no expiration. When `viewer_expires_at <= now(UTC)` the Viewer is expired.

Expiration is checked at login **and** on every authenticated request through current-user resolution. A JWT issued before expiration does not keep working after expiration. The API returns a clear 401 (`Viewer access has expired`). Disabled (`is_active = false`) is a separate status from Expired.

### Reports

`Reports` in the UI and `GET /api/reports/...` share one canonical report query layer. Preview, CSV, and PDF use the same filters and authorization primitive as normal Tenant reads.

Families: Executive Vulnerability Summary, Asset Inventory, New / Changed Assets, Open Vulnerabilities, Resolved Vulnerabilities, Mitigated / Accepted Risk, CVE Aging, Scan History, Agent Health, CMMC / Control Evidence.

- Preview is paginated (default 50, max 200). Preview is **not** audited.
- CSV and PDF exports create `report.export` AuditLog rows (actor, report key, format, scope, filters, generated_at). Report bodies and secrets are not stored.
- CSV uses the Python `csv` module, UTF-8, formula neutralization for cells starting with `= + - @`, and safe `Content-Disposition` filenames. Timestamps in CSV are ISO-8601 UTC.
- PDF is generated with ReportLab from the same dataset. Timestamps render in the effective Site timezone when a Site applies, otherwise the configured global timezone, and the timezone is labeled.
- CMMC / Control Evidence requires exactly one Tenant plus a Framework. It reuses generic Framework/Control/ControlReference mappings. No mapped evidence means “No mapped evidence in the application”, not “Noncompliant”. Mapped evidence means “Evidence/reference is mapped”, not “Compliant”. The existing mapping disclaimer is included. The product does not certify CMMC.
- Existing `GET /tenants/{tenant_id}/assets/export` remains as a compatibility endpoint and uses the shared CSV helper.
- Reports never include Agent enrollment secrets, passwords, JWTs, or SMTP credentials.

### Audit & Events

`Audit & Events` exposes two separate histories:

- `GET /api/audit-history` — security/admin AuditLog
- `GET /api/domain-events` — DomainEvent (does not mutate alert routing)

Both are paginated and ordered deterministically (`created_at`/`occurred_at` DESC, `id` DESC). Viewers only see permitted Tenant rows and never `tenant_id IS NULL` global Admin records.

Security-relevant Agent enrollment, approval, revocation, and deployment-material access are audited (`agent.enroll`, `agent.enroll_denied`, `agent.approve`, `agent.revoke`, `agent.deployment_material_access`). Staff login success and denial are audited (`auth.login_success`, `auth.login_denied`). Tenant create/update are audited. AuditLog details never store enrollment secrets, passwords, tokens, or rendered compose/env.

`DELETE /api/tenants/{id}` is intentionally refuse-closed (`409`) to preserve historical evidence. Physical Tenant deletion is disabled. Tenant archival is not implemented yet. Refused attempts are audited as `tenant.delete_refused`.

### Timezone

Persisted timestamps remain UTC. Report filters use UTC boundaries. CSV prefers reproducible UTC. PDF labels the display timezone.
