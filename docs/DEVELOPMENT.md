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

Current head revision: `0012_policy_engine` (after frozen `0001_baseline` through `0011_phase2c_treatments_compliance`).

`0001_baseline` through `0011_phase2c_treatments_compliance` are immutable. Phase 3A policy lives in `0012_policy_engine`; later correctness fixes belong in application code unless a new revision is truly required.

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

`post_correlation_asset_policy_hook` applies Asset Handling policy after correlation identity is resolved. Phase 1C correlation never auto-approves by observation count or age; only an explicit matching Phase 3A disposition action may set `approved`.

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

## Phase 2B vulnerability intelligence and operational priority

`0010_cve_intelligence_priority` adds scanner-independent CVE enrichment and a transparent P1–P4 operational priority on each Asset Finding.

Sources (central backend only; no tenant, Asset, IP, hostname, or tag data is sent):

- **NVD CVE API 2.0** — CVSS, CWE, status, references. Optional `NVD_API_KEY` in environment/secrets. The Admin UI shows only whether a key is configured.
- **FIRST EPSS** daily CSV (`https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`) — exploit probability and percentile, not severity.
- **CISA KEV** JSON catalog — official known-exploited membership only. KEV is never inferred from Nuclei tags, CVSS, or EPSS.

Refresh is scheduled from the existing single-process APScheduler (the Compose `api` service is one replica). Sources self-gate: EPSS daily, NVD/KEV every six hours. PostgreSQL advisory locks prevent overlapping refresh of the same source. A source outage records `last_error`, updates `last_attempt_at`, and preserves `last_success_at` plus last known-good intelligence. NVD batch updates share one transaction; a later batch failure rolls back the entire refresh, including priority projections. EPSS applies rows present in a valid file and does not treat absence as authority to clear existing scores unless completeness is proven. KEV is three-state: confirmed member, confirmed absent after a complete catalog, or unknown/not synchronized. Failed refreshes do not change finding identity or lifecycle. Vulnerability detail requires a tenant and a linked Asset Finding.

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

## Viewer / Auditor

Viewer is read-only. A Viewer may list agents and see status. A Viewer must not create/approve/revoke agents and must not download compose or env files that can contain an active enrollment secret. Admin and User remain the deployment roles.
