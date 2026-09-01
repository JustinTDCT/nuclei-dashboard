# Nuclei Dashboard — Master Architecture & Implementation Plan

**Document status:** CANONICAL SOURCE OF TRUTH  
**Plan version:** 1.0.0  
**Date:** 2026-08-18  
**Repository:** `https://github.com/JustinTDCT/nuclei-dashboard`  
**Primary implementation environment:** Cursor with Grok 4.6  
**Deployment model:** On-premises, Docker-based central server with remote Docker-based site agents over HTTPS

---

## 1. Purpose of This Document

This file is the canonical architectural and implementation source of truth for the Nuclei Dashboard project.

All implementation work must:

1. Read this file in full before making architectural changes.
2. Preserve the contracts and decisions marked **LOCKED**.
3. Work only within the currently assigned phase/tranche unless explicitly instructed otherwise.
4. Avoid speculative redesigns or “helpful” implementation of later phases.
5. Preserve existing working behavior unless the current phase explicitly replaces it.
6. Use migrations and tests for schema/behavior changes.
7. Report deviations, blockers, or discovered conflicts instead of silently changing the architecture.

### Conflict order

If instructions conflict, use this order:

1. The current explicit user instruction.
2. This `MASTER_PLAN.md`.
3. Existing tests/contracts intentionally preserved by the current phase.
4. Existing implementation behavior.
5. Model assumptions.

Do not silently alter a locked architectural decision because the current code is different.

---

# 2. Product Vision

The product is **not merely a Nuclei dashboard**.

It is a:

> Multi-tenant continuous asset discovery, vulnerability management, compliance-evidence, and alerting platform that uses Nuclei, Naabu, httpx, and potentially other scanning/detection engines.

The system must help technicians and auditors answer:

- What assets currently exist?
- What assets existed historically?
- What changed?
- What new devices appeared?
- What disappeared and later returned?
- What services are exposed?
- What vulnerabilities or security findings affect each asset?
- When was a vulnerability first seen?
- When was it last seen?
- When was it resolved?
- Did it reopen?
- Is it mitigated or accepted rather than technically fixed?
- What compensating controls apply?
- What compliance controls/evidence relate to the asset, finding, mitigation, or scan?
- What scanner/tool/template versions produced the evidence?
- Who changed a classification, policy, mitigation, scope, or other security-relevant record?

Ease of use is a core product requirement. Backend sophistication must not require technicians to understand internal architecture to perform normal work.

---

# 3. Scale Target

**LOCKED**

Design for:

- Hundreds of tenants.
- Thousands to tens of thousands of assets.
- Multiple sites per tenant.
- Multiple networks per site.
- Multiple agents per site.
- Overlapping RFC1918 address space between sites.
- Multiple scheduled and manual scans.
- Long-lived scan, asset, vulnerability, and audit history.

PostgreSQL remains the primary relational datastore unless future measured evidence demonstrates a need to change.

Do not introduce distributed databases or unnecessary infrastructure for hypothetical scale.

### Scale hardening sequence

Inserted before later product work. PostgreSQL remains. Do not introduce sharding, Kafka, microservices, or Kubernetes for these items.

- **Scale S1 — Agent/control plane.** Independent heartbeat while one scan worker runs; persistent HTTP client; lightweight heartbeat; inventory on startup/change/period; SQL-side Agent-specific job selection; poll returns the first claimable job; `SELECT Agent ... FOR UPDATE` before claim so one running job per Agent is atomic; adaptive scan-stage progress logging; httpx DIT model stubbed at image build. No schema change. Frozen baseline commit: `312e0d0`.
- **Scale S2 — Scan ingestion.** Complete / frozen. Change how ingest work is executed, not what the work means. The current Asset correlation algorithm remains authoritative. The existing Finding lifecycle remains authoritative. Raw evidence remains first-class and must still be persisted before a run can succeed. Revision `0017_security_h6_h8` is consumed by security hardening. Later S2 schema, if measured evidence requires it, starts at 0018. Split:
  - **S2A — Benchmark + semantic freeze.** Done. Repeatable PostgreSQL harness in `backend/tests/scale_s2/` measures wall-clock, SQL statement/SELECT/INSERT/UPDATE/flush counts, peak RSS, request sizes, and largest transaction duration. It freezes semantic equivalence for Assets, identifiers, addresses, services, observations, correlation decisions, Devices, Vulnerabilities, detector mappings, Findings/evidence, AssetFindings, run evaluations, Finding history, DomainEvents, Alerts, and ScanJob counters/status. Surrogate IDs and timestamps are normalized. Replay of an identical chunk must equal a single ingest.
  - **S2B — Device/Asset ingestion query collapse.** Accepted at `d9afc55` on security baseline `5aaf4fc`. `ScanIngestContext` write-through caches collapse per-report Device/Asset lookups. Correlate-then-apply and correlation meaning stay unchanged. Schema stayed at `0017_security_h6_h8`. Tenant-wide identifier/address/Device prefetch is a scale metric for later chunked ingest (S2D); do not revert to per-report queries.
  - **S2C — Finding/coverage batch resolver.** Accepted at `fa67a89` on security baseline `5aaf4fc`, directly on accepted S2B `d9afc55`. One `FindingRunIndex` per Finding/coverage/finalize batch collapses current-run observations, Devices, coverage, evidence keys, detector CVE unions, mappings, evaluations, and supporting findings. Historical CVE history is one set-based `Finding.raw_json` query for the distinct `(detector_type, detector_key)` pairs in the batch, not a per-Finding reload. `ingest_findings()` still parses identities first, skips existing evidence keys, then uses the existing catalog/upsert, current-run Device/Asset resolution, detection, and evidence paths. Priority recalculation runs once on the unique touched AssetFinding set. `store_detector_coverage()` writes through the index and flushes so replay stays idempotent. `finalize_run_lifecycle()` uses the same run-resolution model; CLEAN applicability is not weakened. Finding lifecycle meaning is unchanged. Schema stayed at `0017_security_h6_h8`; `0018` was not justified. Committed gates: Finding-stage observation/Device SELECTs `< 10`, coverage-stage coverage SELECTs `< 10`, Finding-stage findings SELECTs `< 70`, same-run replay and isolated-run equivalence, S2B Device collapse intact, no `0018_*` migration.
  - **S2D — Chunked normalized transport.** Accepted. Implementation `c59e144` on accepted S2C `fa67a89` / docs checkpoint `bc0a3ba`. Required one-record list-boundary correction `1040549`. Agent pin follow-up and live HEAD `5a5f922`, which pins generated Agents to implementation `1040549` (not the pin-bump SHA). Security baseline `5aaf4fc`. Transport only: same Device/Finding/coverage list POST bodies, hard server-side row and encoded-byte limits, Agent/scanner slices to those limits. A single record is rejected when `2 + encoded size > max_bytes` so `[record]` always fits. Evidence remains first; existing Device → Finding → coverage → complete order is preserved. Replay of any chunk is idempotent via existing observation/evidence/coverage keys. `POST /complete` remains the only successful finalization; a partial upload stays incomplete and cannot emit CLEAN. Cancel/deadline still refuse successful completion. Correlation and Finding-lifecycle meaning unchanged. Schema stayed at `0017_security_h6_h8`; `0018` was not justified. Each Finding/coverage chunk may build a fresh `FindingRunIndex`; preload count, SELECT count, wall time, and peak RSS are metrics — do not redesign S2C from this tranche. No Agent disk spooling (S2E).
  - **S2E — Agent streaming/spooling.** Accepted. Bound Agent RAM after accepted S2D chunked transport. Scanner commands, evidence interpretation, correlation, and Finding lifecycle stay untouched. Raw artifacts remain first-class. Scanner output is normalized in bounded batches into a per-job disk spool (`$AGENT_DATA_DIR/spool/jobs/{job_id}`, default `/data/spool` on LAN Agents) and uploaded with the existing S2D Device → Finding → coverage → complete order. Atomic temp→fsync→rename records; delete only after server ACK; replay of an acknowledged-but-not-deleted chunk stays harmless under S2D keys. Spool size is capped (`S2E_SPOOL_MAX_BYTES`, default 256 MiB) so memory bounding cannot become unbounded disk use. `POST /complete` with `ok=true` is refused while required chunks remain. Cancel/deadline still refuse CLEAN. Implementation `3cdb52c` (scanner-semantic correction after `ed1e87`). Generated Agents pin `3cdb52c`, not this pin-bump SHA. Required restart-resume: after process death the worker inspects local `pipeline.done` directories *before* polling queued work, asks the server whether that job is still running and owned (`GET /api/agent/jobs/{job_id}` for LAN; existing WAN job-status for central), and resumes leftover chunk upload without calling `/start`. `/start` remains queued-only; a running claimed job is not requeued. Incomplete or unowned spool is abandoned. The central scanner persists `/data` on its own `scanner-data` volume (not `agent-keys`). Spool writes use a write-all loop, file fsync, rename, and parent-directory fsync. An artifact POST failure after `pipeline.done` retains `$AGENT_DATA_DIR/spool/jobs/{job_id}/raw` until ACK. Live LAN Agent and central WAN scanner recreate/resume gates passed. Schema stayed at `0017_security_h6_h8`; `0018` was not justified. Do not materialize full `result["devices"]` / `result["findings"]` lists and then dump them to disk. S2 is complete; S3 is next.
- **Scale S3 — Central maintenance/query paths.** Agent challenge nonces live in PostgreSQL. Split:
  - **S3A — Remove startup whole-Device refresh.** Accepted at implementation `75034d7` plus concurrency correction `901f159`. API startup only `seed()`s; `refresh_discovery_metadata` is one keyset-bounded Device page (`FOR UPDATE SKIP LOCKED`) per scheduler tick. Startup Device SQL is independent of inventory size. Schema stayed at `0017_security_h6_h8`; `0018` was not created. Agent pin stayed `3cdb52c`.
  - **S3B — Scheduler process separation.** Accepted at implementation `c6ccc7f` plus leader-fencing correction `cca2ea2`. APScheduler is not in the API process. Compose service `scheduler` takes a session-level PostgreSQL advisory lock (`pg_try_advisory_lock`) and keeps proving that connection is the same backend (`pg_backend_pid`) every two seconds. Session loss stops APScheduler with `wait=True` and exits nonzero without reacquiring. Graceful SIGTERM also waits for in-flight jobs before unlocking. This is a single-active scheduler design, not a claim of zero-overlap HA under every network partition. The intended deployment is one Compose scheduler service; the lock and PID probe are fail-closed protection against accidental duplicate ownership. Job catalog and intervals stay frozen. Schema stayed at `0017_security_h6_h8`; `0018` was not created. Agent pin stayed `3cdb52c`. This tranche did not add a second API replica.
  - **S3C — EventAlertQueue stale reclaim.** Current. A queue row left `processing` after a crash is reclaimable after `ALERT_QUEUE_LEASE_SECONDS` using existing `updated_at` (set at claim). A recently claimed row is not stolen. Max-attempt rules still apply. Claim stays `FOR UPDATE SKIP LOCKED` and `ALERT_ROUTE_BATCH_SIZE`. Reclaim runs inside the existing `alert-routing` tick; the 12-job catalog is unchanged. Schema stays `0017_security_h6_h8`; `0018` is not created. Agent pin stays `3cdb52c`. This tranche does not add a second API replica.
  - Later S3: true API pagination; keyset report iteration. A deliberate multi-API replica gate only after those central work/query paths are bounded.

### Security hardening sequence

Inserted after a clean-room review of commit `312e0d0`. These are production-safety defects, not Scale work. They may be implemented without waiting for S2/S3. They must not change Finding-lifecycle meaning except to prevent an incomplete detector stage from counting as `EVALUATION_CLEAN`.

- **Sec H1 — Fail-closed detector stages.** Any non-zero Nuclei/Naabu/httpx exit is a failed stage, even when stdout is non-empty. Vulnerability-stage JSONL must fail closed: a nonblank malformed line or a row missing the minimum Nuclei schema (`template-id` plus `host` or `matched-at`) is a failed run and must not publish detector coverage. Valid positive rows from a nonzero Nuclei exit may be stored, but that invocation must carry no clean coverage. Missing findings on a failed stage must never become clean/negative evidence. Detector-coverage persist failure must fail the run.
- **Sec H2 — Deployment secrets.** Startup aborts when `SECRET_KEY`, `SCANNER_TOKEN`, or the database password is empty, a known placeholder, or reused across those control-plane credentials. `ADMIN_PASSWORD` is required only for initial bootstrap on an empty user table. Compose must not supply insecure fallbacks. Documentation is not the security control.
- **Sec H3 — Control-plane exposure.** Caddy must not publish `/api/internal`. WAN job claim must use the same atomic update pattern as LAN claim.
- **Sec H4 — WAN target safety policy.** Authorized WAN targets remain IP/CIDR/FQDN, but creation and live revalidation reject private, loopback, link-local, multicast, reserved, unspecified, cloud-metadata, IPv4-mapped/IPv4-compatible IPv6, and target sets larger than 65,536 addresses (IPv4 `/16` equivalent; IPv6 therefore `/112` or narrower). Authorized FQDNs are pinned to resolved IPs for connect/anti-rebinding; the scanner must still present the original FQDN for HTTP Host and TLS SNI and must not re-resolve the name on the worker. One pinned IP that backs several authorized names must be fanned out so each virtual host is probed and covered separately. Multi-SNI Nuclei output is retained as one combined raw artifact.
- **Sec H5 — Session revocation and SMTP secret masking.** Staff tokens are bound to the current password hash so a reset invalidates outstanding JWTs. Password and email changes are audited. `GET /admin/settings` never returns the SMTP password. An SMTP password may exist only when `SETTINGS_ENCRYPTION_KEY` is a generated Fernet key distinct from other control-plane secrets. Startup migrates leftover plaintext and refuses a missing or wrong key.
- **Sec H6 — Agent supply chain.** Generated Agent builds pin a 40-character commit SHA. Tags and branch refs are rejected; the API does not ship `git` and does not resolve tags. Image construction SHA-256-verifies every Nuclei/Naabu/httpx/templates archive and fails closed on mismatch. LAN Agents keep `network_mode: host` for site RFC1918 reachability and run as uid 1000 with `cap_drop: ALL` plus `NET_RAW` for Naabu SYN/host-discovery. `privileged: true` is forbidden and `no-new-privileges` is set. The WAN scanner uses the same user/capability set on the Docker bridge.
- **Sec H7 — Scanner deadlines.** Jobs receive `deadline_at` at claim. Expiry first sets `cancel_requested_at`; workers SIGTERM the process group, then SIGKILL after a short grace. Partial evidence may still persist. Successful completion and `EVALUATION_CLEAN` are refused for cancelled/expired runs. After cancel grace the control plane force-marks `cancelled`.
- **Sec H8 — Auth edge and challenge DoS.** Login is rate-limited and lockout-backed in PostgreSQL with an atomic UPSERT plus `SELECT ... FOR UPDATE`; lockout is committed before 429. The API and Caddy emit CSP/HSTS/frame/nosniff headers. Staff bearer tokens live in `sessionStorage`, not `localStorage`. Agent challenges are durable multi-record, single-use, expiring rows with creation rate limits. MFA remains deferred.
- **Sec H9 — Horizontal API scale remains later S3 work.** Challenge nonces live in PostgreSQL. APScheduler ownership moved to the dedicated scheduler process in S3B, so API replicas no longer start duplicate schedulers. S3C does not add a second API replica.

---

# 4. Current High-Level Architecture

The existing project already has a useful foundation:

- Docker Compose central deployment.
- Caddy for HTTPS/reverse proxy.
- FastAPI backend.
- PostgreSQL.
- React frontend.
- Central WAN scanner runtime.
- Remote LAN/site agent runtime.
- Nuclei / Naabu / httpx-based scanning.
- User roles.
- Tenants.
- Subnets.
- Agents.
- Scans and scan jobs.
- Devices.
- Findings.
- Alerts.
- Scheduler.

The project should be **evolved**, not restarted.

Existing concepts will be migrated toward the canonical domain model below in controlled phases.

---

# 5. Canonical Domain Hierarchy

**LOCKED**

```text
System
│
├── Users
│   ├── Admin
│   ├── User
│   └── Viewer / Auditor
│
├── Global Settings
│
├── Compliance Frameworks
│   └── Controls
│
└── Tenant
    │
    ├── Sites
    │   ├── Networks
    │   └── Agent Pool
    │
    ├── Authorized WAN Targets
    │
    ├── Assets
    │   ├── Identifiers
    │   ├── Addresses
    │   ├── Services
    │   ├── Tags
    │   └── Observations
    │
    ├── Vulnerabilities / Findings
    │   ├── Detection Evidence
    │   ├── Lifecycle History
    │   ├── Treatment
    │   ├── Mitigations / Risk Acceptance
    │   └── Control References
    │
    ├── Scan Definitions
    │   ├── Stages
    │   ├── Target Scope
    │   ├── Exclusions
    │   ├── Intensity
    │   └── Schedule
    │
    ├── Policies
    │
    ├── Events / Alerts
    │
    └── Audit History
```

---

# 6. Time and Timezone Contract

**LOCKED**

- All persisted timestamps are stored in UTC.
- The system has a global default timezone configured by an Admin.
- Each Site may optionally override the global timezone.
- UI display converts UTC timestamps to the effective timezone.
- Schedules use the Site timezone when a Site applies; otherwise use the configured global timezone.
- Do not persist local-time timestamps as authoritative timestamps.
- Timezone values should use IANA timezone identifiers where possible, e.g. `America/New_York`.

---

# 7. Users, Roles, and Access

## 7.1 Roles

**LOCKED**

### Admin

May:

- Change system-level settings.
- Create/manage users.
- Configure global policies.
- Manage tenants/sites/networks/scans/agents.
- Configure compliance frameworks/controls.
- Configure system-level retention and scanning limits.
- Perform all User actions.

### User

Internal operational staff.

May:

- Create/manage tenants.
- Create/manage sites and networks.
- Create/manage authorized WAN targets.
- Create/manage scans.
- Deploy/approve/manage agents as allowed by policy.
- Classify and manage assets.
- Manage findings, mitigations, accepted risk, and controls.
- Acknowledge/manage alerts.
- Produce reports.

### Viewer / Auditor

Read-only.

May:

- View only data explicitly within granted scope.
- Be restricted to selected tenants.
- Have an account expiration date.
- View and export permitted reports/evidence.

Must not:

- Modify records.
- Create scans.
- Deploy agents.
- Approve agents.
- Retrieve agent enrollment secrets.
- Retrieve deployment material containing active enrollment secrets.
- Change policies, settings, findings, mitigations, classifications, or controls.

## 7.2 Auditor scoping

**LOCKED**

Viewer accounts must support:

- All-tenant access when explicitly granted.
- Selected-tenant access.
- Optional expiration date/time.

Tenant restrictions must be enforced server-side, not only hidden in the UI.

---

# 8. Tenant, Site, and Network Model

## 8.1 Tenant

A Tenant represents a managed client/customer environment.

## 8.2 Site

**LOCKED**

A Tenant may have multiple Sites.

A Site:

- Belongs to exactly one Tenant.
- May contain multiple Networks.
- May contain multiple Agents.
- May define a timezone override.
- May have tags.
- Is the primary locality boundary for LAN asset identity and agent dispatch.

Sites solve overlapping-address-space scenarios such as:

```text
Tenant A
  Site Boston     192.168.1.0/24
  Site Hartford   192.168.1.0/24
```

These are distinct networks because they belong to different Sites.

## 8.3 Network

**LOCKED**

A Network:

- Belongs to a Site.
- Has one or more CIDR/range definitions as supported by the implementation.
- Has a LAN role/scope.
- May have tags.
- May have scan exclusions.
- Has explicitly authorized Agents/Agent Pools.
- Must not be identified globally by CIDR alone.

---

# 9. WAN Target Authorization

**LOCKED**

WAN scans must only run against targets registered as authorized scope for that Tenant.

Supported WAN target types:

- IP address.
- CIDR.
- FQDN.

A scan definition references authorized WAN target records. It must not be able to bypass scope controls by supplying arbitrary Internet targets directly to a worker.

Target creation/change must be audited.

The backend and scanner must fail closed if a requested WAN target is outside the authorized target set.

This is a safety and accountability boundary.

Authorized WAN targets must also pass a safety policy: no private, loopback, link-local, multicast, reserved, unspecified, cloud-metadata, or IPv4-mapped/IPv4-compatible IPv6 addresses, and no target set larger than 65,536 addresses (IPv4 `/16` equivalent; IPv6 `/112` or narrower). Syntax validation and authorization remain separate from that policy. An authorized FQDN is executed as a pinned connect address plus the original hostname for Host/SNI; workers must not resolve the FQDN again.

Future domain/subdomain discovery may be added, but it must not silently expand authorized scope without explicit policy.

---

# 10. Agent Architecture

## 10.1 Deployment

**LOCKED**

- Agents are Docker-based.
- Agents communicate outbound to the central server over HTTPS.
- No inbound connectivity to the site agent should be required for normal operation.
- A technician can generate/download deployment configuration from the central system.
- Agent deployment must remain easy for field technicians.

## 10.2 Enrollment and identity

The existing design is directionally correct and should be preserved/evolved:

1. Central creates Agent identity and UUID.
2. Central creates a one-time enrollment secret.
3. Agent generates a local asymmetric keypair.
4. Agent enrolls using UUID + enrollment secret + public key.
5. Central places Agent into pending approval.
6. Authorized staff approve the Agent.
7. Enrollment secret is invalidated/removed.
8. Future authentication requires proof of possession of the bound private key.
9. Central issues short-lived authenticated session/token material after successful proof.

**LOCKED**

The UUID is an identifier, not the permanent authentication secret.

## 10.3 Non-portability / clone detection

A software key stored in a Docker volume is key-bound rather than true hardware-bound identity.

V1 should preserve public-key binding and support detection/evidence such as:

- Agent public key.
- Agent instance identifier.
- Hostname.
- Last source IP.
- Site.
- Agent version.
- Concurrent-session anomalies.
- Identity mismatch events.

TPM-backed keys may be considered later but are not required for initial implementation.

## 10.4 TLS

**LOCKED**

Production defaults must verify central-server TLS.

`TLS_VERIFY=0` / equivalent must not be the production default.

Support:

- Publicly trusted certificates, or
- Explicitly trusted internal CA material.

TLS verification bypass may exist only as an explicit development/testing option with clear warning semantics.

## 10.5 Agent Pools

**LOCKED**

A Site may contain multiple Agents.

Networks/scan targets may permit multiple eligible Agents.

Dispatch modes:

1. **Any Available**
   - Any healthy authorized Agent may claim/receive the job.

2. **Preferred + Failover**
   - A preferred Agent is attempted first.
   - An authorized healthy secondary Agent may execute if preferred is unavailable.

An Asset does **not** belong to an Agent.

Observations record which Agent observed the Asset.

## 10.6 Offline behavior

**LOCKED**

If all eligible Agents are unavailable:

- Job enters a waiting state rather than immediately failing.
- Wait period is configurable.
- If an eligible Agent returns before expiry, job may run.
- If wait period expires, job becomes missed/failed according to implementation semantics.
- An alert/event is generated as appropriate.

---

# 11. Asset Model

## 11.1 Core principle

**LOCKED**

An Asset is a persistent logical device/system identity.

An IP address is not the Asset.

A hostname is not necessarily the Asset.

An Agent is not the Asset owner.

An Asset primarily belongs to a Tenant and Site and accumulates observations and identifiers over time.

## 11.2 Asset identifiers

The model must support multiple identifiers/evidence types, including where available:

- MAC address.
- MAC vendor/OUI-derived data.
- IPv4 address.
- IPv6 address.
- Hostname.
- FQDN.
- DNS names.
- TLS certificate names.
- Service/banner-derived names.
- Serial number/device identifier when future scanners provide it.
- Other detector-specific identifiers as extensible typed identifiers.

Identifier records should retain provenance and observation timing where useful.

## 11.3 Address history

**LOCKED**

IP addresses are historical attributes.

The system must be able to represent:

- An Asset moving to a new IP.
- DHCP address reuse.
- Multiple current IPs for a multi-homed Asset.
- IPv4/IPv6.
- Multiple assets historically using the same IP at different times.

Do not permanently equate `(tenant, IP)` with device identity.

## 11.4 Services

Assets may have observed services:

- Port.
- Protocol.
- Service/product.
- Version when known.
- TLS metadata.
- Web title.
- Technology fingerprint.
- First seen.
- Last seen.
- Current/historical state.

Service changes should be capable of producing events later.

## 11.5 Asset observations

Each scan run may create observations containing facts such as:

- Observed timestamp.
- Site.
- Network.
- Agent or central scanner.
- IP/MAC/hostname.
- Ports/services.
- Fingerprints.
- Scanner provenance.
- Raw evidence reference.

Observations are historical evidence and should not be overwritten as if they were only current-state rows.

## 11.6 Asset lifecycle vs disposition

**LOCKED**

These are separate concepts.

### Lifecycle state

Examples:

- Active.
- Inactive / Archived.

Lifecycle describes whether the Asset is currently being observed.

### Disposition

Examples:

- Unreviewed.
- Approved.
- Unauthorized.
- Ignored.

Disposition is a security/operational decision.

A device repeatedly appearing must **not** automatically become Approved simply because it has been seen multiple times.

## 11.7 Inactivity/archive

**LOCKED**

- Admin setting defines default inactivity threshold in days.
- Policy/tenant/site overrides may be added according to the policy model.
- When threshold is exceeded, Asset becomes Inactive/Archived.
- Data is not physically moved or deleted.
- Historical identifiers, observations, findings, and audit records remain.
- If observed again, the same Asset should reactivate when correlation is sufficiently confident.
- Reactivation generates a `previously_inactive_asset_returned` event.
- Original first-seen history remains unchanged.

## 11.8 Expected/manual assets

**LOCKED**

Authorized technicians may create an expected Asset before discovery.

Example:

```text
Expected Asset:
  Name: DC01
  Site: HQ
  Expected hostname: dc01.example.local
  Expected MAC: ...
  Expected IP: 10.1.1.10
  State: Expected / Not Yet Observed
```

Discovery should attempt to correlate observations to expected Assets.

## 11.9 Correlation and conflict operations

**LOCKED**

Correlation must use multiple identity signals and confidence rather than simplistic IP-only matching.

The UI must eventually support audited actions:

- Merge Assets.
- Split Asset.
- Mark/correct an identifier.
- Move Asset to another Site where authorized.
- Associate an observation with the correct Asset.

Every manual correlation operation must be audited.

## 11.10 Tags

**LOCKED**

Tags are foundational and should be generic.

Examples:

- Production.
- CUI.
- DMZ.
- OT.
- Guest.
- Management.
- Domain Controller.
- Critical system.
- Accounting.

Tags may apply to assets, sites, networks, and other useful domain objects.

Policies may match tags.

## 11.11 Asset criticality

**LOCKED**

Assets support criticality:

- Low.
- Normal.
- High.
- Critical.

Criticality may be assigned manually or by policy.

It is separate from vulnerability severity.

---

# 12. Policy Engine

## 12.1 Purpose

The system must favor UI-driven policy configuration rather than code/config-file editing for ordinary administrators.

## 12.2 Scope/inheritance

**LOCKED**

Policies may apply at:

1. Global.
2. Tenant.
3. Site.
4. Network.

More-specific scope can override broader defaults according to explicit rule semantics.

Rules should also support explicit priority/order so behavior is deterministic.

## 12.3 Initial policy categories

Planned categories include:

- Asset classification.
- Asset disposition/auto-approval.
- Asset inactivity/archive.
- Alerting.
- Finding resolution defaults.
- Risk/treatment review behavior.
- Scan restrictions/limits where appropriate.

Example:

```text
IF
  Site = Hartford
  AND MAC vendor = Dell
  AND hostname matches "LT-*"

THEN
  Classification = Workstation
  Disposition = Approved
  New-device alert = Suppress
```

Fallback example:

```text
IF
  no approval policy matches

THEN
  Disposition = Unreviewed
  Alert = High
```

Policy execution must be deterministic, explainable, and auditable.

---

# 13. Scan Model

## 13.1 Scan definition vs scan run

**LOCKED**

Separate:

- **Scan Definition**: reusable configured intent and schedule.
- **Scan Run / Job**: one execution instance with immutable execution metadata/evidence.

## 13.2 Stage-based scan builder

**LOCKED**

The scan UI should expose independently configurable stages.

### Discovery

- Enabled/disabled.
- LAN/WAN context as applicable.

### Port Discovery

Modes:

- None.
- Common.
- Deep.
- Custom.

Custom mode accepts explicit ports/ranges.

### Service Identification / Fingerprinting

- Enabled/disabled.

### Vulnerability Scanning

- Enabled/disabled.
- Nuclei is an initial engine.
- Architecture must not permanently couple finding identity to Nuclei.

## 13.3 Intensity

**LOCKED**

Friendly presets:

- Low.
- Normal.
- High.
- Custom.

Underlying controls may include:

- Packet/request rate.
- Parallel hosts.
- Nuclei concurrency.
- Timeouts.
- Retries.
- Tool-specific concurrency/rate settings.

Admins may define global maximums that Users cannot exceed.

## 13.4 Scan exclusions

**LOCKED**

Exclusions are required.

Possible exclusion scopes:

- Global.
- Tenant.
- Site.
- Network.
- Individual scan.

Supported forms should include practical combinations of:

- IP.
- CIDR.
- Range.

Exclusions must be enforced server-side and/or by the executing scanner/agent, not merely hidden in the UI.

Fail closed when scope/exclusion validation is ambiguous.

## 13.5 Scheduling

**LOCKED**

Move beyond `interval_minutes` to proper schedules supporting patterns such as:

- Daily at a specific time.
- Weekly.
- Monthly.
- Cron-like schedules where appropriate.

Schedules honor the effective timezone contract.

## 13.6 Maintenance/blackout windows

**DEFERRED**

Do not build in early phases unless explicitly requested.

Future support may include:

- Allowed scan windows.
- Blackout periods.

## 13.7 Authenticated scanning

**DEFERRED**

Do not implement in V1 foundation phases.

Architecture should permit future credential sets for:

- Windows.
- SSH.
- SNMP.
- HTTP/API.
- VMware.
- Network devices.

Future secrets must be encrypted at rest, access-controlled, audited, and rotatable.

## 13.8 WAN scope safety

A scan run must never receive arbitrary WAN targets that bypass Tenant authorized target records. Authorized CIDRs are also bounded by address cardinality, not family-specific prefix constants. IPv4-mapped IPv6 (`::ffff:0:0/96` and embedded addresses) is rejected entirely. FQDN execution keeps two facts: the authorized logical name, and the pinned connect IP used only for the TCP/TLS connection.

## 13.9 Scanner version provenance

Every Scan Run must eventually record:

- Agent/worker version.
- Nuclei version.
- Nuclei template version/commit/release.
- Naabu version.
- httpx version.
- Scan profile/config revision.
- Relevant runtime flags/config.

---

# 14. Scanner and Template Release Management

**LOCKED DIRECTION**

Do not depend indefinitely on agents silently installing arbitrary `latest` releases at build/run time.

Move toward centrally tracked/pinned approved versions.

Initial goal:

- Central knows desired/approved scanner runtime release.
- Agent reports installed runtime/tool versions.
- UI/API can indicate mismatch/update availability.
- Scan Runs record actual versions used.

Future update channels may include:

- Stable.
- Testing.
- Pinned.

Do not build a full auto-update system until explicitly phased.

---

# 15. Raw Scan Evidence

**LOCKED**

Preserve both:

1. Normalized searchable data in PostgreSQL.
2. Raw scanner evidence/artifacts.

Raw artifacts may include compressed JSONL or other native output.

Recommended default direction:

- Normalized historical data: retained indefinitely unless explicit future retention policy changes.
- Raw scan artifacts: default one-year retention.
- Raw retention: Admin-configurable.

Raw evidence must be associated with the Scan Run and include provenance/version metadata.

Implementation may use filesystem/object-style storage appropriate for on-prem deployment, but must not store arbitrarily huge raw blobs directly in normal relational rows without justification.

---

# 16. Vulnerability / Finding Architecture

## 16.1 Finding independence from Nuclei

**LOCKED**

Nuclei is a detector, not the canonical identity of a vulnerability.

The system must support multiple detection sources.

## 16.2 Vulnerability catalog

**LOCKED**

Create a central catalog abstraction where applicable.

A Vulnerability may contain:

- CVE ID when present.
- Title.
- Description.
- CWE.
- CVSS data.
- References.
- KEV status/data.
- EPSS data.
- Other normalized vulnerability intelligence.

Not every finding has a CVE.

Non-CVE findings such as:

- Exposed admin interface.
- Weak configuration.
- Information disclosure.
- Default credential exposure indicator.
- Outdated software.
- Security header/configuration issue.

must still participate in the same lifecycle framework.

## 16.3 Asset vulnerability / finding instance

Conceptually:

```text
Asset
  └── Asset Finding / Asset Vulnerability
        ├── Finding identity
        ├── First seen
        ├── Last seen
        ├── Technical state
        ├── Treatment
        └── Detection evidence
```

Multiple detection engines may support the same Asset Finding.

## 16.4 Detection evidence

Examples:

- Nuclei template.
- Future scanner.
- Manual confirmation.
- Raw scan evidence.
- Service evidence.

Do not create duplicate logical vulnerabilities simply because multiple engines detected them.

## 16.5 Technical state vs treatment

**LOCKED**

Keep them separate.

### Technical state

At minimum:

- Open.
- Resolved.

Reopened is a lifecycle transition/history event that returns the technical state to Open.

### Treatment

At minimum:

- Unaddressed.
- Mitigated.
- Accepted Risk.
- False Positive.

Example:

```text
Technical State: OPEN
Treatment: MITIGATED
```

means the underlying technical condition still exists, but a compensating control is documented.

Do not mark something technically resolved merely because it has a treatment.

## 16.6 Resolution rule

**LOCKED**

Do not immediately resolve a vulnerability after a single scan that fails to detect it.

Default concept:

```text
Resolve after 2 consecutive successful applicable scans
without detection
```

This threshold is configurable.

Manual resolution may be supported with audit history.

A future positive detection after resolution:

- Reopens the finding.
- Records a reopen transition/event.
- Preserves the original first-seen date and complete lifecycle history.

Applicability matters: a scan that did not actually test the relevant detector/target must not count as a clean confirmation.

## 16.7 Mitigations / risk acceptance

Records may include:

- Treatment type.
- Rationale.
- Compensating controls.
- Evidence/notes.
- Created by.
- Approved/reviewed by where applicable.
- Created date.
- Review date.
- Expiration date.
- Attachments/references in future.
- Related compliance controls.

Expired treatments should be visible/actionable; they must not silently remain considered valid forever.

---

# 17. Vulnerability Intelligence and Risk Priority

## 17.1 Intelligence

**LOCKED DIRECTION**

Where CVEs exist, support normalized enrichment such as:

- CVSS.
- CWE.
- EPSS.
- CISA KEV / known-exploited status.
- References.

External intelligence updates must retain source/update timestamps.

## 17.2 Risk priority

**LOCKED**

The platform should derive a transparent operational priority, e.g.:

- P1 — Immediate.
- P2 — High.
- P3 — Normal.
- P4 — Low.

Possible factors:

- Vulnerability severity/CVSS.
- EPSS.
- KEV status.
- Asset criticality.
- Internet exposure.
- CUI or other relevant tags.
- Finding age.
- Treatment/mitigating controls.

The factors and result must be explainable.

Do not create a mysterious black-box or “AI” score that cannot be justified to a technician or auditor.

---

# 18. Compliance Model

## 18.1 Generic framework architecture

**LOCKED**

Do not hardcode the domain model solely around CMMC.

Support generic:

```text
Framework
  └── Control
```

Initial/future frameworks may include:

- CMMC / NIST SP 800-171.
- NIST CSF.
- CIS.
- ISO 27001.
- Other frameworks.

## 18.2 Evidence/control references

**LOCKED**

Design so evidence-bearing objects can reference controls.

Examples:

- Assets.
- Findings.
- Mitigations.
- Risk acceptances.
- Scan Runs.
- Reports/evidence records.
- Policies where useful.

This allows a future auditor to trace:

```text
Control
  ↓
Evidence
  ↓
Asset / Scan / Finding / Mitigation
```

## 18.3 CMMC

CMMC/NIST SP 800-171 support may be introduced early where reasonable, but the underlying schema remains generic.

Do not claim compliance or certification solely because the application contains evidence/control mappings.

---

# 19. Events and Alerts

## 19.1 Event-first design

**LOCKED DIRECTION**

Use domain events as the foundation rather than scattering notification logic throughout unrelated functions.

Potential event types:

- New Asset.
- Previously inactive Asset returned.
- Asset became inactive.
- Asset disposition changed.
- New service/open port.
- Service/port disappeared.
- New vulnerability/finding.
- Critical vulnerability.
- Vulnerability resolved.
- Vulnerability reopened.
- Treatment created/expired.
- Agent offline.
- Agent online.
- Agent identity/key mismatch.
- Concurrent Agent identity anomaly.
- Scan failed.
- Scan missed due to unavailable Agent.
- WAN target created/changed/removed.
- Policy changed.

## 19.2 Alert policy scope

**LOCKED**

Alert policies support:

- Global.
- Tenant.
- Site.
- Network.

## 19.3 Alert actions

Initial/roadmap:

- Dashboard/in-app.
- Email.
- Webhook.
- Microsoft Teams later.

## 19.4 UI-driven rule builder

Example:

```text
WHEN:
  New Asset

WHERE:
  Site = HQ
  Classification = Unknown

THEN:
  Severity = High
  Dashboard = Yes
  Email = Yes
  Webhook = Yes
  Suppress duplicate alert for 24h
```

Policies must be deterministic and auditable.

---

# 20. Audit Log

**LOCKED**

Security-relevant and administrative actions must be recorded.

Examples:

- Login/security-relevant account actions where appropriate.
- User created/modified/disabled.
- Viewer scope/expiration changed.
- Tenant created/changed/archived.
- Site/network created/changed/archived.
- WAN target changed.
- Agent created/enrolled/approved/revoked.
- Agent deployment secret material generated/accessed where appropriate.
- Scan definition created/changed/deleted/archived.
- Manual scan run initiated.
- Policy changed.
- Asset manually created.
- Asset merged/split/moved.
- Identifier corrected.
- Classification/disposition changed.
- Criticality/tags changed.
- Finding manually resolved/reopened.
- Treatment/mitigation/risk acceptance created/changed/expired.
- Compliance control/evidence mappings changed.
- Report/evidence export where useful.

Audit records should be append-oriented and difficult to accidentally mutate.

At minimum capture:

- Actor.
- Action.
- Object type/id.
- Tenant/site scope when relevant.
- UTC timestamp.
- Before/after or structured details as appropriate.
- Source/context where appropriate.

---

# 21. Archive / Deletion Policy

**LOCKED**

Preserve historical integrity.

For important historical/security objects, prefer:

- Archive.
- Disable.
- Soft delete.

over destructive physical deletion.

Particularly preserve:

- Assets.
- Sites.
- Networks.
- Vulnerabilities/findings.
- Mitigations.
- Scan definitions/runs.
- Audit history.

Physical deletion may exist for narrowly defined administrative/privacy maintenance cases later, but should not be the normal technician workflow.

---

# 22. Reporting

**LOCKED INITIAL REPORT TARGETS**

Initial report families:

1. Executive Vulnerability Summary.
2. Asset Inventory.
3. New / Changed Devices.
4. Open Vulnerabilities.
5. Resolved Vulnerabilities.
6. Mitigated / Accepted Risk.
7. CVE Aging.
8. Scan History.
9. Agent Health.
10. CMMC / Control Evidence Report.

Outputs:

- UI views.
- PDF where appropriate.
- CSV where tabular export is appropriate.

Viewer/Auditor permissions must be respected in report generation and export.

Reports must use historical lifecycle semantics accurately; do not infer “resolved” or “approved” merely from absence or age.

---

# 23. Security and Safety Invariants

**LOCKED**

1. HTTPS is required for remote Agent communications.
2. Production TLS verification defaults ON.
3. UUID alone is not sufficient permanent Agent authentication.
4. Approved Agent public-key binding must be enforced.
5. Enrollment secrets are one-time/temporary and invalidated after approval.
6. Viewer accounts may never retrieve active enrollment secrets.
7. Tenant authorization is enforced server-side.
8. WAN scans can only run against authorized Tenant WAN targets.
9. LAN jobs can only run through Agents authorized for the relevant Site/Network.
10. Scan exclusions are enforced by backend/worker execution, not only by UI.
11. Scan intensity obeys Admin maximums.
12. Secrets must not be written to logs.
13. Security-relevant state changes are audited.
14. Cross-tenant object references must fail closed.
15. Raw scan evidence and reports must respect tenant permissions.
16. Tool/runtime versions must be captured for evidence reproducibility.
17. No future feature should weaken these invariants without an explicit architecture decision.

---

# 24. Database and Migration Policy

## 24.1 PostgreSQL

**LOCKED**

Continue using PostgreSQL.

## 24.2 Migrations

**LOCKED**

Move from ad-hoc runtime schema mutation toward a real migration framework, using Alembic unless repository inspection reveals a compelling incompatibility.

Required end state:

- Schema changes are versioned.
- Fresh database can be built deterministically to current head.
- Existing supported installation can upgrade without data loss.
- Migration behavior is testable.
- Application startup does not become the place where arbitrary future `ALTER TABLE` statements accumulate.
- Migration files are reviewed like code.

Do not delete current compatibility/bootstrap logic until an upgrade path for existing databases is proven.

## 24.3 IDs and indexes

Use database IDs and indexes appropriate to expected access patterns.

Tenant/site scoping columns should be indexed where query patterns require them.

Do not prematurely introduce exotic partitioning/sharding.

---

# 25. API and Domain Design Guidelines

1. Tenant/site authorization is part of backend query semantics.
2. Do not trust frontend filtering for security.
3. Prefer stable IDs over names as references.
4. Do not store foreign-key ID lists in JSON when a relational association is semantically required, unless there is a documented reason.
5. Keep immutable Scan Run execution metadata distinct from editable Scan Definitions.
6. Keep current state projections distinct from historical observations/evidence.
7. Keep technical state distinct from human treatment/disposition.
8. Avoid hidden state transitions.
9. Use explicit enums/constants/domain validation for important statuses.
10. Return explainable errors for invalid cross-scope relationships.

---

# 26. UX Principles

**LOCKED**

The entire system must be easy to use.

Technicians should not need to understand:

- Database schemas.
- Nuclei flags.
- Agent cryptography.
- Cron syntax.
- Correlation algorithms.
- Compliance schema internals.

where a safe UI abstraction can be provided.

Examples:

- Scan intensity: Low / Normal / High / Custom.
- Port discovery: None / Common / Deep / Custom.
- Agent dispatch: Any Available / Preferred + Failover.
- Policy builder: WHEN / WHERE / THEN.
- Finding treatment: clear operational choices with required documentation.
- Timezone selectors: human-readable IANA zones.
- Asset merge/split workflows: guided and auditable.

Advanced details may be available without making them mandatory for common workflows.

---

# 27. Deferred Features / Explicit Non-Goals for Early Phases

Do not implement these merely because they are mentioned in the roadmap.

### Deferred

- Maintenance/blackout scan windows.
- Authenticated/credentialed scanning.
- Microsoft Teams integration.
- TPM-backed Agent identity.
- Full Agent auto-update service/rings.
- SSO/MFA unless explicitly scheduled.
- Complex external subdomain-discovery authorization.
- Distributed databases.
- Microservice decomposition for its own sake.

### Future-friendly design is allowed

Interfaces/schema may leave clean extension points, but no large speculative implementation.

---

# 28. Phased Implementation Plan

## Phase 0 — Architecture Foundation and Migration Safety

### Goal

Make the repository safe for substantial schema evolution without redesigning the functional domain yet.

### Scope

- Verify current repository baseline and existing behavior.
- Establish this `MASTER_PLAN.md` as canonical architecture guidance.
- Add/establish Alembic migration framework.
- Create a safe path for both:
  - fresh database creation, and
  - existing current-schema database adoption/upgrade.
- Stop future ad-hoc migration growth in normal application startup.
- Preserve compatibility until migration coverage is proven.
- Add migration tests/smoke tests.
- Document migration commands and upgrade procedure.
- Add foundational domain constants/enums only where needed to stabilize existing behavior; do not perform Phase 1 schema redesign.
- Fix immediate security boundary issues that are independent of later schema redesign:
  - Viewer must not download deployment material containing active enrollment secret.
  - Production/default generated Agent configuration should verify TLS.
- Add/strengthen tests for those security boundaries.
- Add a concise architecture/development note pointing contributors to this file rather than duplicating its contents.

### Must NOT do

- No Site model yet unless required solely for migration bootstrap, which should be avoided.
- No Asset schema redesign.
- No vulnerability lifecycle redesign.
- No new policy engine.
- No new scan-stage UI.
- No reporting implementation.
- No large frontend redesign.
- No agent pool implementation.
- No broad “cleanup” unrelated to Phase 0.

### Phase 0 acceptance gates

1. Existing working features remain functional.
2. Existing test suite passes.
3. New migration tests pass.
4. Fresh PostgreSQL database can reach migration head deterministically.
5. Existing current-schema database can be safely adopted/upgraded without destructive data loss.
6. Future schema evolution has an explicit migration workflow.
7. Viewer cannot retrieve active agent enrollment secret/deployment material.
8. Generated/default production Agent TLS verification is enabled.
9. No unrelated Phase 1+ features are introduced.
10. Cursor produces a closure report with exact files changed, tests run, migration commands, and remaining risks.

---

## Phase 1A — Tenant → Site → Network and Agent Authorization

### Goal

Introduce the locality model required for overlapping networks and multi-Agent sites.

### Scope

- Site entity.
- Site timezone override.
- Network entity replacing/evolving direct Tenant subnet semantics.
- Network-to-Agent authorization.
- Multiple Agents per Site.
- Dispatch mode foundation:
  - Any Available.
  - Preferred + Failover.
- Safe migration of existing Tenant/Subnet/Agent data.
- Preserve existing scans through compatibility/migration strategy.

### Acceptance themes

- Overlapping CIDRs between Sites are valid.
- Cross-Tenant/Site references fail closed.
- Existing data migrates without loss.
- UI exposes Site/Network concepts simply.
- No asset correlation redesign yet beyond compatibility needs.

---

## Phase 1B — Persistent Asset, Identifier, Address, Service, Observation Model

### Goal

Replace device-as-hostname/IP semantics with persistent Asset identity and historical observations.

### Scope

- Asset.
- AssetIdentifier.
- AssetAddress/history.
- AssetService/history.
- AssetObservation.
- Tags.
- Criticality.
- Lifecycle vs disposition.
- Expected/manual Assets.
- Compatibility/migration from current Device rows.

### Acceptance themes

- Same IP reused by different Assets is representable.
- One Asset may have multiple addresses.
- Observations are historical.
- Assets belong to Site, not Agent.
- Current-state views remain efficient.

---

## Phase 1C — Asset Correlation and Lifecycle

### Goal

Correlate observations into Assets safely and audibly.

### Scope

- Multi-signal correlation engine.
- Confidence/evidence.
- Policy-driven auto-approval/classification hooks.
- Merge.
- Split.
- Identifier correction.
- Move Asset.
- Inactive/archive.
- Reactivation.
- New/reappeared events.

### Acceptance themes

- Repeated observation does not auto-approve by age alone.
- DHCP/reused-IP scenarios do not incorrectly merge.
- Manual corrections are audited.
- Reactivation preserves original history.

---

## Phase 1D — Scan Definition / Stage Redesign

### Goal

Provide safe, configurable scan construction.

### Scope

- Scan Definition vs Scan Run.
- Stage configuration.
- Discovery.
- Port modes.
- Fingerprinting.
- Vulnerability stage.
- Intensity.
- Admin maximums.
- Exclusions.
- Proper schedules/timezone behavior.
- Agent dispatch/wait/failover behavior.
- WAN target authorization enforcement.
- Execution config snapshot per Scan Run.

### Deferred from this phase unless separately approved

- Maintenance windows.
- Authenticated scans.

---

## Phase 2A — Vulnerability Catalog and Finding Lifecycle

### Goal

Create scanner-independent finding identity and lifecycle.

### Scope

- Vulnerability/finding catalog abstraction.
- Asset Finding.
- Detection Evidence.
- First/last seen.
- Consecutive clean-scan resolution.
- Resolved/reopened history.
- Technical state vs treatment.

---

## Phase 2B — CVE Intelligence and Risk Priority

### Scope

- CVSS.
- EPSS.
- KEV.
- CWE.
- Source/update metadata.
- Transparent P1–P4 priority.

---

## Phase 2C — Mitigations, Risk Acceptance, Compliance Frameworks/Controls

### Scope

- Mitigation records.
- Accepted risk.
- False positive treatment.
- Review/expiration.
- Compensating controls.
- Generic Framework/Control model.
- Control references from evidence-bearing objects.
- Initial CMMC/NIST SP 800-171 support where appropriate.

---

## Phase 3A — Policy Engine

### Scope

- Global/Tenant/Site/Network policy scope.
- Explicit priority/inheritance.
- Asset classification/disposition rules.
- Archive rules.
- Finding lifecycle defaults.
- UI policy builder.

---

## Phase 3B — Event and Alert Engine

### Scope

- Domain event persistence.
- Alert policies.
- Dashboard.
- Email.
- Webhook.
- Suppression/deduplication.
- Teams remains later roadmap unless explicitly added.

---

## Phase 3C — Reports and Auditor Experience

### Scope

- Initial report package.
- PDF/CSV exports.
- Viewer tenant scoping.
- Expiring auditor access.
- CMMC/control evidence reporting.
- Audit-friendly historical views.

---

# 29. Development Tranche Rules

Every Cursor implementation prompt should include these rules:

1. Read `MASTER_PLAN.md` fully first.
2. Inspect repository state before editing.
3. State the exact phase/tranche being implemented.
4. Do not implement later phases.
5. Do not change locked architecture.
6. Preserve backward compatibility where the phase requires migration.
7. Add tests for new behavior.
8. Prefer small, reviewable migrations.
9. Do not fabricate passing tests.
10. Report exact commands/tests run.
11. Report blockers and incomplete work explicitly.
12. Do not commit/push unless explicitly instructed.
13. Do not modify production secrets or insert real client data.
14. Avoid destructive data migrations unless explicitly approved and backed by tested upgrade logic.
15. Keep UX simple and safe.

---

# 30. Required Cursor Closure Report Format

Every implementation tranche should end with a report containing:

## 1. Starting State

- Branch.
- HEAD SHA.
- Version if present.
- Working-tree state.
- Relevant existing architecture discovered.

## 2. Scope Implemented

What the prompt asked for.

## 3. Files Changed

Grouped:

- Production.
- Migrations.
- Tests.
- Docs.
- Frontend if applicable.

## 4. Database Changes

- New/changed tables.
- Constraints/indexes.
- Migration revision IDs.
- Upgrade/downgrade behavior.
- Existing-data handling.

## 5. Security / Authorization Changes

Exact behavior.

## 6. Compatibility

- What existing behavior remains.
- Any intentional compatibility shim.

## 7. Tests

- Exact commands.
- Counts/results.
- Any skipped tests and why.

## 8. Manual Verification

What was manually exercised.

## 9. Deviations from MASTER_PLAN.md

Must say `None` if none.

## 10. Risks / Follow-Up

Only real remaining issues.

## 11. Gate Result

`READY` or `NOT_READY` for the next tranche, with reasons.

---

# 31. Locked Decisions Summary

The following are considered architectural contracts unless explicitly changed by the user:

- On-prem Docker central server.
- HTTPS.
- PostgreSQL.
- Multi-tenant.
- Tenant → Site → Network.
- Multiple Agents per Site.
- Overlapping private CIDRs across Sites allowed.
- Explicit Agent authorization to Networks.
- Any Available and Preferred + Failover Agent modes.
- UTC persistence + global timezone + Site override.
- Internal Admin/User roles.
- Viewer/Auditor is read-only, tenant-scopeable, expirable.
- WAN targets support IP/CIDR/FQDN and require explicit authorization.
- Agent UUID is identity, not permanent secret.
- Public-key-bound Agent authentication after approval.
- TLS verification on by default.
- Persistent Asset identity independent of IP/hostname/Agent.
- Asset lifecycle separate from disposition.
- Policy-driven device handling.
- UI-driven policies.
- Tags.
- Asset criticality.
- Inactive/archive after configurable days without destructive history loss.
- Reactivation of previously inactive Asset with event.
- Expected/manual Assets.
- Audited merge/split/correction operations.
- Configurable scan stages.
- Configurable port modes.
- Configurable intensity with Admin caps.
- Scan exclusions.
- Proper scheduled scans with timezone.
- Maintenance windows deferred.
- Authenticated scanning deferred.
- Raw scan evidence retained with configurable retention.
- Scanner/tool/template versions recorded.
- Pinned/centrally tracked scanner versions direction.
- Scanner-independent finding model.
- CVE optional.
- Multiple detection evidence sources.
- Technical finding state separate from treatment.
- Consecutive clean scans required for automatic resolution.
- Mitigation/risk acceptance review and expiration.
- CVSS/EPSS/KEV enrichment.
- Explainable P1–P4 priority.
- Generic compliance Framework/Control model.
- Evidence-bearing objects can reference controls.
- Audit history.
- Dashboard/email/webhook alerts; Teams later.
- Initial reporting package.
- Archive/soft-delete semantics for important historical objects.
- Alembic migration foundation before major schema expansion.

---

# 32. Final Architectural Principle

The central product value is not the scanners themselves.

The platform's long-term value is its ability to maintain a trustworthy, auditable historical model of:

```text
What exists
What changed
What was detected
What remains exposed
What was fixed
What was mitigated
Why risk was accepted
Which controls apply
Who made the decision
What evidence supports it
```

Scanner engines are replaceable detection sources.

Asset identity, history, evidence, lifecycle, authorization, auditability, and usability are the platform.
