# V1A — Master Plan Closure Audit

**Tranche:** V1A — Master Plan Closure Audit / No Code  
**Plan version audited:** `MASTER_PLAN.md` v1.0.0  
**Code baseline:** `3f702b8c970768ae82c9c48e58af171f2b84a913` (docs checkpoint on `fd697a6`)  
**Schema:** `0017_security_h6_h8` · **`0018` not created**  
**Agent pin:** `3cdb52c42a87552db98e609e9ec7c1c01e86b23b`  
**Scale S1–S3 / Sec H1–H9:** frozen / closed as of `3f702b8`  
**Method:** read the entire master plan; walk live backend, frontend, tests, Compose, Caddy, and CI against every Phase 0–3C requirement and locked contract. No production code, no schema, no pin change.

This document is the V1A output. It does not name Phase 4.

---

## Verdict

**Did we finish the product described by v1.0.0?**

**We finished the defined implementation phases. We did not finish a supportable V1 release.**

| Question | Answer |
|---|---|
| Phases 0 → 3C implemented with tests? | **Yes.** Every named phase has a backend test module except Phase 0, which is covered by `test_migrations.py`, `test_agent_rbac.py`, and `test_tls_defaults.py`. |
| Scale S1–S3 and Sec H1–H9 closed? | **Yes.** Frozen at `3f702b8`. |
| Locked domain model present in code? | **Yes, with listed PARTIALs.** |
| Explicit §27 deferred items implemented by accident? | **No.** They remain deferred. |
| Ease-of-use (§26) satisfied for a new MSP technician? | **PARTIAL.** The happy path exists; several common actions still expose IDs, cron, `window.prompt`, or missing controls. |
| Production / operationally supportable? | **No.** CI workflow exists; branch protection, proven restore, certificate renewal, rollback playbook, log/disk monitoring, and a scale soak are not in-repo evidence. |
| **V1 RELEASE READY?** | **No.** |

Call the current software **V1 feature-complete for the written roadmap**, not **V1 released**. A release tag should wait for operational proof and a technician/auditor UX walk that turns the PARTIAL list below into an accepted backlog.

---

## Status legend

| Status | Meaning |
|---|---|
| **COMPLETE** | Required behavior exists in code and is proven by tests and/or accepted live evidence. |
| **PARTIAL** | Core contract exists; a listed slice is missing, API-only, or UX-incomplete. |
| **DEFERRED** | Master plan explicitly said not to build this in V1 / early phases. Absence is correct. |
| **MISSING** | Plan required it for V1 (or listed it as a locked example that should exist) and it is not implemented. |

---

## 1. Phase rollup

| Phase | Goal | Status | Evidence |
|---|---|---|---|
| **0** Foundation / Alembic / viewer secret / TLS default | COMPLETE | `backend/app/migrate.py`; `test_migrations.py`; `test_agent_rbac.py`; `test_tls_defaults.py`; `docs/DEVELOPMENT.md` |
| **1A** Site / Network / agent authorization | COMPLETE | `0002_sites_networks`; `test_phase1a.py`; `SitesPanel.tsx` |
| **1B** Asset / identifier / address / service / observation | COMPLETE | `0003`/`0004`; `test_phase1b.py`; `AssetsPanel.tsx` |
| **1C** Correlation / lifecycle / merge-split | COMPLETE | `0005`; `correlation.py`; `identity_ops.py`; `test_phase1c.py` |
| **1D** Scan definition / stages / schedule / WAN snapshot | COMPLETE (core) | `0006`; `test_phase1d.py`; `TenantDetail.tsx` scan wizard |
| **2A** Finding catalog / lifecycle | COMPLETE | `0007`–`0009`; `test_phase2a.py` |
| **2B** CVE intelligence / P1–P4 | COMPLETE | `0010`; `intel/*`; `test_phase2b.py` |
| **2C** Treatments / Framework–Control | COMPLETE (scoped) | `0011`; `test_phase2c.py`; `Compliance.tsx` |
| **3A** Policy engine | COMPLETE (scoped) | `0012`; `test_phase3a.py`; `Policies.tsx` |
| **3B** Events / alerts | COMPLETE (scoped) | `0013`; `test_phase3b.py`; `Alerts.tsx` |
| **3C** Reports / viewer / auditor | COMPLETE | `0014`; `test_phase3c.py`; `Reports.tsx`; `History.tsx` |
| **S1–S3** Scale | COMPLETE / FROZEN | `test_scale_s1.py` … `test_scale_s3f.py`; live S3F at `fd697a6` |
| **H1–H9** Security | COMPLETE / H9 CLOSED | `test_security_boundaries.py`; `test_security_h6_h8.py`; H9 live gate documented |

Phase 1D / 2C / 3A / 3B are COMPLETE for their **phase scope**. Items the phase itself deferred (blackouts, authenticated scans, Teams) stay DEFERRED. Gaps versus later locked sections are PARTIAL/MISSING in the matrices below, not phase failures.

---

## 2. Locked invariants (§23 / §31)

| ID | Contract | Status | Evidence |
|---|---|---|---|
| I-01 | On-prem Docker central + HTTPS Agents | COMPLETE | `docker-compose.yml`; Caddy `:8118`; agent compose outbound HTTPS |
| I-02 | PostgreSQL only; no sharding/K8s | COMPLETE | Compose postgres; no 0018; scale docs forbid speculative infra |
| I-03 | Tenant → Site → Network; overlapping RFC1918 | COMPLETE | `test_phase1a.py::test_overlapping_cidrs_across_sites_and_authorization_rules` |
| I-04 | Explicit Agent authorization; Any Available / Preferred+Failover | COMPLETE | `NetworkAgent`; `scan_dispatch.py`; `test_phase1d.py::test_waiting_missed_and_preferred_failover` |
| I-05 | UTC persist; global TZ; Site override; IANA | COMPLETE persist/schedule; PARTIAL display | `timezones.py`; `scan_schedule.py`; many UI lists use global TZ only |
| I-06 | Admin / User / Viewer; viewer read-only, scoped, expirable | COMPLETE | `access.py`; `test_phase3c.py`; `test_agent_rbac.py` |
| I-07 | WAN IP/CIDR/FQDN authorized; fail-closed; H4 safety | COMPLETE | `wan_targets.py`; `test_security_boundaries.py::test_wan_target_policy_rejects_unsafe_scope`; `test_phase1d.py` |
| I-08 | Agent UUID ≠ secret; pubkey after enroll; secret one-time | COMPLETE | `agent_api.py` enroll/challenge/token; secret cleared on approve |
| I-09 | TLS verify default ON | COMPLETE | `compose_gen.py` `TLS_VERIFY:-1`; `test_tls_defaults.py` |
| I-10 | Viewer never gets enrollment secret / deploy material | COMPLETE | `agents.py` `require_user` on compose/env; `test_agent_rbac.py` |
| I-11 | Tenant auth server-side | COMPLETE | `apply_tenant_scope` / `require_visible_tenant` |
| I-12 | LAN jobs only via authorized Agents | COMPLETE | snapshot + dispatch; Phase 1A/1D tests |
| I-13 | Exclusions enforced by backend/worker | COMPLETE | `scan_exclusions.py` / snapshot; `test_phase1d.py` |
| I-14 | Intensity Admin caps | COMPLETE | `scan_intensity.py`; `test_phase1d.py::test_intensity_caps_exclusions_and_viewer` |
| I-15 | Security-relevant changes audited | PARTIAL | Broad `record_audit` coverage; no staff **manual finding resolve** audit because that API does not exist |
| I-16 | Cross-tenant IDs fail closed | COMPLETE | Phase 3C direct-ID tests |
| I-17 | Raw evidence + reports tenant-scoped | COMPLETE | `raw_artifacts.py`; `reporting/scope.py`; `test_phase3c.py` |
| I-18 | Tool/runtime versions on runs | COMPLETE | `runtime_provenance`; Tranche C / raw-evidence gates |
| I-19 | Asset ≠ IP; lifecycle ≠ disposition | COMPLETE | `test_phase1b.py`; `test_phase1c.py` |
| I-20 | Finding identity ≠ Nuclei; tech state ≠ treatment | COMPLETE | `Vulnerability` + `AssetFinding` + `FindingTreatment`; `test_phase2a.py` / `test_phase2c.py` |
| I-21 | Consecutive CLEAN scans to auto-resolve; applicability | COMPLETE | `finding_lifecycle.py`; `test_phase2a.py` |
| I-22 | Archive/soft-delete over physical delete | COMPLETE | Sites/Networks/Scans archive; tenant delete refused |
| I-23 | Alembic before further schema | COMPLETE | Head `0017`; startup is not ad-hoc ALTER |

---

## 3. Users, authorization, timezone

| ID | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| 7.1 | Admin / User / Viewer | COMPLETE | `auth.py`; `AdminUsers.tsx` | |
| 7.1-ro | Viewer cannot mutate, scan, approve, or fetch secrets | COMPLETE | `require_user` on writes; `test_agent_rbac.py` | |
| 7.2 | All-tenant vs selected tenants, server-side | COMPLETE | `ViewerTenantGrant`; `access.py`; `test_phase3c.py` | |
| 7.2-exp | Viewer expiration | COMPLETE | `viewer_expires_at`; `0014`; `test_phase3c.py` | |
| 6-utc | Timestamps UTC | COMPLETE | timezone-aware columns | |
| 6-iana | IANA global + site override | COMPLETE | `AdminSettings.tsx`; `SitesPanel` TimezoneField | |
| 6-ui | UI shows effective TZ | PARTIAL | Schedules and some site heartbeats use effective TZ; tenant job/finding lists often use global default (`timezone.tsx` / `TenantDetail`) | Site override not applied everywhere |
| 6-sched | Schedules honor site TZ (LAN) / global (WAN) | COMPLETE | `effective_scan_timezone`; DST tests in `test_phase1d.py` | |

---

## 4. Tenant, Site, Network, WAN, Agent

| ID | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| 8.1–8.2 | Tenant, multi-site, tags, TZ | COMPLETE | `tenants.py`; `sites.py`; `SitesPanel.tsx` | |
| 8.3-cidr | Network not globally identified by CIDR | COMPLETE | unique `(site_id, name)`; overlapping-CIDR test | |
| 8.3-multi | One or more CIDRs per Network | PARTIAL | Single `Network.cidr` column | Workaround: multiple Networks |
| 8.3-excl-ui | Network may have exclusions | PARTIAL | Model+API all scopes; UI creates **tenant** exclusions only | Site/network/scan exclusion UI missing |
| 8.3-auth | Authorized agents + dispatch modes | COMPLETE | `SitesPanel` authorize + mode | No separate AgentPool entity (pool = authorized set) |
| 9 | WAN types, scan refs, fail-closed, audit, H4 | COMPLETE | `wan_targets.py`; Phase 1D + H4 tests | |
| 9-sub | Subdomain discovery | DEFERRED | §9 / §27 | Correctly absent |
| 10.1–10.2 | Docker agent, compose download, enroll/approve/keypair | COMPLETE | `compose_gen.py`; `agent_api.py`; Sites/Tenant agent UI | |
| 10.3 | Clone/mismatch signals | PARTIAL | pubkey, hostname, last IP, site, inventory, identity-mismatch event | No concurrent-session anomaly product; no TPM (deferred) |
| 10.4 | TLS default verify; CA mount; bypass opt-in | COMPLETE | `test_tls_defaults.py`; agent-certs docs | |
| 10.6 | Wait → missed + event | COMPLETE | `JOB_WAITING_FOR_AGENT`; `expire_waiting_jobs`; `emit_scan_missed_unavailable_agent` | |
| 10-tpm | TPM-backed keys | DEFERRED | §10.3 / §27 | |

---

## 5. Assets, correlation, scans

| ID | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| 11.1–11.3 | Persistent Asset; historical IPs; multi-address | COMPLETE | `test_phase1b.py` | No explicit address `ended_at` |
| 11.2-oui | MAC vendor as identifier | PARTIAL | OUI folded into `tech`/`vendor` meta (`scan_runtime/oui.py`) | Not a typed `AssetIdentifier` |
| 11.4 | Services | PARTIAL | `AssetService` fields | No current/historical state enum; no service-change events (§11.4 “later”) |
| 11.5 | Immutable observations | COMPLETE | `observation_key`; `0004` | |
| 11.6–11.8 | Lifecycle vs disposition; inactivity; expected assets | COMPLETE | `lifecycle.py`; `AssetsPanel`; `test_phase1b.py` / `test_phase1c.py` | |
| 11.9 | Merge / split / correct / move / reassociate + audit | COMPLETE backend; PARTIAL UX | `identity_ops.py`; `test_phase1c.py`; `AssetsPanel` confirm panel | ID-typed, not a guided wizard (§26) |
| 11.10–11.11 | Tags; criticality | COMPLETE | models + UI editors | |
| 13.1–13.2 | Definition vs run; stages | COMPLETE | `execution_snapshot`; scan wizard | |
| 13.3 | Intensity presets + caps | COMPLETE | `scan_intensity.py` | |
| 13.3-dry | Dry-run | PARTIAL | Backend `intensity_config.dry_run`; runner dry-run | **No UI control** |
| 13.4 | Exclusions all scopes | PARTIAL | Enforced; UI tenant-only | |
| 13.5 | Daily/weekly/monthly/cron + TZ | COMPLETE | `scan_schedule.py`; UI | Cron still visible (allowed as advanced) |
| 13.6 | Blackout windows | DEFERRED | §13.6 | |
| 13.7 | Authenticated scanning | DEFERRED | §13.7 | |
| 13-cancel | Technician cancel | PARTIAL | Deadline/H7 cancel path; `mark_cancel_requested` | **No staff cancel API or button** (`routers/scans.py`) |
| 13.9 / 14 | Provenance + approved-version mismatch UI | COMPLETE | `runtime_provenance`; `versionStatus.ts`; Admin approved pins | Auto-update rings DEFERRED |

---

## 6. Policy, findings, intelligence, compliance, alerts, reports, audit

| ID | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| 12.1–12.2 | UI policies; Global/Tenant/Site/Network + priority | COMPLETE | `policy.py`; `Policies.tsx`; `test_phase3a.py` | |
| 12.3 | Categories | PARTIAL | Four exist: `asset_handling`, `asset_inactivity`, `finding_lifecycle`, `alerting` | **No risk/treatment-review category.** Scan limits live in Admin settings, not PolicyRule |
| 16.1–16.5 | Catalog, AssetFinding, evidence, tech vs treatment | COMPLETE | `test_phase2a.py`; `test_phase2c.py` | |
| 16.6 | N consecutive CLEAN; reopen; first_seen preserved | COMPLETE | `finding_lifecycle.py` | |
| 16.6-manual | Manual resolve/reopen with audit | MISSING | No `/resolve` route; §16.6 and §20 list it | Auto path only |
| 16.7 | Mitigate / accept / FP; review; expiry | COMPLETE | `treatments.py`; `test_phase2c.py` | Attachments deferred |
| 17 | CVSS/EPSS/KEV/CWE; explainable P1–P4 | COMPLETE | `intel/priority.py`; `test_phase2b.py` | |
| 18.1 | Generic Framework → Control | COMPLETE | `compliance.py`; `Compliance.tsx` | Bundled catalog is NIST SP 800-171 Rev. 3 only |
| 18.2 | Control refs from evidence objects | PARTIAL | asset, asset_finding, finding, treatment, scan_job | Policy not a subject |
| 18.3 | CMMC / 800-171 | PARTIAL | OSCAL-derived 800-171; UI disclaimer | No CMMC L2 / CIS / ISO / CSF catalogs (not claimed as certification) |
| 19.1 | Domain events | PARTIAL | Implemented: new/inactive/returned asset, disposition, new/resolved/reopened finding, treatment created/expired, scan failed/missed, agent identity mismatch, WAN target, policy | **Missing:** new/disappeared service, distinct critical finding, agent online/offline, concurrent identity anomaly |
| 19.2–19.4 | Alert policies; dashboard/email/webhook; suppress | COMPLETE | `alert_engine.py`; `test_phase3b.py`; `Alerts.tsx` | |
| 19.3-teams | Microsoft Teams | DEFERRED | §19.3 / Phase 3B | |
| 20 | Append-only audit | COMPLETE | `AuditLog`; `History.tsx` | Manual finding resolve cannot be audited until it exists |
| 22 | Ten report families; PDF/CSV; viewer scope; historical semantics | COMPLETE | `reporting/catalog.py` (executive, asset_inventory, asset_changes, open/resolved findings, treatments, cve_aging, scan_history, agent_health, control_evidence); `test_phase3c.py`; S3E keyset | Report 3 titled “New / Changed **Assets**” (plan said Devices) — meaning matches Assets |

---

## 7. Explicit deferred items (§27 and related)

Absence is **correct**. Do not treat these as V1 defects.

| Item | Plan citation |
|---|---|
| Maintenance / blackout windows | §13.6, §27, Phase 1D |
| Authenticated / credentialed scanning | §13.7, §27 |
| Microsoft Teams | §19.3, Phase 3B, §27 |
| TPM-backed Agent identity | §10.3, §27 |
| Full Agent auto-update / rings | §14, §27 |
| SSO / MFA | §27; H8 “MFA remains deferred”; DEVELOPMENT httpOnly cookies later |
| Complex external subdomain discovery | §9, §27 |
| Distributed databases / microservices / K8s / sharding | §3, §24.3, §27 |
| Treatment attachments | §16.7 |
| Physical deletion as normal workflow | §21 |
| Arbitrary N-replica HA, PostgreSQL HA, scaled scheduler | H9 closure boundary |

---

## 8. UX gaps (§2 ease of use, §26)

The technician path **exists** as dedicated UI:

`/login` → `/tenants` → tenant Sites (`SitesPanel`: site, network, authorize, dispatch) → Agents (create, download compose/env, approve) → Scans wizard (scope, stages, intensity, schedule) → Run now → Assets → Findings + treatments → `/compliance` mapping → `/reports` → `/alerts` → `/history`. Viewer write controls are hidden; grants are server-side.

That is not the same as “a new MSP technician never sees internals.”

| Gap | Why it matters | Suggested backlog |
|---|---|---|
| Asset merge/split by raw IDs | §26 wants guided merge/split | Search-and-pick wizard |
| No scan **Cancel** in UI | Operators use SQL/container today | Staff POST cancel + confirm |
| No **dry-run** toggle | Backend exists | Intensity step checkbox |
| Exclusions UI is tenant-only | Plan allows site/network/scan | Scoped exclusion editor |
| Treatment revoke uses `window.prompt` | Fragile, not auditable confirmation UX | Modal with typed confirm |
| Run now / Archive / Approve lack confirm | Easy misclick | Confirm dialogs |
| Job/finding timestamps ignore site TZ | §6 display contract | Use effective TZ |
| Cron still on the common schedule step | §26: technicians should not need cron | Hide under Advanced |
| Custom intensity exposes tool knobs | Fine if behind Advanced | Default Low/Normal/High only |
| Home still says “New devices” | Asset is canonical | Copy: New assets |
| No dedicated Devices page (correct) | Compatibility Device rows remain | Keep Device as projection; don’t revive a Device-first UI |
| Empty states exist but are thin | First-run guidance | Checklist: create site → network → agent → scan |
| Viewer UX not walked end-to-end | §3C auditor experience | V1C auditor script |
| Agent compose still requires Docker literacy | Unavoidable for V1 field deploy | README is the mitigation; do not hide Docker |

This list is a **prioritized UX backlog**, not random polish. It is not a live technician walk-through; that walk is the next recommended tranche.

---

## 9. Operational gaps

| Item | Status | Evidence / gap |
|---|---|---|
| CI workflow (pytest + frontend typecheck/lint/test/build) | COMPLETE as code | `.github/workflows/ci.yml` on `push`/`pull_request` |
| CI green on `3f702b8` | UNVERIFIED here | This environment has no `gh` auth |
| `main` branch protection requiring those checks | MISSING as proven setting | DEVELOPMENT tells operators to protect `main`; it is a GitHub setting, not code. Prior governing notes said main was unprotected. **Treat as open until an admin screenshot/`gh api` proves otherwise.** |
| PostgreSQL backup documented | PARTIAL | README mentions volumes |
| **Restore proven** (PG + `scan-artifacts`) | MISSING | No restore runbook or test in-repo. Live secdock had a pre-S3F dump; restore was not the gate. |
| Certificate renewal | MISSING | Install/create documented; Caddy does not auto-issue; no renewal/reload procedure |
| Update / rollback | PARTIAL | `git pull` + rebuild; Alembic downgrade refused → restore from backup, but restore unproven |
| Disk capacity monitoring | MISSING | Install note only |
| Application log retention | MISSING | `docker compose logs` only |
| Artifact retention | COMPLETE | 365-day setting + hourly cleanup |
| Recovery from one API / scheduler / scanner failure | PARTIAL | S3F proved API replica recycle for GET; scheduler remains single-active; scanner recreate was an S2E gate, not a V1 ops runbook |
| Scale soak (multi-tenant, schedules, alerts, recycle) | MISSING | S1–S3 are bounded tests + two-API gate, not a soak. `0018` stays unjustified until soak evidence |

---

## 10. Security leftovers

| Item | Status |
|---|---|
| H1–H8 | COMPLETE with tests |
| H9 | CLOSED (supported 1 or 2 API replicas; see plan) |
| MFA / SSO | DEFERRED |
| httpOnly cookies | DEFERRED (tokens in `sessionStorage`; XSS-readable; DEVELOPMENT) |
| Staff cancel + manual finding resolve | Product gaps with security/audit impact (stuck jobs; no audited manual close) |
| Branch protection | Operational leftover, not an H-tranche |

Do not reopen H1–H9. Do not treat H9 non-claims as unfinished H9.

---

## 11. Recommended post-V1 priority

Do **not** name Phase 4A yet. Use closure-style tranches until a new immutable roadmap is written.

1. **V1B — Production / operational readiness (no product features).** Verify CI on this baseline; enable `main` protection requiring those checks; write and **perform** a restore of PostgreSQL + `scan-artifacts`; document cert renewal, update/rollback, disk and log retention; one-page recovery for API / scheduler / scanner failure. Still no `0018`.
2. **V1C — Technician and auditor UX walk.** Execute the MSP script (tenant → site → network → agent → approve → scan → assets → triage → treat → map control → report) and the viewer script. File every confusing click. Turn §8 into an accepted backlog with severity. Implement only after the walk, in a named UX tranche.
3. **V1D — Operational scale soak.** Several tenants/sites, simultaneous LAN/WAN, schedules, alerts, reports, artifact growth, Agent disconnect, one API recycle. Watch connections, RSS, scheduler duration, spool, disk, slow queries. Create `0018` only if that soak proves it.
4. **Then write V1.1 / V2 roadmap.** Decide which §27 items (MFA/SSO, Teams, auto-update, blackouts, authenticated scans, TPM, subdomain discovery) belong, plus UX/ops leftovers from V1B–V1D.
5. **Release checkpoint.** Tag the SHA that survives V1B–V1D (and any accepted UX fixes) as production V1. New features start from that tag.

---

## 12. What this audit is not

- Not a live technician walk (no browser script was executed for V1A).
- Not a proven restore or soak.
- Not a GitHub branch-protection verification (`gh` unauthenticated here).
- Not a reopen of S1–S3 or H1–H9.
- Not permission to add `0018`, bump the Agent pin, or start Phase 4.

---

## Gate

**V1A audit: READY as the closure record.**  
**Product: NOT V1 RELEASE READY.**  
**Next: V1B operational readiness, then V1C UX walk — not a new feature phase.**
