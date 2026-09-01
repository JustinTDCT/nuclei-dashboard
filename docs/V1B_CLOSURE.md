# V1B — Closure evidence

**Tranche:** V1B — Operational Release Readiness  
**Status:** IN PROGRESS  
**V1A:** ACCEPT / CLOSED (`a06e455` on audited baseline `3f702b8`)  
**Candidate SHA:** `7f5b4af121cc8d1a7269ec6dc28fd3878c341c99`  
**Schema:** `0017_security_h6_h8` · **`0018` not created**  
**Agent pin:** `3cdb52c42a87552db98e609e9ec7c1c01e86b23b`  
**Verdict:** **NOT READY FOR V1C** until PR #1 is on protected `main` and currently deployed site Agents have the 10m × 5 json-file ceiling.

This file records evidence. The runbook is `docs/V1B_OPERATIONS.md`. V1A product PARTIALs are not in scope. Restore was not repeated.

---

## Gates

| Gate | Status | Evidence |
|---|---|---|
| V1A closure | CLOSED | `a06e455` on `3f702b8` |
| PostgreSQL + artifacts backup | CLOSED | secdock `20260901T150552Z` |
| Isolated restore | CLOSED | `nuclei-v1b-restore` / port 18118; not repeated |
| Artifact integrity after restore | CLOSED | Artifact 23 SHA-256 matched |
| Isolated certificate replacement | CLOSED | Throwaway cert on 18118; live trust anchor untouched |
| Frontend CI / Node 22 | CLOSED | Run [33524201425](https://github.com/JustinTDCT/nuclei-dashboard/actions/runs/33524201425) on `7f5b4af`: frontend 27s success |
| Backend CI on candidate | CLOSED | Same run: backend 20m28s success. Check names `backend` and `frontend`. |
| `main` protection | CLOSED | Ruleset **V1B main protection** id `22025478`, enforcement `active`, `bypass_actors: []`, `current_user_can_bypass: never`. PR required (0 approving reviews), required checks `backend` + `frontend` (strict / up to date), deletion forbidden, force-push (`non_fast_forward`) forbidden. Classic “branch protection” API still 404; the ruleset is the control. [html](https://github.com/JustinTDCT/nuclei-dashboard/rules/22025478) |
| Upgrade/rollback walk | CLOSED | Isolated project `nuclei-v1b-rollback` on 2026-09-01 (rerun 16:02Z): `nuclei-dashboard-api:v1b-7f5b4af` (`sha256:4cfcb8bad969fc261c8105d7a971960df813003914ea95ed42ae34e85c17904f`) → `nuclei-dashboard-api:v1b-d161490` (`sha256:5b9b58c621eb57e22db9645b087c08192e9fe050bc9d6a864118ccc465b8183e`) → exact known-good image ID. IDs were distinct. `/api/health` succeeded after every transition. Alembic stayed `0017_security_h6_h8`. Postgres volume mountpoint/CreatedAt unchanged. `alembic downgrade 0016` raised `Refusing to downgrade 0017_security_h6_h8: 50 challenge, throttle, or deadline/cancel row(s) exist`. Then `down -v` **only** that project. Production `nuclei-dashboard-api:latest` stayed `1cd4014153d8`. Repeat: `ops/v1b-rollback-walk.sh` (builds those tags from git archive if missing; never retags `:latest`; fails closed on health/readiness and if image IDs are not distinct). |
| Log/disk controls | PARTIAL | **Live secdock (central) deployed:** every running service `json-file` `max-size=10m` `max-file=5` (~50 MB/container). Two APIs healthy, scheduler advisory lock `91304701` granted, `/api/health` `{"ok":true}`. **Generated remote Agent compose** (`agent_compose()`, `agent/docker-compose.yml`, template) uses the same ceiling; this is deployment config only (no Agent pin bump). Existing site Agents stay unbounded until their local compose is replaced and the container is recreated. **GitHub `main` does not yet contain the Compose change** (protection is on; land via PR). Disk thresholds remain documented, not a monitoring product. |
| Failure-recovery smoke | CLOSED | S3F/H9 unchanged. Logging deploy recreated postgres (same volume), api-1, api-2, web, caddy, scanner, and scheduler without `down -v`. Scheduler started and ran `route_pending_events_job` / `process_pending_deliveries_job`. |
| V1C admission | **NOT READY** | Open: merge PR #1 onto protected `main`; then replace currently deployed site Agent compose files and recreate with `--env-file agent.env`, verifying Docker `LogConfig` is `10m` × `5`. |

---

## Direct-push policy (now enforced)

Direct pushes to `main` are **prohibited**, including for repository admins. Branch → PR → `backend` and `frontend` green → merge. No standing bypass list.

---

## What V1B is not

- Not a reopen of S1–S3 or H1–H9.
- Not permission to add `0018` or bump the Agent pin.
- Not a fix for V1A product gaps.
- Not a V1 release tag.
- Not a live production certificate rotation.
