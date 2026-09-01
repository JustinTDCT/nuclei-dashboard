# V1B — Closure evidence

**Tranche:** V1B — Operational Release Readiness  
**Status:** IN PROGRESS  
**V1A:** ACCEPT / CLOSED (`a06e455` on audited baseline `3f702b8`)  
**Candidate SHA:** `7f5b4af121cc8d1a7269ec6dc28fd3878c341c99`  
**Schema:** `0017_security_h6_h8` · **`0018` not created**  
**Agent pin:** `3cdb52c42a87552db98e609e9ec7c1c01e86b23b`  
**Verdict:** **NOT READY FOR V1C** until the bounded-logging Compose change is on protected `main` (it is deployed on secdock; GitHub `main` is still the pre-logging file).

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
| Upgrade/rollback walk | CLOSED | Isolated project `nuclei-v1b-rollback` on 2026-09-01: known-good → later → known-good API labels; Alembic stayed `0017_security_h6_h8`; postgres volume mountpoint/CreatedAt unchanged; `alembic downgrade 0016` raised `Refusing to downgrade 0017_security_h6_h8: 50 challenge, throttle, or deadline/cancel row(s) exist`; then `down -v` **only** that project. Repeat: `ops/v1b-rollback-walk.sh`. |
| Log/disk controls | PARTIAL | **Live secdock deployed:** every running service `json-file` `max-size=10m` `max-file=5` (~50 MB/container). Two APIs healthy, scheduler advisory lock `91304701` granted, `/api/health` `{"ok":true}`. **GitHub `main` does not yet contain the Compose anchor** (protection is on; land via PR). Disk thresholds remain documented, not a monitoring product. |
| Failure-recovery smoke | CLOSED | S3F/H9 unchanged. Logging deploy recreated postgres (same volume), api-1, api-2, web, caddy, scanner, and scheduler without `down -v`. Scheduler started and ran `route_pending_events_job` / `process_pending_deliveries_job`. |
| V1C admission | **NOT READY** | Open: merge the logging Compose file onto protected `main`. |

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
