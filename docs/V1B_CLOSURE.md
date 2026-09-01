# V1B — Closure evidence

**Tranche:** V1B — Operational Release Readiness  
**Status:** ACCEPT / CLOSED  
**V1A:** ACCEPT / CLOSED (`a06e455` on audited baseline `3f702b8`)  
**Implementation/ops baseline:** `bb63c6b7bc91e9098f2edc035fe3828aec831618` (merge of [PR #1](https://github.com/JustinTDCT/nuclei-dashboard/pull/1); PR head `3051266`). Checking out this SHA still shows the pre-closure V1B record (`NOT READY FOR V1C`). That is expected: PR #1 landed bounded logging in git, but the deployed-Agent log rollout finished afterward.  
**V1B acceptance checkpoint:** `39f463c0f34289f4dc0e5eb74886471dc6e256e2` (merge of [PR #2](https://github.com/JustinTDCT/nuclei-dashboard/pull/2); parents `bb63c6b` and `68cc342`). That merge SHA is the immutable V1B acceptance reference.  
**Schema:** `0017_security_h6_h8` · **`0018` not created**  
**Agent pin:** `3cdb52c42a87552db98e609e9ec7c1c01e86b23b` (unchanged)  
**Verdict:** **V1B — ACCEPT / CLOSED.** **V1C — ACCEPT / CLOSED** (`docs/V1C_CLOSURE.md`). **V1D — READY TO START.**

This file records evidence. The runbook is `docs/V1B_OPERATIONS.md`. V1A product PARTIALs are not in scope. Restore and the immutable-image rollback walk were not repeated at closure.

---

## Gates

| Gate | Status | Evidence |
|---|---|---|
| V1A closure | CLOSED | `a06e455` on `3f702b8` |
| PostgreSQL + artifacts backup | CLOSED | secdock `20260901T150552Z` |
| Isolated restore | CLOSED | `nuclei-v1b-restore` / port 18118; not repeated at V1B close |
| Artifact integrity after restore | CLOSED | Artifact 23 SHA-256 matched |
| Isolated certificate replacement | CLOSED | Throwaway cert on 18118; live trust anchor untouched |
| Frontend CI / Node 22 | CLOSED | PR #1 run [33529638706](https://github.com/JustinTDCT/nuclei-dashboard/actions/runs/33529638706) on `3051266`: frontend success. Earlier candidate run [33524201425](https://github.com/JustinTDCT/nuclei-dashboard/actions/runs/33524201425) on `7f5b4af` also green. |
| Backend CI on candidate | CLOSED | Same PR run: backend success. Check names `backend` and `frontend`. |
| Protected `main` | CLOSED | Ruleset **V1B main protection** id `22025478`, enforcement `active`, `bypass_actors: []`, `current_user_can_bypass: never`. PR required (0 approving reviews), required checks `backend` + `frontend` (strict / up to date), deletion forbidden, force-push (`non_fast_forward`) forbidden. Direct pushes to `main` remain prohibited. [html](https://github.com/JustinTDCT/nuclei-dashboard/rules/22025478) |
| PR #1 merge | CLOSED | Merged 2026-09-01 16:33Z as `bb63c6b` (implementation/ops baseline). `origin/main` at that SHA contains central `x-logging` (`json-file` `10m` × `5`) and generated/static Agent compose with the same ceiling. It is not the V1B acceptance checkout. |
| Upgrade/rollback walk | CLOSED | Isolated project `nuclei-v1b-rollback` rerun 2026-09-01 16:02Z: `nuclei-dashboard-api:v1b-7f5b4af` (`sha256:4cfcb8bad969fc261c8105d7a971960df813003914ea95ed42ae34e85c17904f`) → `nuclei-dashboard-api:v1b-d161490` (`sha256:5b9b58c621eb57e22db9645b087c08192e9fe050bc9d6a864118ccc465b8183e`) → exact known-good image ID. IDs were distinct. `/api/health` succeeded after every transition. Alembic stayed `0017_security_h6_h8`. Postgres volume identity unchanged. `alembic downgrade 0016` refused (`50` history rows). Then `down -v` **only** that project. Production `:latest` stayed `1cd4014153d8`. Not repeated at close. Repeat script: `ops/v1b-rollback-walk.sh`. |
| Central log rotation | CLOSED | Live secdock: every running service `json-file` `max-size=10m` `max-file=5`. Two APIs healthy, scheduler advisory lock `91304701` granted, `/api/health` `{"ok":true}`. |
| Remote Agent log rotation | CLOSED | **Nuclei-Pi4** (`NUCLEI-AGENT`, `10.150.10.152`): compose patched, `sudo docker compose --env-file agent.env up -d --no-build --force-recreate`; inspect `{"Type":"json-file","Config":{"max-file":"5","max-size":"10m"}}`; `TLS_CA_FILE=/certs/ca.pem`; heartbeat current. **TAB1** (`docker01`): compose `agent-4ff50012-630a-45f6-b2de-ba1817d24256.yml` patched; recreate with matching `--env-file`; inspect `{"Type":"json-file","Config":{"max-file":"5","max-size":"10m"}}`; heartbeat current (`16:41:53Z`, ~14s lag at check). Agent pin unchanged. Disk thresholds remain documented, not a monitoring product. |
| Failure-recovery smoke | CLOSED | S3F/H9 unchanged. Logging deploy recreated postgres (same volume), api-1, api-2, web, caddy, scanner, and scheduler without `down -v`. |
| V1C admission | CLOSED | Operator UX walk on live `39f463c0`. No V1C blockers. Evidence: `docs/V1C_CLOSURE.md`. V1A PARTIALs remain backlog. |

---

## Direct-push policy (enforced)

Direct pushes to `main` are **prohibited**, including for repository admins. Branch → PR → `backend` and `frontend` green → merge. No standing bypass list.

---

## What V1B is not

- Not a reopen of S1–S3 or H1–H9.
- Not permission to add `0018` or bump the Agent pin.
- Not a fix for V1A product gaps.
- Not a V1 release tag.
- Not a live production certificate rotation.
