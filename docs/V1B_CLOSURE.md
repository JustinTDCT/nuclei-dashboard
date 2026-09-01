# V1B — Closure evidence

**Tranche:** V1B — Operational Release Readiness  
**Status:** IN PROGRESS  
**V1A:** ACCEPT / CLOSED (`a06e455` on audited baseline `3f702b8`)  
**Schema:** `0017_security_h6_h8` · **`0018` not created**  
**Agent pin:** `3cdb52c42a87552db98e609e9ec7c1c01e86b23b`  
**Verdict:** **NOT READY FOR V1C** — restore and isolated certificate replacement are proven; CI is still red on `main`; branch protection is not enabled.

This file records evidence. The runbook is `docs/V1B_OPERATIONS.md`. V1A product PARTIALs are not in scope.

---

## Gates

| Gate | Status | Evidence |
|---|---|---|
| CI green on release-candidate lineage | OPEN | Frontend job on Node 20 fails: `webidl.util.markAsUncloneable is not a function` (jsdom 30). Node 22 pin is in `.github/workflows/ci.yml` and `frontend/package.json` `engines`. Local `npm test` on Node v22.23.2: 3 files / 3 tests passed (`api`, `auth`, `AssetsPanel`). Not green on GitHub until that change is on `main`. Run `33521948577` on `a06e455` failed frontend. |
| `main` branch protection | OPEN | `gh api .../branches/main/protection` → HTTP 404 (2026-09-01). **Not enabled while CI is red.** Intended policy: required checks `backend` + `frontend`, PRs required, `enforce_admins`, no force-push, no deletion, no standing bypass. Direct pushes become **prohibited**. |
| PostgreSQL + `scan-artifacts` backup | CLOSED | secdock `20260901T150552Z`: `nuclei.dump` 414K (`pg_dump -Fc`), `scan-artifacts.tar.gz` 70K. Live volumes `nuclei-dashboard_postgres-data` 71.5M, `nuclei-dashboard_scan-artifacts` 196K. |
| Restore proven in isolation | CLOSED | Compose project `nuclei-v1b-restore`, Caddy **18118** (`ports: !override`). No scheduler/scanner. Counts matched live: alembic `0017_security_h6_h8`, tenants 2, assets 239, findings 0, scan_jobs 11, scan_artifacts 23. Staff login OK. Artifact **23** (job 10) SHA-256 `c121037044dff601500121e8287972037b8f08fc0e97e333fab6abea44395f29` (566 bytes) matched after download through isolated Caddy. Production `:8118` stayed `{"ok":true}`. Restore then `down -v` **only** that project; live two-API stack unchanged. Repeat: `ops/v1b-restore-proof.sh`. |
| Certificate lifecycle exercised | CLOSED for isolated replacement | Production TLS is **self-signed** host files `certs/cert.pem` + `certs/key.pem`. Caddy does not auto-issue. SAN `DNS:scanner.thedubes.net, IP:10.150.125.70`. CN `nuclei-scanner.thedubes.net`. `notAfter=Nov 21 19:32:12 2028 GMT`. SHA-256 fingerprint `FB:D5:51:9D:4E:53:17:BB:81:97:AA:D8:66:FB:7F:19:A0:97:BC:09:4E:2C:1D:1A:DF:AD:07:E2:B3:F7:0F:2C`. Isolated Caddy was recreated on a **separate** cert dir (fingerprint `BF:75:FA:3F:96:4C:BD:7A:30:38:17:BE:51:85:F2:EC:35:53:34:00:5B:86:2D:5C:68:A6:F3:90:CE:8D:7C:43`); `NEW_CERT_HEALTH={"ok":true}` while production `:8118` still verified with the original cert. **Did not rotate the live Agent trust anchor.** |
| Upgrade / rollback playbook | PARTIAL | `docs/V1B_OPERATIONS.md` §5 written (no `down -v`; Alembic forward-only; restore after migrations). Not walked on a dummy SHA. |
| Disk / log / health | OPEN | Host `/` was 59% of 98 GB during the proof. Compose still has no `json-file` `max-size`; log growth can fill the host until that is deployed. |
| Failure recovery smoke | PARTIAL | S3F/H9 remains the two-API GET failover evidence. Live topology is still `--scale api=2`. V1B did not reopen S3F and did not recycle production scheduler/scanner/postgres. |
| V1C verdict | **NOT READY** | |

---

## Direct-push policy

**Prohibited** on `main` once protection is enabled (including repository admins). Workflow: branch → PR → `backend` and `frontend` green → merge. Enable only after a green run on the Node 22 pin.

---

## What V1B is not

- Not a reopen of S1–S3 or H1–H9.
- Not permission to add `0018` or bump the Agent pin.
- Not a fix for V1A product gaps.
- Not a V1 release tag.
- Not a live production certificate rotation (Agents pin the self-signed public cert).
