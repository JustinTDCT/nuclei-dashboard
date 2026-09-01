# V1B — Operational Release Readiness

**Tranche:** V1B — Operational Release Readiness  
**Status:** ACCEPT / CLOSED (`bb63c6b`). V1C is READY TO START.  
**Does not change:** schema (`0017`), Agent pin `3cdb52c`, Scale S1–S3, Sec H1–H9, V1A product PARTIAL/MISSING items.

This file is the operator runbook. Evidence of what was actually exercised lives in `docs/V1B_CLOSURE.md`. Instructions without a matching closure row are not a passed gate.

Production host for this deployment: secdock (`10.150.125.70`), compose project in `~/nuclei-dashboard`, public URL `https://scanner.thedubes.net:8118`. Do not `docker compose down -v` on that project.

---

## 1. CI and `main` protection

Workflow: `.github/workflows/ci.yml`.

| Job | What it runs |
|---|---|
| `backend` | `pytest -q` on Python 3.12 |
| `frontend` | `npm ci` then typecheck, lint, vitest, production build on **Node 22** |

jsdom 30 requires Node ≥ 22.10 (`worker_threads.markAsUncloneable`). Node 20 makes the frontend job fail after the node-environment tests with `webidl.util.markAsUncloneable is not a function`, and `AssetsPanel.test.tsx` never collects.

### Policy (V1B)

- Direct pushes to `main` are **prohibited**, including for repository admins (`enforce_admins`).
- Force-push and branch deletion are **forbidden**.
- Pull requests into `main` must be up to date and must pass required checks `backend` and `frontend`.
- Approving reviews are not required (solo operator). The PR itself is required so CI runs **before** `main` advances.
- There is no standing bypass list. An emergency bypass is a conscious GitHub ruleset edit, not an accidental `git push`.

Enable this setting only after both jobs are green on the candidate SHA. Protecting a red `main` blocks the CI fix.

Verify:

```bash
gh api repos/JustinTDCT/nuclei-dashboard/branches/main/protection
gh run list --branch main --limit 5
```

---

## 2. Backup

Take PostgreSQL **and** `scan-artifacts`. A `pg_dump` alone is not a recoverable system.

Run from `~/nuclei-dashboard` on the central host. Substitute the Compose project volume prefix if `docker volume ls` shows a different name (often `nuclei-dashboard_scan-artifacts`).

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DEST="$HOME/v1b-backups/$STAMP"
mkdir -p "$DEST"

docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc \
  > "$DEST/nuclei.dump"

docker run --rm \
  -v nuclei-dashboard_scan-artifacts:/src:ro \
  -v "$DEST":/dst \
  alpine tar -C /src -czf /dst/scan-artifacts.tar.gz .

cp -a certs "$DEST/certs"
# Record git SHA and alembic head in $DEST/MANIFEST.txt; do not copy .env into git.
```

Also copy `certs/cert.pem` and `certs/key.pem` under the organization's private-key rules. Do not commit dumps, artifact tarballs, or private keys.

`postgres-data` volume copies of a **running** cluster are not the backup procedure.

---

## 3. Proven restore (isolated)

Restore into a **different** Compose project so production volumes stay untouched.

```bash
# Prefer ops/v1b-restore-proof.sh on the central host (sudo docker).
# Overlay uses `ports: !override` so Caddy binds 18118, not production 8118.

docker compose -p nuclei-v1b-restore -f docker-compose.yml -f ops/compose.restore.yml \
  --env-file .env up -d --no-build postgres
# wait until postgres healthy
docker compose -p nuclei-v1b-restore -f docker-compose.yml -f ops/compose.restore.yml exec -T postgres \
  pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner \
  < "$DEST/nuclei.dump"

docker run --rm \
  -v nuclei-v1b-restore_scan-artifacts:/dst \
  -v "$DEST":/src \
  alpine tar -C /dst -xzf /src/scan-artifacts.tar.gz

docker compose -p nuclei-v1b-restore -f docker-compose.yml -f ops/compose.restore.yml \
  --env-file .env up -d --no-build postgres api web caddy
```

Pass conditions (must all be true):

1. Restored row counts for tenants, assets, findings, scan_jobs, and scan_artifacts match the live counts taken immediately before the dump.
2. `alembic_version` is `0017_security_h6_h8`.
3. `GET https://127.0.0.1:18118/api/health` returns `{"ok":true}` with the restored stack's certificate.
4. Staff login against the restored API succeeds (password hash is in the dump, not invented).
5. A known `scan_artifacts` row downloads; SHA-256 of the bytes matches the metadata row.

Then destroy **only** the restore project:

```bash
docker compose -p nuclei-v1b-restore -f docker-compose.yml -f ops/compose.restore.yml down -v
```

Never run `down -v` without `COMPOSE_PROJECT_NAME=nuclei-v1b-restore`.

---

## 4. Certificate lifecycle

**Source.** Caddy does not issue or renew certificates. The listener uses host files `certs/cert.pem` and `certs/key.pem` (`Caddyfile` `tls /etc/caddy/certs/cert.pem /etc/caddy/certs/key.pem`). This production install is a **self-signed** certificate whose SAN must match `PUBLIC_URL` (currently `scanner.thedubes.net`). Agents trust that public cert via `TLS_CA_FILE=/certs/ca.pem` (copy of `cert.pem`, never `key.pem`).

**Expiry monitoring.**

```bash
openssl x509 -in certs/cert.pem -noout -dates -subject -ext subjectAltName
# Alert when notAfter is within 30 days.
```

**Replacement (production self-signed).** Replacing the self-signed trust anchor **breaks every Agent** until `agent-certs/ca.pem` is updated on each Agent host. Do not rotate on a whim.

1. Pre-upgrade backup of `certs/`.
2. Issue a new cert with the same SAN as `PUBLIC_URL`.
3. `install -m 644` new `cert.pem`; `install -m 600` new `key.pem`.
4. `docker compose up -d --no-deps --force-recreate caddy` (do not `down -v`).
5. `curl --cacert certs/cert.pem https://scanner.thedubes.net:8118/api/health`
6. Copy the new public cert to each Agent `agent-certs/ca.pem` and recreate the Agent container with `--env-file agent.env`.

**Failure/recovery.** If Caddy fails to start after a bad cert/key pair, restore the previous `certs/` files and recreate Caddy. The API, PostgreSQL, and `scan-artifacts` volumes are independent of Caddy TLS files.

**V1B exercise (safe).** Proven 2026-09-01 on secdock: isolated Caddy on port 18118 was recreated with a 2-day test certificate in `/tmp/v1b-test-certs` (not `~/nuclei-dashboard/certs`). New fingerprint served `{"ok":true}` with `--cacert` on the test cert; production `:8118` still verified with the original host cert. Then `docker compose -p nuclei-v1b-restore … down -v` only.

This production install (recorded 2026-09-01):

- Self-signed files `certs/cert.pem` / `certs/key.pem`
- SAN `DNS:scanner.thedubes.net`, `IP:10.150.125.70`
- `notAfter=Nov 21 19:32:12 2028 GMT`
- SHA-256 fingerprint `FB:D5:51:9D:4E:53:17:BB:81:97:AA:D8:66:FB:7F:19:A0:97:BC:09:4E:2C:1D:1A:DF:AD:07:E2:B3:F7:0F:2C`


---

## 5. Upgrade / rollback

**Before every upgrade**

1. Proven backup (section 2) of PostgreSQL, `scan-artifacts`, and `certs/`.
2. Record `git rev-parse HEAD` and `docker compose images`.
3. Confirm Alembic head in the release notes. Current head: `0017_security_h6_h8`. **Do not create `0018` in V1B.**

**Forward**

```bash
git fetch origin
git merge --ff-only origin/main   # after V1B protection: merge a green PR locally or on GitHub
docker compose build api scheduler scanner web
docker compose up -d
# If Caddyfile or Compose changed:
docker compose up -d --build --no-deps caddy
```

API startup runs `alembic upgrade head`. That is forward-only for this schema.

**What can roll back**

- Application image/git to a SHA that is schema-compatible with the **current** database (same Alembic head). Restore the previous images and `docker compose up -d`.
- Caddyfile and `certs/` independently of the database.

**What cannot roll back without restore**

- Any Alembic revision that has been applied. Downgrade from `0002`–`0017` is refused when data exists (`docs/DEVELOPMENT.md`). There is no safe `alembic downgrade` of production data.
- After a future migration lands, rollback of **code** to a pre-migration SHA while leaving the upgraded database is undefined. Restore from the pre-upgrade dump instead.

**Walked 2026-09-01** on isolated Compose project `nuclei-v1b-rollback` (not production). Rerun 16:02Z used two distinct immutable API images, not a label-only recreation:

- known-good: `nuclei-dashboard-api:v1b-7f5b4af` (`sha256:4cfcb8ba…17904f`) booted against the restored DB
- later: `nuclei-dashboard-api:v1b-d161490` (`sha256:5b9b58c6…b8183e`) booted
- return: the running container image ID equaled the original known-good ID
- `/api/health` succeeded after every transition; Alembic stayed `0017_security_h6_h8`; postgres volume identity did not change
- `alembic downgrade 0016` refused (`50` history rows) and left the schema at 0017
- then `down -v` only on that project
- production `nuclei-dashboard-api:latest` remained `1cd4014153d8`

Repeat: `ops/v1b-rollback-walk.sh` (run with docker sudo). It builds the two tags from `git archive` of those SHAs if they are missing; it does not retag `:latest`. It fails closed if postgres or `/api/health` never becomes ready, if the two image IDs are identical, or if the final container is not the original known-good image.

**Forbidden**

```bash
docker compose down -v   # deletes postgres-data, scan-artifacts, scanner-data, …
```

---

## 6. Disk, logs, health

| Signal | How to read | Threshold (starting V1B) |
|---|---|---|
| Host disk | `df -h /` | Investigate above 70% used; emergency above 85% |
| PostgreSQL volume | `docker system df -v` / `du` inside the volume | Growth without matching asset/finding growth is a leak |
| `scan-artifacts` | volume size vs Admin retention (365 days default) | Retention cleanup is hourly; expired bytes should disappear |
| Scanner/Agent spool | `scanner-data` / Agent `/data/spool` | Cap `S2E_SPOOL_MAX_BYTES` (default 256 MiB) |
| Container health | `docker compose ps` | `api` and `postgres` must be healthy |
| Certificate | `openssl x509 -enddate` | 30 days |
| Logs | Docker `json-file` | Must have `max-size` / `max-file` so logs cannot fill the disk |

Compose sets a shared `json-file` ceiling on every long-lived central service (`x-logging: &default-logging`, `max-size: 10m`, `max-file: 5`, about 50 MB per container). Recreate containers **without** `-v` after changing it. Live secdock applied this on 2026-09-01 (`--scale api=2 --no-build`); inspect with `docker inspect <container> --format '{{json .HostConfig.LogConfig}}'`.

Generated site Agent compose (`agent_compose()`, plus `agent/docker-compose.yml` and the reference template) uses the same `json-file` 10m × 5 ceiling. That is deployment configuration only; it does not change scan runtime and does not require an Agent pin bump. Existing Agent hosts must have their local compose updated and the container recreated with `--env-file` (do not omit it, or `TLS_CA_FILE` will not interpolate).

**Rolled 2026-09-01.** Nuclei-Pi4 on NUCLEI-AGENT: `--env-file agent.env --no-build --force-recreate`; LogConfig `max-size=10m` `max-file=5`; heartbeat current. TAB1 on docker01: same ceiling on `agent-4ff50012-630a-45f6-b2de-ba1817d24256.yml` with its matching `--env-file`; inspect `{"Type":"json-file","Config":{"max-file":"5","max-size":"10m"}}`; heartbeat current.

---

## 7. Failure recovery smoke

Do not reopen S3F. Document and, where safe, re-run **restart** (not replica topology) proofs.

| Component | Recovery | Must not |
|---|---|---|
| API (one replica) | `docker compose up -d --no-deps --force-recreate api` | `down -v` |
| API (two replicas) | S3F already proved GET failover; leave `--scale api=2` if that is the live topology | `--scale scheduler=2` |
| Scheduler | Recreate the single `scheduler` service. Advisory lock + PID probe fail closed. | Scale to 2 |
| Scanner | Recreate `scanner`; S2E spool resume is unchanged | Delete `scanner-data` |
| Caddy | Recreate `caddy` after Caddyfile/cert change | Unmount `certs/` |
| PostgreSQL | Recreate `postgres` on the **same** `postgres-data` volume; wait for healthy; API reconnects | New volume, `down -v`, or `pg_restore` onto live |

WAN scanner talks to `http://api:8000` (no Caddy retry). A brief API recreate can 502 in-flight scanner POSTs; that is accepted H9 non-claim.

**Walked 2026-09-01** as part of log-rotation deploy: `docker compose up -d --no-build --scale api=2` recreated postgres (same volume), both API replicas, web, Caddy, scanner, and scheduler. Health `{"ok":true}`; scheduler lock `91304701` granted; APScheduler started. Did not reopen S3F.

---

## 8. Out of scope for V1B (historical)

These stayed out of V1B. V1C is the technician/auditor walk.

- V1A product gaps (single CIDR, timezone lists, cancel/dry-run UI, exclusions UI, merge wizard, manual resolve, treatment-review policy, extra event types).
- V1D soak and any speculative `0018`.
- Phase 4 / V1.1 feature roadmap.
