# V1D — Operational soak

**Tranche:** V1D — Operational soak  
**Status:** READY TO START  
**Does not change:** schema (`0017_security_h6_h8`), Agent pin `3cdb52c`, Scale S1–S3, Sec H1–H9, V1A product PARTIAL/MISSING items.  
**Admission:** V1A / V1B / V1C ACCEPT / CLOSED. Walked product SHA `39f463c0`. V1C checkpoint is the merge of the V1C docs PR.

This is the final technical gate before a V1 Release Decision. It is not a feature tranche. Do **not** create `0018` because V1D exists. If the soak actually demonstrates a queue/index problem, that evidence can justify a later schema change. Otherwise leave the schema alone.

Production host: secdock (`10.150.125.70`), compose project in `~/nuclei-dashboard`, public URL `https://scanner.thedubes.net:8118`. Live topology is `--scale api=2`. Do not `--scale scheduler=2`. Do not `docker compose down -v` on that project.

Evidence of a passed soak belongs in a later `docs/V1D_CLOSURE.md`. Instructions in this file without a matching closure row are not a passed gate.

---

## 1. Duration

Run the real system **normally** for **48–72 hours minimum**. A week is better if you are not in a hurry.

Soak starts when baseline samples below are recorded, not when this file lands on `main`.

---

## 2. Exercise

Keep both APIs, the single scheduler, Caddy, postgres, and the WAN scanner up. Do not idle the fleet for the whole window.

| Surface | What to exercise |
|---|---|
| LAN Agents | Both approved site Agents: Nuclei-Pi4 (NUCLEI-AGENT) and TAB1 (docker01) |
| WAN scanner | Central scanner jobs against authorized WAN targets |
| Tenancy | Multiple tenants and sites (overlapping RFC1918 is expected) |
| Schedules | Recurring scan definitions (daily/weekly/cron as already configured) |
| Concurrency | Overlapping / concurrent jobs (LAN + WAN, more than one tenant) |
| Ingest | Assets and findings arriving from completed runs |
| Policy / treatment | Existing treatments and policies continue to apply; create or expire at least one treatment if the live data allows it without breaking a customer story |
| Alerts | Alert creation and deliveries (dashboard/email/webhook as configured) |
| Reports | Generate and download at least one report/export during the window |
| Artifacts | Raw `scan-artifacts` growth and retention behavior |
| Agent reconnect | Stop and start one Agent container (keep `--env-file`); confirm heartbeat and a later LAN job |
| Two APIs | Leave `--scale api=2`. Do not recycle both replicas at once as a soak “test” unless you also record the outage |

Do not invent load that the product does not already run. Prefer real scheduled work plus a small number of deliberate extra runs over a synthetic hammer.

---

## 3. Watch

Sample at soak start, at least twice per day, and at soak end. Prefer `docker compose exec` / `docker stats` on secdock. Record timestamps in UTC.

| Signal | How | Fail if |
|---|---|---|
| PostgreSQL connections | `SELECT count(*) FROM pg_stat_activity;` plus `max_connections` | Unbounded climb, idle-in-transaction pile-up, connection exhaustion |
| Database growth | `SELECT pg_size_pretty(pg_database_size(current_database()));` | Unexplained size jump unrelated to scans/events |
| API / scanner / scheduler CPU+RSS | `sudo docker stats --no-stream` | Unexplained monotonic RSS growth across the window |
| Scheduler | One Compose `scheduler`; advisory lock `91304701` granted once; job duration in scheduler logs | Two APSchedulers; lock held by two backends; jobs that never finish |
| Scan job queue | `scan_jobs.status` counts | Permanently stuck `queued` / `running` / `waiting_for_agent` that never miss, fail, or complete |
| Event/alert queue | `event_alert_queue.status` counts | Permanently `pending`/`processing` growth; duplicate open alerts for the same subject caused by two APIs |
| Alert deliveries | `alert_deliveries.status` counts | Routing finished (`event_alert_queue` processed) while email/webhook rows stay `pending`/`processing`; delivery worker stuck |
| Duplicate processing | Compare job ids, domain events, alert deliveries | Duplicate jobs/events/alerts attributable to two API replicas (scheduler must stay single-active) |
| Agent / scanner spool | Agent `/data/spool`, WAN `scanner-data` | Unbounded growth after ACKs; leftover `pipeline.done` that never uploads |
| `scan-artifacts` | Volume size + `scan_artifacts` row count | Unbounded growth that retention cannot explain |
| Disk | `df -h` on secdock, Agent hosts | Logs or volumes filling the disk (json-file ceiling is 10m × 5 per container) |
| Docker logs | `sudo docker compose logs --since 6h` | Unexpected 4xx/5xx storms, crash loops, lock errors |
| Schedules | Compare due scans vs `scan_jobs` with `trigger_type = scheduled` | Missed schedules with no `missed` job / event |
| Agents | `agents.last_heartbeat` | Stale Agents that do not recover after reconnect |
| Tenant isolation | Spot-check viewer/staff scoped lists vs another tenant’s ids | Any cross-tenant leakage |
| Recovery | Operator notes | Any production recovery beyond expected operations (recreate one replica, restart one Agent, normal backup) |

Starter samples (read-only). Expand `$POSTGRES_USER` / `$POSTGRES_DB` **inside** the postgres container; they come from Compose `.env` and are often blank in the secdock host shell. API `:8000` is not published to host loopback — probe health from an `api` container, not `curl http://127.0.0.1:8000`. (`docker compose exec api` with `--scale api=2` hits one replica; that is enough for this baseline.)

```bash
sudo docker compose exec -T postgres \
  sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<'SQL'
SELECT status, count(*) FROM scan_jobs GROUP BY status ORDER BY 1;
SELECT status, count(*) FROM event_alert_queue GROUP BY status ORDER BY 1;
SELECT status, count(*) FROM alert_deliveries GROUP BY status ORDER BY 1;
SELECT count(*) AS pg_sessions FROM pg_stat_activity;
SELECT pg_size_pretty(pg_database_size(current_database())) AS db_size;
SELECT objid, granted, pid
  FROM pg_locks
 WHERE locktype = 'advisory' AND objid = 91304701;
SELECT id, name, last_heartbeat, status
  FROM agents
 ORDER BY id;
SQL

sudo docker compose exec -T api python -c \
'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8000/api/health").read().decode())'

sudo docker compose ps
sudo docker inspect "$(sudo docker compose ps -q scheduler)" \
  --format '{{json .HostConfig.LogConfig}}'
```

---

## 4. Pass criteria

All of the following must hold for the soak window:

- No data loss
- No cross-tenant leakage
- No permanently stuck scan / job / event / delivery queue
- No duplicate processing caused by the two APIs
- Scheduler remains single-active (advisory lock `91304701`, do not scale scheduler)
- Agents remain healthy and reconnect cleanly
- Storage and log growth is explainable and bounded
- Scans continue completing correctly
- Reports and history remain usable
- No unexplained resource growth
- No production recovery intervention beyond expected operations

A V1A PARTIAL that was already known (no cancel button, tenant-only exclusion UI, and so on) is **not** a V1D fail unless it forces manual SQL/container recovery to keep the product usable.

---

## 5. Fail / abort

Stop the soak and record evidence if any of these happen:

- Data missing or overwritten across tenants
- Queue that cannot drain without dropping rows or restarting PostgreSQL
- Two scheduler leaders, or APScheduler running inside an API replica
- Disk full, log flood, or spool that grows without matching completed jobs
- Agents that cannot re-enroll/heartbeat after a clean compose recreate with `--env-file`
- Need for `docker compose down -v`, a live `alembic downgrade`, or a restore onto production volumes

Then write what failed. Do not “fix it with `0018`” unless the evidence is a demonstrated queue/index problem.

---

## 6. Out of scope for V1D

- V1A product/UX PARTIALs
- Agent pin bump
- Live production certificate rotation
- Re-running V1B restore/rollback unless storage or migrations change
- Phase 4 / V1.1 feature work
- Speculative `0018`

---

## 7. After a pass

1. Write `docs/V1D_CLOSURE.md` with samples, duration, and pass/fail against §4.
2. Hold a **V1 Release Decision** checkpoint (docs-only).
3. Only then create the V1 release tag.
4. Only then write a V1.1 / V2 roadmap.

There is still no Phase 4 in `MASTER_PLAN.md`.
