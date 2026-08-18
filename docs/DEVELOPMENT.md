# Development and deployment notes

`MASTER_PLAN.md` is the canonical architecture and phase contract. Do not implement later phases from it unless the current task says so.

## Database migrations (Alembic)

Schema changes belong in versioned Alembic revisions under `backend/alembic/versions/`. Do not add new `ALTER TABLE` statements to application startup.

From `backend/`, with `DATABASE_URL` set:

```bash
alembic current
alembic upgrade head
alembic history
alembic revision -m "describe the change"
```

Current baseline revision: `0001_baseline`.

`alembic downgrade` from `0001_baseline` drops the application schema and **destroys data**. There is no non-destructive downgrade from the baseline.

### Fresh install

Start the stack. API startup runs `apply_schema()`, which is `alembic upgrade head` on an empty database, then seeds the first admin.

Do not delete the PostgreSQL volume as a normal operation.

### Existing install (pre-Alembic)

1. Deploy this version **without** removing the `postgres-data` volume.
2. Restart the API.

Startup detects the current tables, runs the retained compatibility helper (`ensure_columns`) so leftover columns/constraints match today's models, stamps `0001_baseline`, then upgrades to head. Existing rows are not dropped.

Manual adoption of a current-schema database (same non-destructive stamp, only if you are not using API startup):

```bash
cd backend
alembic stamp 0001_baseline
alembic upgrade head
```

Stamp only a database that already matches the current application schema. Do not stamp a partial or unknown schema.

### Tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest
```

Migration tests start an isolated PostgreSQL on `127.0.0.1:55432` via Docker, or use `TEST_DATABASE_URL` if you set it.

## TLS verification

Generated agent compose/env and production defaults verify central-server TLS (`TLS_VERIFY=1` / `AGENT_TLS_VERIFY=1`).

Publicly trusted certificates need no extra agent configuration.

Internal CA (including Caddy's local CA): keep verification **on**. Give the agent the CA file:

- `TLS_CA_FILE=/path/to/ca.pem`, or
- `TLS_VERIFY=/path/to/ca.pem`

Caddy's local root is typically `root.crt` under the `caddy-data` volume (`pki/authorities/local/`). Copy that file to the agent host and point `TLS_CA_FILE` at it. Do not embed environment-specific CA material in the repository.

Development opt-out only: `AGENT_TLS_VERIFY=0` or `TLS_VERIFY=0`.

## Viewer / Auditor

Viewer is read-only. A Viewer may list agents and see status. A Viewer must not create/approve/revoke agents and must not download compose or env files that can contain an active enrollment secret. Admin and User remain the deployment roles.
