#!/bin/bash
# Isolated rollback walk for V1B. Does not touch the production Compose project.
# Uses existing V1B dump. No scanner/scheduler. No down -v on nuclei-dashboard.
set -euo pipefail

ROOT=/home/jdube/nuclei-dashboard
DEST=$(ls -d /home/jdube/v1b-backups/*/ 2>/dev/null | sort | tail -1)
DEST=${DEST%/}
RESTORE_PROJECT=nuclei-v1b-rollback
OVERRIDE=/tmp/v1b-rollback.override.yml
RESTORE=(docker compose -p "$RESTORE_PROJECT" -f "$ROOT/docker-compose.yml" -f "$OVERRIDE" --env-file "$ROOT/.env")

if [ ! -f "$DEST/nuclei.dump" ]; then
  echo "missing dump at $DEST/nuclei.dump" >&2
  exit 1
fi

cat > "$OVERRIDE" <<'YAML'
services:
  api:
    image: nuclei-dashboard-api:latest
    pull_policy: never
    labels:
      v1b.rollback: known-good
  web:
    image: nuclei-dashboard-web:latest
    pull_policy: never
  caddy:
    profiles: ["v1b-rollback-never"]
  scheduler:
    profiles: ["v1b-rollback-never"]
  scanner:
    profiles: ["v1b-rollback-never"]
YAML

"${RESTORE[@]}" down -v >/dev/null 2>&1 || true

echo "== known-good SHA context =="
echo "LIVE_GIT=$(git -C "$ROOT" rev-parse HEAD)"
echo "DUMP=$DEST/nuclei.dump"

"${RESTORE[@]}" up -d --no-build postgres
for i in $(seq 1 30); do
  if "${RESTORE[@]}" exec -T postgres sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
"${RESTORE[@]}" exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner' \
  < "$DEST/nuclei.dump"
"${RESTORE[@]}" up -d --no-build postgres api
for i in $(seq 1 40); do
  if "${RESTORE[@]}" exec -T api python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" >/dev/null 2>&1; then
    break
  fi
  sleep 3
done

PG_VOL_BEFORE=$(docker volume inspect "${RESTORE_PROJECT}_postgres-data" --format '{{.Mountpoint}} {{.CreatedAt}}')
ART_VOL_BEFORE=$(docker volume inspect "${RESTORE_PROJECT}_scan-artifacts" --format '{{.Mountpoint}} {{.CreatedAt}}' 2>/dev/null || echo "scan-artifacts-not-yet")
STAGE_BEFORE=$(docker inspect "${RESTORE_PROJECT}-api-1" --format '{{index .Config.Labels "v1b.rollback"}}')
ALEMBIC_BEFORE=$("${RESTORE[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT version_num FROM alembic_version"')
echo "PG_VOL_BEFORE=$PG_VOL_BEFORE"
echo "STAGE_BEFORE=$STAGE_BEFORE"
echo "ALEMBIC_BEFORE=$ALEMBIC_BEFORE"

echo "== deploy harmless later config (same schema) =="
sed -i 's/known-good/later/' "$OVERRIDE"
"${RESTORE[@]}" up -d --no-build --no-deps --force-recreate api
for i in $(seq 1 40); do
  if "${RESTORE[@]}" exec -T api python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" >/dev/null 2>&1; then
    break
  fi
  sleep 3
done
STAGE_LATER=$(docker inspect "${RESTORE_PROJECT}-api-1" --format '{{index .Config.Labels "v1b.rollback"}}')
ALEMBIC_LATER=$("${RESTORE[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT version_num FROM alembic_version"')
echo "STAGE_LATER=$STAGE_LATER"
echo "ALEMBIC_LATER=$ALEMBIC_LATER"

echo "== return to prior application config =="
sed -i 's/later/known-good/' "$OVERRIDE"
"${RESTORE[@]}" up -d --no-build --no-deps --force-recreate api
for i in $(seq 1 40); do
  if "${RESTORE[@]}" exec -T api python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" >/dev/null 2>&1; then
    break
  fi
  sleep 3
done
STAGE_AFTER=$(docker inspect "${RESTORE_PROJECT}-api-1" --format '{{index .Config.Labels "v1b.rollback"}}')
ALEMBIC_AFTER=$("${RESTORE[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT version_num FROM alembic_version"')
PG_VOL_AFTER=$(docker volume inspect "${RESTORE_PROJECT}_postgres-data" --format '{{.Mountpoint}} {{.CreatedAt}}')
echo "STAGE_AFTER=$STAGE_AFTER"
echo "ALEMBIC_AFTER=$ALEMBIC_AFTER"
echo "PG_VOL_AFTER=$PG_VOL_AFTER"

if [ "$STAGE_LATER" != "later" ] || [ "$STAGE_AFTER" != "known-good" ]; then
  echo "STAGE_WALK_FAILED" >&2
  exit 1
fi
if [ "$ALEMBIC_BEFORE" != "0017_security_h6_h8" ] || [ "$ALEMBIC_LATER" != "$ALEMBIC_BEFORE" ] || [ "$ALEMBIC_AFTER" != "$ALEMBIC_BEFORE" ]; then
  echo "ALEMBIC_WALK_FAILED" >&2
  exit 1
fi
if [ "$PG_VOL_BEFORE" != "$PG_VOL_AFTER" ]; then
  echo "VOLUME_REPLACED" >&2
  exit 1
fi

echo "== alembic downgrade must refuse (restore, not guess) =="
set +e
DOWNGRADE_OUT=$("${RESTORE[@]}" exec -T api alembic downgrade 0016 2>&1)
DOWNGRADE_RC=$?
set -e
echo "$DOWNGRADE_OUT" | tail -20
echo "DOWNGRADE_RC=$DOWNGRADE_RC"
if [ "$DOWNGRADE_RC" -eq 0 ]; then
  echo "DOWNGRADE_SHOULD_HAVE_REFUSED" >&2
  exit 1
fi
echo "$DOWNGRADE_OUT" | grep -q "Refusing to downgrade 0017_security_h6_h8"
ALEMBIC_STILL=$("${RESTORE[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT version_num FROM alembic_version"')
if [ "$ALEMBIC_STILL" != "0017_security_h6_h8" ]; then
  echo "DOWNGRADE_DAMAGED_SCHEMA" >&2
  exit 1
fi

echo "== destroy isolated rollback project only =="
"${RESTORE[@]}" down -v
echo V1B_ROLLBACK_WALK_OK
