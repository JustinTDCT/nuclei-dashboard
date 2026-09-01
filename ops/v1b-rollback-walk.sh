#!/bin/bash
# Isolated application-image rollback walk for V1B.
# Does not touch the production Compose project. No scanner/scheduler.
# No down -v on nuclei-dashboard. Does not retag nuclei-dashboard-api:latest.
#
# Walks two schema-compatible immutable API images:
#   known-good → later → known-good
# Postgres readiness and API /api/health waits fail closed (nonzero) on timeout.
# Image IDs must differ; the final container must be the original known-good ID.
set -euo pipefail

ROOT="${ROOT:-/home/jdube/nuclei-dashboard}"
DEST="${DEST:-$(ls -d /home/jdube/v1b-backups/*/ 2>/dev/null | sort | tail -1)}"
DEST=${DEST%/}
RESTORE_PROJECT="${RESTORE_PROJECT:-nuclei-v1b-rollback}"
OVERRIDE="${OVERRIDE:-/tmp/v1b-rollback.override.yml}"
KNOWN_GOOD_SHA="${KNOWN_GOOD_SHA:-7f5b4af121cc8d1a7269ec6dc28fd3878c341c99}"
LATER_SHA="${LATER_SHA:-d161490b7b3bcb3cb87eb843549395a6c38bffed}"
KNOWN_GOOD_IMAGE="${KNOWN_GOOD_IMAGE:-nuclei-dashboard-api:v1b-7f5b4af}"
LATER_IMAGE="${LATER_IMAGE:-nuclei-dashboard-api:v1b-d161490}"
RESTORE=(docker compose -p "$RESTORE_PROJECT" -f "$ROOT/docker-compose.yml" -f "$OVERRIDE" --env-file "$ROOT/.env")

if [ "$RESTORE_PROJECT" = "nuclei-dashboard" ]; then
  echo "refusing production Compose project name" >&2
  exit 1
fi

wait_postgres_ready() {
  local i
  for i in $(seq 1 30); do
    if "${RESTORE[@]}" exec -T postgres sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "POSTGRES_NOT_READY" >&2
  return 1
}

wait_api_health() {
  local i
  for i in $(seq 1 40); do
    if "${RESTORE[@]}" exec -T api python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" >/dev/null 2>&1; then
      return 0
    fi
    sleep 3
  done
  echo "API_HEALTH_TIMEOUT" >&2
  return 1
}

write_override() {
  local image="$1"
  local stage="$2"
  case "$image" in
    *[!A-Za-z0-9._/:@-]*)
      echo "refusing image name: $image" >&2
      exit 1
      ;;
  esac
  cat > "$OVERRIDE" <<YAML
services:
  api:
    image: ${image}
    pull_policy: never
    labels:
      v1b.rollback: ${stage}
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
}

image_id() {
  docker image inspect -f '{{.Id}}' "$1"
}

container_image_id() {
  docker inspect -f '{{.Image}}' "${RESTORE_PROJECT}-api-1"
}

container_image_ref() {
  docker inspect -f '{{.Config.Image}}' "${RESTORE_PROJECT}-api-1"
}

ensure_api_image() {
  local sha="$1"
  local tag="$2"
  if docker image inspect "$tag" >/dev/null 2>&1; then
    echo "using existing $tag"
    return 0
  fi
  if ! git -C "$ROOT" cat-file -e "${sha}^{commit}"; then
    echo "missing commit $sha in $ROOT; git fetch origin first" >&2
    exit 1
  fi
  echo "== building $tag from $sha (does not retag :latest) =="
  local tmp
  tmp=$(mktemp -d)
  git -C "$ROOT" archive "$sha" backend | tar -C "$tmp" -x
  docker build -t "$tag" "$tmp/backend"
  rm -rf "$tmp"
}

if [ ! -f "$DEST/nuclei.dump" ]; then
  echo "missing dump at $DEST/nuclei.dump" >&2
  exit 1
fi

ensure_api_image "$KNOWN_GOOD_SHA" "$KNOWN_GOOD_IMAGE"
ensure_api_image "$LATER_SHA" "$LATER_IMAGE"

KNOWN_GOOD_ID=$(image_id "$KNOWN_GOOD_IMAGE")
LATER_ID=$(image_id "$LATER_IMAGE")
echo "KNOWN_GOOD_IMAGE=$KNOWN_GOOD_IMAGE"
echo "KNOWN_GOOD_SHA=$KNOWN_GOOD_SHA"
echo "KNOWN_GOOD_ID=$KNOWN_GOOD_ID"
echo "LATER_IMAGE=$LATER_IMAGE"
echo "LATER_SHA=$LATER_SHA"
echo "LATER_ID=$LATER_ID"
if [ "$KNOWN_GOOD_ID" = "$LATER_ID" ]; then
  echo "IMAGES_NOT_DISTINCT" >&2
  exit 1
fi

write_override "$KNOWN_GOOD_IMAGE" "known-good"

"${RESTORE[@]}" down -v >/dev/null 2>&1 || true

echo "== known-good image against restored DB =="
echo "LIVE_GIT=$(git -C "$ROOT" rev-parse HEAD)"
echo "DUMP=$DEST/nuclei.dump"

"${RESTORE[@]}" up -d --no-build postgres
wait_postgres_ready
"${RESTORE[@]}" exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner' \
  < "$DEST/nuclei.dump"
"${RESTORE[@]}" up -d --no-build postgres api
wait_api_health

PG_VOL_BEFORE=$(docker volume inspect "${RESTORE_PROJECT}_postgres-data" --format '{{.Mountpoint}} {{.CreatedAt}}')
STAGE_BEFORE=$(docker inspect "${RESTORE_PROJECT}-api-1" --format '{{index .Config.Labels "v1b.rollback"}}')
IMAGE_BEFORE=$(container_image_id)
IMAGE_REF_BEFORE=$(container_image_ref)
ALEMBIC_BEFORE=$("${RESTORE[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT version_num FROM alembic_version"')
echo "PG_VOL_BEFORE=$PG_VOL_BEFORE"
echo "STAGE_BEFORE=$STAGE_BEFORE"
echo "IMAGE_REF_BEFORE=$IMAGE_REF_BEFORE"
echo "IMAGE_BEFORE=$IMAGE_BEFORE"
echo "ALEMBIC_BEFORE=$ALEMBIC_BEFORE"
if [ "$IMAGE_BEFORE" != "$KNOWN_GOOD_ID" ] || [ "$IMAGE_REF_BEFORE" != "$KNOWN_GOOD_IMAGE" ]; then
  echo "KNOWN_GOOD_IMAGE_MISMATCH" >&2
  exit 1
fi

echo "== deploy later immutable image (same schema) =="
write_override "$LATER_IMAGE" "later"
"${RESTORE[@]}" up -d --no-build --no-deps --force-recreate api
wait_api_health
STAGE_LATER=$(docker inspect "${RESTORE_PROJECT}-api-1" --format '{{index .Config.Labels "v1b.rollback"}}')
IMAGE_LATER=$(container_image_id)
IMAGE_REF_LATER=$(container_image_ref)
ALEMBIC_LATER=$("${RESTORE[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT version_num FROM alembic_version"')
echo "STAGE_LATER=$STAGE_LATER"
echo "IMAGE_REF_LATER=$IMAGE_REF_LATER"
echo "IMAGE_LATER=$IMAGE_LATER"
echo "ALEMBIC_LATER=$ALEMBIC_LATER"
if [ "$IMAGE_LATER" != "$LATER_ID" ] || [ "$IMAGE_REF_LATER" != "$LATER_IMAGE" ]; then
  echo "LATER_IMAGE_MISMATCH" >&2
  exit 1
fi

echo "== return to exact known-good image =="
write_override "$KNOWN_GOOD_IMAGE" "known-good"
"${RESTORE[@]}" up -d --no-build --no-deps --force-recreate api
wait_api_health
STAGE_AFTER=$(docker inspect "${RESTORE_PROJECT}-api-1" --format '{{index .Config.Labels "v1b.rollback"}}')
IMAGE_AFTER=$(container_image_id)
IMAGE_REF_AFTER=$(container_image_ref)
ALEMBIC_AFTER=$("${RESTORE[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT version_num FROM alembic_version"')
PG_VOL_AFTER=$(docker volume inspect "${RESTORE_PROJECT}_postgres-data" --format '{{.Mountpoint}} {{.CreatedAt}}')
echo "STAGE_AFTER=$STAGE_AFTER"
echo "IMAGE_REF_AFTER=$IMAGE_REF_AFTER"
echo "IMAGE_AFTER=$IMAGE_AFTER"
echo "ALEMBIC_AFTER=$ALEMBIC_AFTER"
echo "PG_VOL_AFTER=$PG_VOL_AFTER"

if [ "$STAGE_LATER" != "later" ] || [ "$STAGE_AFTER" != "known-good" ]; then
  echo "STAGE_WALK_FAILED" >&2
  exit 1
fi
if [ "$IMAGE_AFTER" != "$KNOWN_GOOD_ID" ] || [ "$IMAGE_AFTER" != "$IMAGE_BEFORE" ]; then
  echo "ROLLBACK_IMAGE_MISMATCH" >&2
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
