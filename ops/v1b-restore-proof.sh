#!/bin/bash
# Isolated restore proof for V1B. Run on the central host with docker sudo.
# Does not stop production. Does not docker compose down -v on the live project.
set -euo pipefail

ROOT="${ROOT:-/home/jdube/nuclei-dashboard}"
LIVE_COMPOSE=(docker compose -f "$ROOT/docker-compose.yml" --env-file "$ROOT/.env")
STAMP="${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
DEST="${DEST:-/home/jdube/v1b-backups/$STAMP}"
RESTORE_PROJECT="${RESTORE_PROJECT:-nuclei-v1b-restore}"
RESTORE_COMPOSE=(docker compose -p "$RESTORE_PROJECT" -f "$ROOT/docker-compose.yml" -f /tmp/v1b-restore.override.yml --env-file "$ROOT/.env")
LIVE_ARTIFACTS_VOL="${LIVE_ARTIFACTS_VOL:-nuclei-dashboard_scan-artifacts}"
RESTORE_ARTIFACTS_VOL="${RESTORE_PROJECT}_scan-artifacts"

mkdir -p "$DEST"

cat > /tmp/v1b-restore.override.yml <<'YAML'
services:
  api:
    image: nuclei-dashboard-api:latest
    pull_policy: never
  web:
    image: nuclei-dashboard-web:latest
    pull_policy: never
  caddy:
    ports: !override
      - "18118:8118"
  scheduler:
    profiles: ["v1b-restore-never"]
  scanner:
    profiles: ["v1b-restore-never"]
YAML

# Any leftover isolated proof from a previous attempt. Never the live project.
"${RESTORE_COMPOSE[@]}" down -v >/dev/null 2>&1 || true

echo "== counts before dump =="
"${LIVE_COMPOSE[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "
SELECT '\''alembic'\'', version_num FROM alembic_version;
SELECT '\''tenants'\'', count(*)::text FROM tenants;
SELECT '\''assets'\'', count(*)::text FROM assets;
SELECT '\''findings'\'', count(*)::text FROM findings;
SELECT '\''scan_jobs'\'', count(*)::text FROM scan_jobs;
SELECT '\''scan_artifacts'\'', count(*)::text FROM scan_artifacts;
"' | tee "$DEST/live-counts.txt"

echo "== artifact sample =="
"${LIVE_COMPOSE[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "
SELECT id || '\'' '\'' || scan_job_id || '\'' '\'' || sha256 || '\'' '\'' || size_bytes || '\'' '\'' || coalesce(deleted_at::text, '\''active'\'')
FROM scan_artifacts WHERE deleted_at IS NULL ORDER BY id DESC LIMIT 1;
"' | tee "$DEST/live-artifact-sample.txt"

echo "== pg_dump =="
"${LIVE_COMPOSE[@]}" exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$DEST/nuclei.dump"
ls -lh "$DEST/nuclei.dump"

echo "== scan-artifacts tarball =="
docker run --rm -v "$LIVE_ARTIFACTS_VOL":/src:ro -v "$DEST":/dst alpine \
  tar -C /src -czf /dst/scan-artifacts.tar.gz .
ls -lh "$DEST/scan-artifacts.tar.gz"

echo "== start isolated postgres =="
"${RESTORE_COMPOSE[@]}" up -d --no-build postgres
for i in $(seq 1 30); do
  if "${RESTORE_COMPOSE[@]}" exec -T postgres sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
"${RESTORE_COMPOSE[@]}" exec -T postgres sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"'

echo "== pg_restore =="
"${RESTORE_COMPOSE[@]}" exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner' \
  < "$DEST/nuclei.dump"

echo "== start api web caddy (no scheduler/scanner) =="
"${RESTORE_COMPOSE[@]}" up -d --no-build postgres api web caddy
for i in $(seq 1 40); do
  if "${RESTORE_COMPOSE[@]}" exec -T api python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" >/dev/null 2>&1; then
    break
  fi
  sleep 3
done

echo "== load artifacts into restore volume =="
docker run --rm -v "$RESTORE_ARTIFACTS_VOL":/dst -v "$DEST":/src alpine \
  tar -C /dst -xzf /src/scan-artifacts.tar.gz

echo "== restored counts =="
"${RESTORE_COMPOSE[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "
SELECT '\''alembic'\'', version_num FROM alembic_version;
SELECT '\''tenants'\'', count(*)::text FROM tenants;
SELECT '\''assets'\'', count(*)::text FROM assets;
SELECT '\''findings'\'', count(*)::text FROM findings;
SELECT '\''scan_jobs'\'', count(*)::text FROM scan_jobs;
SELECT '\''scan_artifacts'\'', count(*)::text FROM scan_artifacts;
"' | tee "$DEST/restored-counts.txt"

echo "== compare counts =="
diff -u "$DEST/live-counts.txt" "$DEST/restored-counts.txt"

echo "== health through isolated caddy =="
curl -sk --cacert "$ROOT/certs/cert.pem" --resolve scanner.thedubes.net:18118:127.0.0.1 \
  https://scanner.thedubes.net:18118/api/health
echo

export ROOT DEST
echo "== login + artifact download =="
python3 - <<'PY'
import hashlib, json, os, subprocess, sys
from pathlib import Path

root = Path(os.environ.get("ROOT", "/home/jdube/nuclei-dashboard"))
dest = Path(os.environ["DEST"])
env = {}
for line in (root / ".env").read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, _, value = line.partition("=")
    env[key.strip()] = value.strip().strip('"').strip("'")
user = env.get("ADMIN_USERNAME") or "admin"
password = env.get("ADMIN_PASSWORD") or ""
curl = [
    "curl", "-sk", "--fail", "--cacert", str(root / "certs/cert.pem"),
    "--resolve", "scanner.thedubes.net:18118:127.0.0.1",
]
login = subprocess.run(
    curl + ["-H", "content-type: application/json", "-d",
            json.dumps({"username": user, "password": password}),
            "https://scanner.thedubes.net:18118/api/auth/login"],
    capture_output=True, text=True, check=False,
)
if login.returncode != 0:
    sys.stderr.write(login.stderr or login.stdout or "login curl failed\n")
    raise SystemExit("LOGIN_FAILED")
payload = json.loads(login.stdout)
token = payload.get("access_token") or ""
if not token:
    raise SystemExit("LOGIN_FAILED keys=" + ",".join(payload.keys()))
print("LOGIN_OK")
sample = (dest / "live-artifact-sample.txt").read_text().strip().split()
art_id, expect_sha = sample[0], sample[2]
out = dest / "downloaded-artifact.bin"
dl = subprocess.run(
    curl + ["-H", f"Authorization: Bearer {token}", "-o", str(out),
            f"https://scanner.thedubes.net:18118/api/scan-artifacts/{art_id}/download"],
    capture_output=True, text=True, check=False,
)
if dl.returncode != 0:
    sys.stderr.write(dl.stderr or "download curl failed\n")
    raise SystemExit("ARTIFACT_DOWNLOAD_FAILED")
got = hashlib.sha256(out.read_bytes()).hexdigest()
print(f"artifact_id={art_id} expected_sha={expect_sha} got_sha={got}")
if got != expect_sha:
    raise SystemExit("ARTIFACT_SHA_MISMATCH")
print("ARTIFACT_DOWNLOAD_OK")
PY
echo DEST="$DEST"
echo RESTORE_PROJECT="$RESTORE_PROJECT"
echo V1B_RESTORE_PROOF_OK
