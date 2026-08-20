#!/bin/sh
set -eu

ARCH="${1:-}"
if [ -z "$ARCH" ]; then
  ARCH="$(uname -m)"
fi
case "$ARCH" in
  amd64|x86_64) PDARCH="amd64" ;;
  arm64|aarch64) PDARCH="arm64" ;;
  *)
    echo "Unsupported architecture: ${ARCH}" >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
VERSIONS_FILE="${VERSIONS_FILE:-}"
if [ -z "$VERSIONS_FILE" ]; then
  if [ -f "/tmp/pinned_versions.json" ]; then
    VERSIONS_FILE="/tmp/pinned_versions.json"
  else
    VERSIONS_FILE="${SCRIPT_DIR}/pinned_versions.json"
  fi
fi
DOWNLOADER="${DOWNLOADER:-}"
if [ -z "$DOWNLOADER" ]; then
  if [ -f "/tmp/pinned_download.py" ]; then
    DOWNLOADER="/tmp/pinned_download.py"
  else
    DOWNLOADER="${SCRIPT_DIR}/pinned_download.py"
  fi
fi

if [ ! -f "$VERSIONS_FILE" ]; then
  echo "Pinned versions file not found: ${VERSIONS_FILE}" >&2
  exit 1
fi

read_pin() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$VERSIONS_FILE" "$1"
}

verify_sha256() {
  file="$1"
  expected="$2"
  if [ -z "$expected" ]; then
    echo "Missing SHA-256 pin for ${file}" >&2
    rm -f "$file"
    exit 1
  fi
  actual="$(sha256sum "$file" | awk '{print $1}')"
  if [ "$actual" != "$expected" ]; then
    echo "SHA-256 mismatch for ${file}" >&2
    echo "expected ${expected}" >&2
    echo "actual   ${actual}" >&2
    rm -f "$file"
    exit 1
  fi
}

install_pd() {
  bin="$1"
  echo "Installing pinned ${bin} (${PDARCH})"
  url="$(python3 "$DOWNLOADER" zip "$bin" "$PDARCH" "$VERSIONS_FILE")"
  expected="$(python3 "$DOWNLOADER" checksum zip "$bin" "$PDARCH" "$VERSIONS_FILE")"
  echo "Fetching ${url}"
  if ! curl -fsSL "$url" -o "/tmp/${bin}.zip"; then
    echo "Pinned ${bin} release was not found. Refusing to fall back to latest: ${url}" >&2
    exit 1
  fi
  verify_sha256 "/tmp/${bin}.zip" "$expected"
  unzip -o "/tmp/${bin}.zip" -d /tmp/pdout
  find /tmp/pdout -type f -name "$bin" -exec mv {} "/usr/local/bin/${bin}" \;
  chmod +x "/usr/local/bin/${bin}"
  rm -rf /tmp/pdout "/tmp/${bin}.zip"
  "$bin" -version
}

install_templates() {
  tag="$(read_pin nuclei_templates_version)"
  url="$(python3 "$DOWNLOADER" templates "$VERSIONS_FILE")"
  expected="$(python3 "$DOWNLOADER" checksum templates "$VERSIONS_FILE")"
  echo "Installing pinned nuclei-templates ${tag}"
  echo "Fetching ${url}"
  if ! curl -fsSL "$url" -o /tmp/nuclei-templates.tar.gz; then
    echo "Pinned nuclei-templates release was not found. Refusing to fall back to latest: ${url}" >&2
    exit 1
  fi
  verify_sha256 /tmp/nuclei-templates.tar.gz "$expected"
  mkdir -p /tmp/templates-src /opt/nuclei-templates /root/nuclei-templates
  tar -xzf /tmp/nuclei-templates.tar.gz -C /tmp/templates-src
  top="$(find /tmp/templates-src -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [ -z "$top" ]; then
    echo "Pinned nuclei-templates archive did not contain a directory" >&2
    exit 1
  fi
  cp -a "$top"/. /opt/nuclei-templates/
  cp -a "$top"/. /root/nuclei-templates/
  printf '%s\n' "$tag" > /opt/nuclei-templates/.nd-templates-version
  mkdir -p /root/.config/nuclei
  python3 -c '
import json, sys
tag = sys.argv[1]
nuclei = sys.argv[2]
path = "/root/.config/nuclei/.templates-config.json"
print(json.dumps({
    "nuclei-templates-directory": "/opt/nuclei-templates",
    "nuclei-templates-version": tag,
    "nuclei-templates-latest-version": tag,
    "nuclei-latest-version": nuclei,
}, indent=2))
' "$tag" "$(read_pin nuclei_version)" > /root/.config/nuclei/.templates-config.json
  cat > /root/.config/nuclei/config.yaml <<'EOF'
disable-update-check: true
EOF
  rm -rf /tmp/templates-src /tmp/nuclei-templates.tar.gz
}

install_pd nuclei
install_pd naabu
install_pd httpx
# Python's httpx package also ships a CLI named httpx; keep the PD binary.
cp /usr/local/bin/httpx /usr/local/bin/pd-httpx
chmod +x /usr/local/bin/pd-httpx
# httpx v1.10.0 initializes the DIT page classifier on -json and otherwise
# downloads ~92MB from Hugging Face into ~/.dit/model.json. We do not use
# PageType. Seed a local stub so cold Agents stay offline and deterministic.
mkdir -p /root/.dit
printf '%s\n' '{}' > /root/.dit/model.json
install_templates
mkdir -p /usr/local/share
cp "$VERSIONS_FILE" /usr/local/share/nuclei-dashboard-pinned-versions.json
