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

install_pd() {
  repo="$1"
  bin="$2"
  echo "Installing ${bin} (${PDARCH}) from ${repo}"
  url=$(curl -fsSL "https://api.github.com/repos/projectdiscovery/${repo}/releases/latest" \
    | python3 -c "import json,sys
assets=json.load(sys.stdin).get('assets', [])
need=f'linux_{sys.argv[1]}'
matches=[a['browser_download_url'] for a in assets if need in a['name'] and a['name'].endswith('.zip')]
if not matches:
    raise SystemExit(f'no linux_{sys.argv[1]} zip for {sys.argv[2]}')
print(matches[0])
" "$PDARCH" "$bin")
  curl -fsSL "$url" -o "/tmp/${bin}.zip"
  unzip -o "/tmp/${bin}.zip" -d /tmp/pdout
  find /tmp/pdout -type f -name "$bin" -exec mv {} "/usr/local/bin/${bin}" \;
  chmod +x "/usr/local/bin/${bin}"
  rm -rf /tmp/pdout "/tmp/${bin}.zip"
  "$bin" -version
}

install_pd nuclei nuclei
install_pd naabu naabu
install_pd httpx httpx
# Python's httpx package also ships a CLI named httpx; keep the PD binary.
cp /usr/local/bin/httpx /usr/local/bin/pd-httpx
chmod +x /usr/local/bin/pd-httpx
