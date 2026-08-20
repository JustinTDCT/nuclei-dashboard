"""Resolve exact ProjectDiscovery download URLs and SHA-256 pins.

Never uses the GitHub latest-release endpoint. Callers must fail if the
requested release or checksum is missing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PINNED_PATH = Path(__file__).resolve().parent / "pinned_versions.json"
VERSION_KEYS = (
    "runtime_version",
    "nuclei_version",
    "nuclei_templates_version",
    "naabu_version",
    "httpx_version",
)
TOOL_REPOS = {
    "nuclei": ("nuclei", "nuclei_version"),
    "naabu": ("naabu", "naabu_version"),
    "httpx": ("httpx", "httpx_version"),
}


def load_pinned_manifest(path: str | Path | None = None) -> dict:
    target = Path(path) if path else PINNED_PATH
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("pinned versions must be an object")
    return data


def load_pinned_versions(path: str | Path | None = None) -> dict[str, str]:
    data = load_pinned_manifest(path)
    versions: dict[str, str] = {}
    for key in VERSION_KEYS:
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"missing pinned {key}")
        versions[key] = value.strip()
    return versions


def load_pinned_checksums(path: str | Path | None = None) -> dict[str, str]:
    data = load_pinned_manifest(path)
    raw = data.get("checksums_sha256")
    if not isinstance(raw, dict) or not raw:
        raise ValueError("pinned checksums_sha256 is missing")
    checksums: dict[str, str] = {}
    for key, value in raw.items():
        digest = str(value or "").strip().lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError(f"invalid SHA-256 pin for {key}")
        checksums[str(key)] = digest
    return checksums


def release_tag(value: str) -> str:
    text = (value or "").strip()
    if not text:
        raise ValueError("pinned release tag is empty")
    return text if text.lower().startswith("v") else f"v{text}"


def release_number(value: str) -> str:
    tag = release_tag(value)
    return tag[1:] if tag.lower().startswith("v") else tag


def github_zip_url(repo: str, binary: str, tag: str, arch: str) -> str:
    version = release_number(tag)
    named_tag = release_tag(tag)
    return (
        f"https://github.com/projectdiscovery/{repo}/releases/download/"
        f"{named_tag}/{binary}_{version}_linux_{arch}.zip"
    )


def templates_archive_url(tag: str) -> str:
    return (
        "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/"
        f"{release_tag(tag)}.tar.gz"
    )


def tool_zip_url(binary: str, arch: str, pins: dict[str, str] | None = None) -> str:
    if binary not in TOOL_REPOS:
        raise ValueError(f"unsupported pinned tool: {binary}")
    repo, key = TOOL_REPOS[binary]
    versions = pins or load_pinned_versions()
    tag = versions.get(key) or ""
    if not tag:
        raise ValueError(f"missing pinned {key}")
    return github_zip_url(repo, binary, tag, arch)


def checksum_for(kind: str, *, binary: str = "", arch: str = "", path: str | Path | None = None) -> str:
    checksums = load_pinned_checksums(path)
    if kind == "zip":
        if binary not in TOOL_REPOS:
            raise ValueError(f"unsupported pinned tool: {binary}")
        key = f"{binary}_linux_{arch}"
    elif kind == "templates":
        key = "nuclei_templates"
    else:
        raise ValueError(f"unsupported checksum kind: {kind}")
    digest = checksums.get(key) or ""
    if not digest:
        raise ValueError(f"missing SHA-256 pin for {key}")
    return digest


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: pinned_download.py zip <nuclei|naabu|httpx> <arch> [manifest]", file=sys.stderr)
        print("       pinned_download.py templates [manifest]", file=sys.stderr)
        print("       pinned_download.py checksum zip <nuclei|naabu|httpx> <arch> [manifest]", file=sys.stderr)
        print("       pinned_download.py checksum templates [manifest]", file=sys.stderr)
        return 2
    kind = args[0]
    if kind == "zip":
        if len(args) < 3:
            print("usage: pinned_download.py zip <binary> <arch> [manifest]", file=sys.stderr)
            return 2
        binary, arch = args[1], args[2]
        path = args[3] if len(args) > 3 else None
        pins = load_pinned_versions(path)
        print(tool_zip_url(binary, arch, pins))
        return 0
    if kind == "templates":
        path = args[1] if len(args) > 1 else None
        pins = load_pinned_versions(path)
        print(templates_archive_url(pins["nuclei_templates_version"]))
        return 0
    if kind == "checksum":
        if len(args) < 2:
            print("usage: pinned_download.py checksum zip <binary> <arch> [manifest]", file=sys.stderr)
            return 2
        checksum_kind = args[1]
        if checksum_kind == "zip":
            if len(args) < 4:
                print("usage: pinned_download.py checksum zip <binary> <arch> [manifest]", file=sys.stderr)
                return 2
            print(checksum_for("zip", binary=args[2], arch=args[3], path=args[4] if len(args) > 4 else None))
            return 0
        if checksum_kind == "templates":
            print(checksum_for("templates", path=args[2] if len(args) > 2 else None))
            return 0
        print(f"unknown checksum kind: {checksum_kind}", file=sys.stderr)
        return 2
    print(f"unknown command: {kind}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
