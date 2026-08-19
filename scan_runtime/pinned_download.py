"""Resolve exact ProjectDiscovery download URLs from the pinned version manifest.

Never uses the GitHub latest-release endpoint. Callers must fail if the
requested release is missing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PINNED_PATH = Path(__file__).resolve().parent / "pinned_versions.json"

TOOL_REPOS = {
    "nuclei": ("nuclei", "nuclei_version"),
    "naabu": ("naabu", "naabu_version"),
    "httpx": ("httpx", "httpx_version"),
}


def load_pinned_versions(path: str | Path | None = None) -> dict[str, str]:
    target = Path(path) if path else PINNED_PATH
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("pinned versions must be an object")
    return {str(key): str(value).strip() for key, value in data.items()}


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


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2:
        print("usage: pinned_download.py zip <nuclei|naabu|httpx> <arch> [manifest]", file=sys.stderr)
        print("       pinned_download.py templates [manifest]", file=sys.stderr)
        return 2
    kind = args[0]
    path = None
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
    print(f"unknown command: {kind}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
