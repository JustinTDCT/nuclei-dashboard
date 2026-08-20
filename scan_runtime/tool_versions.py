"""Canonical scanner runtime / tool / template version collector.

Shared by Agent inventory reporting and per-run ScanJob provenance.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

LogFn = Callable[[str, None], None] | Callable[[str], None]

INVENTORY_FIELDS = (
    "runtime_version",
    "nuclei_version",
    "nuclei_templates_version",
    "naabu_version",
    "httpx_version",
)
MAX_VERSION_CHARS = 200
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_VERSION_TOKEN_RE = re.compile(r"v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.]+)?", re.IGNORECASE)


class VersionCollectionError(RuntimeError):
    pass


def _log(message: str, log: Callable[..., Any] | None = None) -> None:
    if log:
        log(message)
    else:
        print(message, flush=True)


def _which(name: str) -> str | None:
    return shutil.which(name)


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text or "")


def canonicalize_version_text(text: str | None) -> str | None:
    if text is None:
        return None
    cleaned = _strip_ansi(str(text)).strip()
    if not cleaned:
        return None
    return cleaned[:MAX_VERSION_CHARS]


def compact_version(text: str | None) -> str | None:
    cleaned = canonicalize_version_text(text)
    if not cleaned:
        return None
    match = _VERSION_TOKEN_RE.search(cleaned)
    if match:
        return match.group(0)[:MAX_VERSION_CHARS]
    first = cleaned.splitlines()[0].strip()
    return first[:MAX_VERSION_CHARS] if first else None


def load_pinned_runtime_version() -> str | None:
    env = (os.environ.get("SCAN_RUNTIME_VERSION") or "").strip()
    if env:
        return env[:MAX_VERSION_CHARS]
    for candidate in (
        Path(__file__).resolve().parent / "pinned_versions.json",
        Path("/usr/local/share/nuclei-dashboard-pinned-versions.json"),
        Path("/app/pinned_versions.json"),
        Path("/tmp/pinned_versions.json"),
    ):
        if not candidate.is_file():
            continue
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        value = compact_version(str((data or {}).get("runtime_version") or ""))
        if value:
            return value
    return None


def _run_tool(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return _strip_ansi(f"{proc.stdout or ''}\n{proc.stderr or ''}")


def _tool_version(binary: str, extra_args: list[str] | None = None) -> str | None:
    path = binary if os.path.isabs(binary) else _which(binary)
    if not path:
        return None
    args = extra_args if extra_args is not None else ["-version"]
    text = _run_tool([path, *args])
    lowered = text.lower()
    for line in text.splitlines():
        if "engine version" in line.lower() or "current version" in line.lower():
            version = compact_version(line)
            if version:
                return version
    if "projectdiscovery" in lowered or "current version" in lowered or "engine version" in lowered:
        return compact_version(text)
    return compact_version(text.splitlines()[0] if text.strip() else text)


def _pd_httpx() -> str | None:
    for name in ("pd-httpx", "httpx"):
        path = _which(name)
        if not path:
            continue
        text = _run_tool([path, "-version"]).lower()
        if "projectdiscovery" in text or "current version" in text:
            return path
    return None


def _nuclei_templates_version() -> str | None:
    binary = _which("nuclei")
    if not binary:
        return None
    text = _run_tool([binary, "-tv", "-disable-update-check"])
    for line in text.splitlines():
        lowered = line.lower()
        if "public nuclei-templates version" not in lowered and "nuclei-templates version" not in lowered:
            continue
        after = line.split(":", 1)[-1].strip()
        token = after.split("(", 1)[0].strip()
        if not token or token.startswith("("):
            continue
        return compact_version(token) or token[:MAX_VERSION_CHARS]
    for candidate in (
        Path("/opt/nuclei-templates/.nd-templates-version"),
        Path("/home/scanner/nuclei-templates/.nd-templates-version"),
        Path("/root/nuclei-templates/.nd-templates-version"),
    ):
        if candidate.is_file():
            value = compact_version(candidate.read_text(encoding="utf-8"))
            if value:
                return value
    return None


def collect_runtime_inventory(log: Callable[..., Any] | None = None) -> dict[str, str]:
    httpx_bin = _pd_httpx()
    inventory = {
        "runtime_version": load_pinned_runtime_version(),
        "nuclei_version": _tool_version("nuclei"),
        "nuclei_templates_version": _nuclei_templates_version(),
        "naabu_version": _tool_version("naabu"),
        "httpx_version": _tool_version(httpx_bin) if httpx_bin else None,
    }
    compact = {key: value for key, value in inventory.items() if value}
    if log:
        _log("collected runtime inventory: " + ", ".join(f"{k}={v}" for k, v in compact.items()), log)
    return compact


def collect_run_provenance(
    *,
    used_tools: set[str] | None = None,
    dry_run: bool = False,
    log: Callable[..., Any] | None = None,
) -> dict[str, str]:
    inventory = collect_runtime_inventory(log=log)
    if dry_run:
        runtime = inventory.get("runtime_version")
        return {"runtime_version": runtime} if runtime else {}
    required = ["runtime_version"]
    tools = {item.lower() for item in (used_tools or set())}
    if "naabu" in tools:
        required.append("naabu_version")
    if "httpx" in tools:
        required.append("httpx_version")
    if "nuclei" in tools:
        required.extend(["nuclei_version", "nuclei_templates_version"])
    missing = [key for key in required if not inventory.get(key)]
    if missing:
        raise VersionCollectionError(
            "required scanner version provenance could not be determined: " + ", ".join(missing)
        )
    return {key: inventory[key] for key in required}


def collect_tool_versions(log: Callable[..., Any] | None = None) -> dict[str, Any]:
    """Compatibility wrapper used by existing tests and callers."""
    return collect_runtime_inventory(log=log)
