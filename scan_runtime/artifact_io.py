from __future__ import annotations

import gzip
import json
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

LogFn = Callable[[str], None]
CHUNK_SIZE = 1024 * 1024


def log_message(message: str, log: LogFn | None) -> None:
    if log:
        log(message)
    else:
        print(message, flush=True)


def run_command_to_file(cmd: list[str], dest: Path, log: LogFn | None = None) -> None:
    log_message("$ " + " ".join(cmd), log)
    dest.parent.mkdir(parents=True, exist_ok=True)
    stderr_chunks: list[bytes] = []
    stderr_limit = 65536
    with dest.open("wb") as out:
        proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.PIPE)
        assert proc.stderr is not None
        while True:
            chunk = proc.stderr.read(8192)
            if not chunk:
                break
            if sum(len(part) for part in stderr_chunks) < stderr_limit:
                stderr_chunks.append(chunk)
        returncode = proc.wait()
    stderr_text = b"".join(stderr_chunks).decode("utf-8", errors="replace").strip()
    empty = dest.stat().st_size == 0
    if returncode != 0 and empty:
        dest.unlink(missing_ok=True)
        raise RuntimeError(stderr_text or f"command failed: {cmd[0]}")
    if stderr_text:
        log_message(stderr_text, log)


def parse_jsonl_file(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def stream_gzip(src: Path, dest: Path, *, chunk_size: int = CHUNK_SIZE) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as incoming, gzip.open(dest, "wb") as outgoing:
        while True:
            chunk = incoming.read(chunk_size)
            if not chunk:
                break
            outgoing.write(chunk)


def cleanup_staging(staging_dir: str | Path | None) -> None:
    if not staging_dir:
        return
    path = Path(staging_dir)
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)


def artifact_meta(
    *,
    artifact_key: str,
    stage: str,
    tool: str,
    gz_path: Path,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "artifact_key": artifact_key,
        "stage": stage,
        "tool": tool,
        "path": str(gz_path),
        "media_type": "application/x-ndjson",
        "content_encoding": "gzip",
        "provenance": provenance or {},
    }
