from __future__ import annotations

import gzip
import json
import os
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

LogFn = Callable[[str], None]
CHUNK_SIZE = 1024 * 1024
PROGRESS_POLL_SECONDS = 30.0
DEFAULT_KILL_GRACE_SECONDS = 5.0
PROGRESS_FAST_UNTIL_SECONDS = 600.0
PROGRESS_MEDIUM_UNTIL_SECONDS = 1800.0
PROGRESS_FAST_INTERVAL_SECONDS = 30.0
PROGRESS_MEDIUM_INTERVAL_SECONDS = 120.0
PROGRESS_SLOW_INTERVAL_SECONDS = 300.0


def progress_interval_for_elapsed(elapsed: float) -> float:
    """Keep long scans visible without a hard silence cap.

    0–10 min: every 30s; 10–30 min: every 2 min; 30+ min: every 5 min.
    """
    if elapsed < PROGRESS_FAST_UNTIL_SECONDS:
        return PROGRESS_FAST_INTERVAL_SECONDS
    if elapsed < PROGRESS_MEDIUM_UNTIL_SECONDS:
        return PROGRESS_MEDIUM_INTERVAL_SECONDS
    return PROGRESS_SLOW_INTERVAL_SECONDS


def log_message(message: str, log: LogFn | None) -> None:
    if log:
        log(message)
    else:
        print(message, flush=True)


class ScanCancelled(RuntimeError):
    def __init__(self, message: str = "scan cancelled"):
        super().__init__(message)


class ScanDeadlineExceeded(ScanCancelled):
    def __init__(self, message: str = "scan deadline exceeded"):
        super().__init__(message)


class JobControl:
    def __init__(
        self,
        *,
        deadline_monotonic: float | None = None,
        cancel_event: threading.Event | None = None,
        kill_grace: float = DEFAULT_KILL_GRACE_SECONDS,
    ):
        self.deadline_monotonic = deadline_monotonic
        self.cancel_event = cancel_event or threading.Event()
        self.kill_grace = max(0.5, float(kill_grace))

    @classmethod
    def from_job(
        cls,
        job: dict[str, Any] | None = None,
        *,
        cancel_event: threading.Event | None = None,
        kill_grace: float = DEFAULT_KILL_GRACE_SECONDS,
        now: datetime | None = None,
    ) -> "JobControl":
        deadline_monotonic = None
        raw = (job or {}).get("deadline_at")
        if raw:
            text = str(raw).replace("Z", "+00:00")
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            remaining = (parsed - (now or datetime.now(timezone.utc))).total_seconds()
            deadline_monotonic = time.monotonic() + remaining
        if (job or {}).get("cancel_requested"):
            event = cancel_event or threading.Event()
            event.set()
            cancel_event = event
        return cls(deadline_monotonic=deadline_monotonic, cancel_event=cancel_event, kill_grace=kill_grace)

    def check(self) -> None:
        if self.cancel_event.is_set():
            raise ScanCancelled()
        if self.deadline_monotonic is not None and time.monotonic() >= self.deadline_monotonic:
            raise ScanDeadlineExceeded()


_current_control: ContextVar[JobControl | None] = ContextVar("scan_job_control", default=None)


def current_control() -> JobControl:
    return _current_control.get() or JobControl()


@contextmanager
def use_job_control(control: JobControl) -> Iterator[JobControl]:
    token = _current_control.set(control)
    try:
        yield control
    finally:
        _current_control.reset(token)


def terminate_process_group(proc: subprocess.Popen, *, grace: float) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=grace)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def run_command_to_file(cmd: list[str], dest: Path, log: LogFn | None = None) -> None:
    log_message("$ " + " ".join(cmd), log)
    dest.parent.mkdir(parents=True, exist_ok=True)
    stderr_chunks: list[bytes] = []
    stderr_limit = 65536
    started = time.monotonic()
    last_progress = started
    tool = Path(cmd[0]).name if cmd else "scanner"

    def _drain_stderr(pipe) -> None:
        while True:
            chunk = pipe.read(8192)
            if not chunk:
                break
            if sum(len(part) for part in stderr_chunks) < stderr_limit:
                stderr_chunks.append(chunk)

    control = current_control()
    control.check()
    with dest.open("wb") as out:
        proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.PIPE, start_new_session=True)
        assert proc.stderr is not None
        reader = threading.Thread(target=_drain_stderr, args=(proc.stderr,), daemon=True)
        reader.start()
        cancelled: ScanCancelled | None = None
        while True:
            try:
                control.check()
            except ScanCancelled as exc:
                cancelled = exc
                log_message(f"{tool} {exc}; sending SIGTERM to process group", log)
                terminate_process_group(proc, grace=control.kill_grace)
                returncode = proc.poll()
                if returncode is None:
                    returncode = -signal.SIGKILL
                break
            try:
                returncode = proc.wait(timeout=min(PROGRESS_POLL_SECONDS, 1.0))
                break
            except subprocess.TimeoutExpired:
                now = time.monotonic()
                elapsed = now - started
                if now - last_progress + 0.01 < progress_interval_for_elapsed(elapsed):
                    continue
                size = dest.stat().st_size if dest.exists() else 0
                log_message(f"{tool} still running ({int(elapsed)}s, {size} bytes written)", log)
                last_progress = now
        reader.join(timeout=5)
    stderr_text = b"".join(stderr_chunks).decode("utf-8", errors="replace").strip()
    empty = dest.stat().st_size == 0
    if cancelled is not None:
        if empty:
            dest.unlink(missing_ok=True)
        raise cancelled
    if returncode != 0:
        if empty:
            dest.unlink(missing_ok=True)
        raise RuntimeError(stderr_text or f"command failed: {cmd[0]} (exit {returncode})")
    if stderr_text:
        log_message(stderr_text, log)


class JsonlParseError(ValueError):
    """Raised when detector JSONL cannot be interpreted safely."""


def parse_jsonl_text(text: str, *, strict: bool = False) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            if strict:
                raise JsonlParseError(f"malformed JSONL at line {number}") from exc
            continue
        if not isinstance(parsed, dict):
            if strict:
                raise JsonlParseError(f"JSONL line {number} is not an object")
            continue
        rows.append(parsed)
    return rows


def parse_jsonl_file(path: Path, *, strict: bool = False) -> list[dict[str, Any]]:
    return parse_jsonl_text(path.read_text(encoding="utf-8", errors="replace"), strict=strict)


def validate_nuclei_row(raw: dict[str, Any]) -> None:
    template_id = raw.get("template-id") or raw.get("template_id")
    if not isinstance(template_id, str) or not template_id.strip():
        raise JsonlParseError("nuclei row is missing template-id")
    host = raw.get("host") or raw.get("matched-at")
    if not isinstance(host, str) or not host.strip():
        raise JsonlParseError("nuclei row is missing host")


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
