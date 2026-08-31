"""Per-job bounded disk spool for Scale S2E.

Normalized records are sealed as S2D-sized chunk files under a job-scoped
directory. Write temp → fsync → rename so a crash cannot leave an apparently
valid half-written chunk. Foreign job directories are abandoned, never
attached to another run. No schema change.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Iterator

from ingest_chunks import IngestLimitError, encoded_bytes, ingest_limits

DEFAULT_SPOOL_MAX_BYTES = 268435456
DONE_NAME = "pipeline.done"
KINDS = ("devices", "findings", "coverage")


class SpoolError(RuntimeError):
    pass


class SpoolCapExceeded(SpoolError):
    pass


def spool_root() -> Path:
    explicit = os.environ.get("AGENT_DATA_DIR")
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.append(Path("/data"))
    candidates.append(Path(tempfile_root()))
    last_error: OSError | None = None
    for base in candidates:
        try:
            root = base / "spool"
            root.mkdir(parents=True, exist_ok=True)
            os.chmod(root, 0o700)
            return root
        except OSError as exc:
            last_error = exc
            continue
    raise SpoolError(f"could not create spool root: {last_error}")


def tempfile_root() -> str:
    return os.environ.get("TMPDIR") or "/tmp"


def spool_max_bytes() -> int:
    return int(os.environ.get("S2E_SPOOL_MAX_BYTES", str(DEFAULT_SPOOL_MAX_BYTES)))


def reclaim_foreign_jobs(root: Path, current_job_id: int) -> None:
    jobs = root / "jobs"
    if not jobs.is_dir():
        return
    for child in jobs.iterdir():
        if child.name != str(current_job_id):
            shutil.rmtree(child, ignore_errors=True)


def _spool_search_roots() -> list[Path]:
    explicit = os.environ.get("AGENT_DATA_DIR")
    if explicit:
        return [Path(explicit) / "spool"]
    return [Path("/data/spool"), Path(tempfile_root()) / "spool"]


def discover_completed_job_ids(root: Path | None = None) -> list[int]:
    """List job IDs that have ``pipeline.done`` without reclaiming siblings.

    Used on worker startup before polling queued work. Do not call
    ``JobSpool.for_job`` here — that deletes other job directories.
    """
    bases = [Path(root)] if root is not None else _spool_search_roots()
    found: set[int] = set()
    for base in bases:
        jobs = base / "jobs"
        if not jobs.is_dir():
            continue
        for child in jobs.iterdir():
            if not child.is_dir() or not (child / DONE_NAME).is_file():
                continue
            try:
                found.add(int(child.name))
            except ValueError:
                continue
    return sorted(found)


def abandon_job_spool(job_id: int, *, root: Path | None = None) -> None:
    """Delete one job directory without touching siblings."""
    bases = [Path(root)] if root is not None else _spool_search_roots()
    for base in bases:
        shutil.rmtree(base / "jobs" / str(int(job_id)), ignore_errors=True)


class JobSpool:
    def __init__(self, root: Path, job_id: int, *, max_bytes: int | None = None):
        self.job_id = int(job_id)
        self.root = Path(root)
        self.dir = self.root / "jobs" / str(self.job_id)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.max_bytes = int(max_bytes if max_bytes is not None else spool_max_bytes())
        self._open: dict[str, list[Any]] = {kind: [] for kind in KINDS}
        self._sizes: dict[str, list[int]] = {kind: [] for kind in KINDS}
        self._seq: dict[str, int] = {kind: self._next_seq(kind) for kind in KINDS}
        self.discard_tmp()

    @classmethod
    def for_job(cls, job_id: int, *, root: Path | None = None, max_bytes: int | None = None) -> JobSpool:
        base = root or spool_root()
        reclaim_foreign_jobs(base, int(job_id))
        return cls(base, int(job_id), max_bytes=max_bytes)

    def discard_tmp(self) -> None:
        for path in self.dir.glob("*.tmp"):
            path.unlink(missing_ok=True)

    def raw_staging_dir(self) -> Path:
        """Durable per-job raw evidence. Survives container recreate with /data."""
        staging = self.dir / "raw"
        staging.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(staging, 0o700)
        except OSError:
            pass
        return staging

    def pipeline_complete(self) -> bool:
        return (self.dir / DONE_NAME).is_file()

    def pipeline_meta(self) -> dict[str, Any]:
        path = self.dir / DONE_NAME
        if not path.is_file():
            return {}
        raw = path.read_text(encoding="utf-8").strip()
        if raw in {"", "ok"}:
            return {"ok": True}
        payload = json.loads(raw)
        return payload if isinstance(payload, dict) else {"ok": True}

    def mark_pipeline_complete(self, meta: dict[str, Any] | None = None) -> None:
        self.seal_all()
        self._atomic_write_json(self.dir / DONE_NAME, meta if meta is not None else {"ok": True})

    def append(self, kind: str, record: Any) -> None:
        if kind not in self._open:
            raise SpoolError(f"unknown spool kind {kind}")
        size = encoded_bytes(record)
        max_rows, max_chunk_bytes = ingest_limits()
        if 2 + size > max_chunk_bytes:
            raise IngestLimitError(f"single {kind} record exceeds {max_chunk_bytes}-byte limit")
        batch = self._open[kind]
        sizes = self._sizes[kind]
        next_count = len(batch) + 1
        next_bytes = 2 + sum(sizes) + size + len(batch)
        if batch and (next_count > max_rows or next_bytes > max_chunk_bytes):
            self.seal(kind)
            batch = self._open[kind]
            sizes = self._sizes[kind]
        batch.append(record)
        sizes.append(size)

    def seal(self, kind: str) -> Path | None:
        batch = self._open[kind]
        if not batch:
            return None
        self._seq[kind] += 1
        path = self.dir / f"{kind}-{self._seq[kind]:06d}.ready"
        self._atomic_write(path, batch)
        self._open[kind] = []
        self._sizes[kind] = []
        return path

    def seal_all(self) -> None:
        for kind in KINDS:
            self.seal(kind)

    def ready_chunks(self, kind: str) -> list[Path]:
        return sorted(self.dir.glob(f"{kind}-*.ready"))

    def read_chunk(self, path: Path) -> list[Any]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise SpoolError(f"spool chunk {path.name} is not a list")
        return payload

    def ack_delete(self, path: Path) -> None:
        Path(path).unlink(missing_ok=True)

    def pending_ready(self) -> int:
        return sum(1 for _ in self.dir.glob("*.ready"))

    def pending_open(self) -> int:
        return sum(len(batch) for batch in self._open.values())

    def has_pending(self) -> bool:
        return self.pending_ready() > 0 or self.pending_open() > 0

    def disk_bytes(self) -> int:
        return sum(path.stat().st_size for path in self.dir.iterdir() if path.is_file())

    def iter_records(self, kind: str) -> Iterator[Any]:
        for path in self.ready_chunks(kind):
            yield from self.read_chunk(path)
        yield from list(self._open[kind])

    def abandon(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def _next_seq(self, kind: str) -> int:
        highest = 0
        for path in self.dir.glob(f"{kind}-*.ready"):
            try:
                highest = max(highest, int(path.stem.split("-")[-1]))
            except ValueError:
                continue
        return highest

    def _atomic_write(self, dest: Path, payload: list[Any]) -> None:
        self._atomic_write_json(dest, payload)

    def _atomic_write_json(self, dest: Path, payload: Any) -> None:
        data = json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")
        if self.disk_bytes() + len(data) > self.max_bytes:
            raise SpoolCapExceeded(f"spool exceeds {self.max_bytes}-byte cap")
        tmp = dest.with_name(dest.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, dest)
        os.chmod(dest, 0o600)
        fsync_directory(dest.parent)


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while sealing spool file")
        view = view[written:]


def fsync_directory(path: Path) -> None:
    try:
        dir_fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        return
    finally:
        os.close(dir_fd)


def recover_owned_spool(job_id: int, *, root: Path | None = None) -> JobSpool | None:
    """Resume a completed owned job, or abandon incomplete/foreign spool state.

    Foreign job directories are deleted and never attached to this run.
    Incomplete pipeline state is discarded so a restart cannot mix stale
    chunks into a new attempt. ``pipeline.done`` means normalize finished
    and remaining ``*.ready`` chunks may be uploaded again.
    """
    spool = JobSpool.for_job(int(job_id), root=root)
    if spool.pipeline_complete():
        return spool
    spool.abandon()
    return None


def resume_pipeline_result(spool: JobSpool) -> dict[str, Any]:
    meta = spool.pipeline_meta()
    return {
        "artifacts": list(meta.get("artifacts") or []),
        "staging_dir": meta.get("staging_dir"),
        "provenance": meta.get("provenance") or {},
        "dry_run": bool(meta.get("dry_run")),
        "devices": [],
        "findings": [],
        "detector_coverage": [],
        "spool": spool,
        "spool_resume": True,
        "skipped_no_targets": bool(meta.get("skipped_no_targets")),
    }


__all__ = [
    "DEFAULT_SPOOL_MAX_BYTES",
    "DONE_NAME",
    "JobSpool",
    "SpoolCapExceeded",
    "SpoolError",
    "abandon_job_spool",
    "discover_completed_job_ids",
    "fsync_directory",
    "reclaim_foreign_jobs",
    "recover_owned_spool",
    "resume_pipeline_result",
    "spool_max_bytes",
    "spool_root",
    "write_all",
]
