from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.audit import record_audit
from app.config import settings
from app.models import (
    PORT_SCOPE_DETECTED,
    ScanArtifact,
    ScanJob,
)
from app.scan_snapshot import PROVENANCE_SCALAR_KEYS, is_secret_key, merge_provenance, scalar_provenance_value
from app.schemas import RawEvidenceDeclaration, ScanArtifactOut
from app.settings_store import get_settings

log = logging.getLogger(__name__)

CHUNK_SIZE = 1024 * 1024
PROVENANCE_MAX_BYTES = 16 * 1024
CLEANUP_BATCH_SIZE = 100
DEFAULT_RETENTION_DAYS = 365
MAX_RETENTION_DAYS = 3650
MIN_RETENTION_DAYS = 1
DEFAULT_MEDIA_TYPE = "application/x-ndjson"
DEFAULT_CONTENT_ENCODING = "gzip"
DELETE_REASON_RETENTION = "retention"
ARTIFACT_STATUS_AVAILABLE = "available"
ARTIFACT_STATUS_EXPIRED = "expired"
ARTIFACT_STATUS_UNAVAILABLE = "unavailable"
RAW_EVIDENCE_CAPTURED = "captured"
RAW_EVIDENCE_DRY_RUN = "dry_run"
RAW_EVIDENCE_NONE_EXECUTED = "none_executed"
RAW_EVIDENCE_SKIPPED_NO_TARGETS = "skipped_no_targets"
RAW_EVIDENCE_STATUSES = frozenset(
    {
        RAW_EVIDENCE_CAPTURED,
        RAW_EVIDENCE_DRY_RUN,
        RAW_EVIDENCE_NONE_EXECUTED,
        RAW_EVIDENCE_SKIPPED_NO_TARGETS,
    }
)
DISCOVERY_NAABU_KEY = "discovery.naabu"
DOWNSTREAM_ARTIFACT_KEYS = frozenset(
    {"port_discovery.naabu", "fingerprint.httpx", "vulnerability.nuclei"}
)
CLIENT_PROVENANCE_ALLOWLIST = frozenset(
    {
        "runtime_version",
        "naabu_version",
        "httpx_version",
        "nuclei_version",
        "nuclei_templates_version",
        "nuclei_templates",
        "tool",
        "stage",
        "generated_at",
        "worker",
    }
)
PROVENANCE_MAX_SCALAR_CHARS = 200

_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class ArtifactError(Exception):
    def __init__(self, detail: str, status_code: int = 400):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


class ArtifactConflict(ArtifactError):
    def __init__(self, detail: str = "Artifact content conflicts with existing evidence"):
        super().__init__(detail, status_code=409)


class ArtifactTooLarge(ArtifactError):
    def __init__(self, detail: str = "Artifact exceeds the configured maximum size"):
        super().__init__(detail, status_code=413)


class ArtifactStorageError(ArtifactError):
    def __init__(self, detail: str = "Artifact storage path is invalid"):
        super().__init__(detail, status_code=400)


class RawEvidenceError(ArtifactError):
    def __init__(self, detail: str = "Raw evidence declaration is required to complete a successful run"):
        super().__init__(detail, status_code=409)


@dataclass(frozen=True)
class IngestedArtifact:
    artifact: ScanArtifact
    created_path: Path | None = None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def retention_days_from_settings(cfg: dict[str, Any] | None = None) -> int:
    raw = (cfg or {}).get("raw_scan_artifact_retention_days", DEFAULT_RETENTION_DAYS)
    try:
        days = int(raw)
    except (TypeError, ValueError) as exc:
        raise ArtifactError("raw_scan_artifact_retention_days must be a positive integer") from exc
    if days < MIN_RETENTION_DAYS or days > MAX_RETENTION_DAYS:
        raise ArtifactError(
            f"raw_scan_artifact_retention_days must be an integer from {MIN_RETENTION_DAYS} to {MAX_RETENTION_DAYS}"
        )
    return days


def storage_root() -> Path:
    return Path(settings.raw_artifact_dir).expanduser().resolve()


def ensure_storage_root() -> Path:
    root = storage_root()
    root.mkdir(parents=True, exist_ok=True)
    incoming = root / ".incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    return root


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def validate_storage_key(storage_key: str) -> str:
    if not storage_key or not isinstance(storage_key, str):
        raise ArtifactStorageError("storage_key is required")
    if "\x00" in storage_key:
        raise ArtifactStorageError("storage_key is invalid")
    candidate = storage_key.replace("\\", "/")
    if candidate.startswith("/") or candidate.startswith("~"):
        raise ArtifactStorageError("storage_key must be a relative path")
    parts = [part for part in candidate.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise ArtifactStorageError("storage_key must remain under the configured storage root")
    if any(part.startswith(".") for part in parts[:-1]):
        raise ArtifactStorageError("storage_key must remain under the configured storage root")
    return "/".join(parts)


def resolve_storage_path(storage_key: str, *, root: Path | None = None) -> Path:
    root = (root or storage_root()).resolve()
    relative = validate_storage_key(storage_key)
    candidate = (root / relative).resolve()
    if not _is_relative_to(candidate, root):
        raise ArtifactStorageError("storage_key escaped the configured storage root")
    if candidate.is_symlink() or any(parent.is_symlink() for parent in candidate.parents if _is_relative_to(parent, root)):
        raise ArtifactStorageError("storage_key resolved through a symlink")
    return candidate


def generate_storage_key(tenant_id: int, scan_job_id: int) -> str:
    return f"tenant/{int(tenant_id)}/job/{int(scan_job_id)}/{uuid.uuid4().hex}.jsonl.gz"


def validate_artifact_token(value: str, *, field: str, pattern: re.Pattern[str] = _SAFE_TOKEN) -> str:
    text = (value or "").strip()
    if not pattern.fullmatch(text):
        raise ArtifactError(f"{field} is invalid")
    if ".." in text or "/" in text or "\\" in text:
        raise ArtifactError(f"{field} is invalid")
    return text


def validate_artifact_key(value: str) -> str:
    return validate_artifact_token(value, field="artifact_key", pattern=_SAFE_KEY)


def sanitize_client_provenance(payload: dict[str, Any]) -> dict[str, Any]:
    for key in payload:
        if is_secret_key(str(key)):
            raise ArtifactError("provenance must not contain secrets")
    sanitized: dict[str, Any] = {}
    for key, value in payload.items():
        if key not in CLIENT_PROVENANCE_ALLOWLIST:
            continue
        if value in (None, ""):
            continue
        if isinstance(value, (dict, list)):
            raise ArtifactError("provenance fields must be scalar strings")
        scalar = scalar_provenance_value(value)
        if scalar is None:
            raise ArtifactError("provenance fields must be scalar strings")
        if len(scalar) > PROVENANCE_MAX_SCALAR_CHARS:
            raise ArtifactError("provenance value exceeds the maximum allowed size")
        sanitized[key] = scalar
    return sanitized


def parse_provenance(raw: str | dict[str, Any] | None) -> dict[str, Any]:
    if raw in (None, "", {}):
        return {}
    if isinstance(raw, dict):
        encoded = json.dumps(raw, default=str)
        if len(encoded.encode("utf-8")) > PROVENANCE_MAX_BYTES:
            raise ArtifactError("provenance exceeds the maximum allowed size")
        return sanitize_client_provenance(raw)
    if not isinstance(raw, str):
        raise ArtifactError("provenance must be a JSON object")
    if len(raw.encode("utf-8")) > PROVENANCE_MAX_BYTES:
        raise ArtifactError("provenance exceeds the maximum allowed size")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ArtifactError("provenance must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ArtifactError("provenance must be a JSON object")
    return sanitize_client_provenance(parsed)


def download_filename(artifact: ScanArtifact) -> str:
    stage = re.sub(r"[^A-Za-z0-9._-]+", "-", artifact.stage).strip("-") or "stage"
    tool = re.sub(r"[^A-Za-z0-9._-]+", "-", artifact.tool).strip("-") or "tool"
    return f"scan-{artifact.scan_job_id}-{stage}-{tool}.jsonl.gz"


def site_id_from_job(job: ScanJob | None) -> int | None:
    snapshot = (job.execution_snapshot or {}) if job is not None else {}
    site = snapshot.get("site") if isinstance(snapshot, dict) else None
    if isinstance(site, dict) and site.get("id") is not None:
        try:
            return int(site["id"])
        except (TypeError, ValueError):
            return None
    return None


def artifact_is_expired(artifact: ScanArtifact, *, now: datetime | None = None) -> bool:
    if artifact.deleted_at is not None:
        return True
    expires = artifact.retention_expires_at
    if expires is None:
        return False
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires <= (now or utcnow())


def artifact_bytes_readable(artifact: ScanArtifact) -> bool:
    try:
        path = resolve_storage_path(artifact.storage_key)
    except ArtifactError:
        return False
    return path.is_file() and not path.is_symlink()


def artifact_status(artifact: ScanArtifact, *, now: datetime | None = None) -> str:
    if artifact_is_expired(artifact, now=now):
        return ARTIFACT_STATUS_EXPIRED
    if artifact_bytes_readable(artifact):
        return ARTIFACT_STATUS_AVAILABLE
    return ARTIFACT_STATUS_UNAVAILABLE


def artifact_available(artifact: ScanArtifact) -> bool:
    return artifact_status(artifact) == ARTIFACT_STATUS_AVAILABLE


def serialize_artifact(artifact: ScanArtifact) -> ScanArtifactOut:
    status = artifact_status(artifact)
    return ScanArtifactOut(
        id=artifact.id,
        scan_job_id=artifact.scan_job_id,
        tenant_id=artifact.tenant_id,
        artifact_key=artifact.artifact_key,
        tool=artifact.tool,
        stage=artifact.stage,
        media_type=artifact.media_type,
        content_encoding=artifact.content_encoding,
        size_bytes=artifact.size_bytes,
        sha256=artifact.sha256,
        created_at=artifact.created_at,
        retention_expires_at=artifact.retention_expires_at,
        deleted_at=artifact.deleted_at,
        delete_reason=artifact.delete_reason,
        status=status,
        available=status == ARTIFACT_STATUS_AVAILABLE,
        provenance=artifact.provenance or {},
        download_filename=download_filename(artifact),
    )


def _write_stream_to_temp(chunks: Iterable[bytes], temp_path: Path, *, max_bytes: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with temp_path.open("wb") as handle:
        for chunk in chunks:
            if not chunk:
                continue
            if not isinstance(chunk, (bytes, bytearray)):
                raise ArtifactError("artifact upload must be binary")
            size += len(chunk)
            if size > max_bytes:
                handle.close()
                temp_path.unlink(missing_ok=True)
                raise ArtifactTooLarge()
            handle.write(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def iter_file_chunks(handle, *, chunk_size: int = CHUNK_SIZE) -> Iterable[bytes]:
    while True:
        chunk = handle.read(chunk_size)
        if not chunk:
            break
        yield chunk


def build_provenance(
    job: ScanJob,
    *,
    tool: str,
    stage: str,
    extra: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    runtime = job.runtime_provenance if isinstance(job.runtime_provenance, dict) else {}
    snapshot: dict[str, Any] = {
        "tool": tool,
        "stage": stage,
        "scan_job_id": job.id,
        "generated_at": (now or utcnow()).isoformat(),
        "worker": scalar_provenance_value(runtime.get("worker")) or "Not Recorded",
    }
    for key in ("claimed_agent_id", "agent_uuid", *PROVENANCE_SCALAR_KEYS):
        value = scalar_provenance_value(runtime.get(key))
        if value:
            snapshot[key] = value
    if extra:
        for key, value in extra.items():
            if key not in CLIENT_PROVENANCE_ALLOWLIST or key in snapshot:
                continue
            scalar = scalar_provenance_value(value)
            if scalar is None:
                continue
            snapshot[key] = scalar
    return snapshot


def ingest_chunks(
    db: Session,
    job: ScanJob,
    *,
    artifact_key: str,
    stage: str,
    tool: str,
    chunks: Iterable[bytes],
    media_type: str = DEFAULT_MEDIA_TYPE,
    content_encoding: str = DEFAULT_CONTENT_ENCODING,
    provenance: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> IngestedArtifact:
    artifact_key = validate_artifact_key(artifact_key)
    stage = validate_artifact_token(stage, field="stage")
    tool = validate_artifact_token(tool, field="tool")
    media_type = (media_type or DEFAULT_MEDIA_TYPE).strip() or DEFAULT_MEDIA_TYPE
    content_encoding = (content_encoding or DEFAULT_CONTENT_ENCODING).strip() or DEFAULT_CONTENT_ENCODING
    if len(media_type) > 128 or len(content_encoding) > 32:
        raise ArtifactError("artifact metadata is invalid")
    extra = parse_provenance(provenance)
    current = now or utcnow()
    root = ensure_storage_root()
    incoming = root / ".incoming"
    temp_path = incoming / f"{uuid.uuid4().hex}.part"
    final_path: Path | None = None
    try:
        size, digest = _write_stream_to_temp(chunks, temp_path, max_bytes=settings.raw_artifact_max_bytes)
        existing = (
            db.query(ScanArtifact)
            .filter(ScanArtifact.scan_job_id == job.id, ScanArtifact.artifact_key == artifact_key)
            .with_for_update()
            .first()
        )
        if existing is not None:
            if existing.sha256 == digest and existing.size_bytes == size:
                temp_path.unlink(missing_ok=True)
                return IngestedArtifact(artifact=existing)
            raise ArtifactConflict()
        storage_key = generate_storage_key(job.tenant_id, job.id)
        final_path = resolve_storage_path(storage_key, root=root)
        final_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(temp_path, final_path)
        cfg = get_settings(db)
        days = retention_days_from_settings(cfg)
        row = ScanArtifact(
            scan_job_id=job.id,
            tenant_id=job.tenant_id,
            artifact_key=artifact_key,
            stage=stage,
            tool=tool,
            media_type=media_type,
            content_encoding=content_encoding,
            storage_key=storage_key,
            size_bytes=size,
            sha256=digest,
            created_at=current,
            retention_expires_at=current + timedelta(days=days),
            provenance=build_provenance(job, tool=tool, stage=stage, extra=extra, now=current),
        )
        db.add(row)
        db.flush()
        return IngestedArtifact(artifact=row, created_path=final_path)
    except ArtifactError:
        temp_path.unlink(missing_ok=True)
        if final_path is not None:
            final_path.unlink(missing_ok=True)
        raise
    except Exception:
        temp_path.unlink(missing_ok=True)
        if final_path is not None:
            final_path.unlink(missing_ok=True)
        raise


def ingest_upload_file(
    db: Session,
    job: ScanJob,
    *,
    upload: UploadFile,
    artifact_key: str,
    stage: str,
    tool: str,
    media_type: str | None = None,
    content_encoding: str | None = None,
    provenance: str | dict[str, Any] | None = None,
) -> IngestedArtifact:
    handle = upload.file
    return ingest_chunks(
        db,
        job,
        artifact_key=artifact_key,
        stage=stage,
        tool=tool,
        chunks=iter_file_chunks(handle, chunk_size=CHUNK_SIZE),
        media_type=media_type or DEFAULT_MEDIA_TYPE,
        content_encoding=content_encoding or DEFAULT_CONTENT_ENCODING,
        provenance=parse_provenance(provenance),
    )


def commit_ingested_artifact(db: Session, ingested: IngestedArtifact) -> None:
    try:
        db.commit()
    except Exception:
        if ingested.created_path is not None:
            ingested.created_path.unlink(missing_ok=True)
        raise


def snapshot_is_dry_run(job: ScanJob) -> bool:
    snapshot = job.execution_snapshot if isinstance(job.execution_snapshot, dict) else {}
    return snapshot.get("dry_run") is True


def expected_artifact_keys(job: ScanJob) -> list[str]:
    if snapshot_is_dry_run(job):
        return []
    snapshot = job.execution_snapshot if isinstance(job.execution_snapshot, dict) else {}
    stages = snapshot.get("stages")
    if not isinstance(stages, dict):
        return []
    keys: list[str] = []
    port_mode = str(stages.get("port_mode") or "none").strip()
    if port_mode and port_mode != "none":
        keys.append("port_discovery.naabu")
    elif stages.get("discovery"):
        keys.append("discovery.naabu")
    if stages.get("fingerprint"):
        keys.append("fingerprint.httpx")
    if stages.get("vulnerability"):
        keys.append("vulnerability.nuclei")
    return keys


def snapshot_requires_raw_artifacts(job: ScanJob) -> bool:
    if snapshot_is_dry_run(job):
        return False
    snapshot = job.execution_snapshot if isinstance(job.execution_snapshot, dict) else {}
    stages = snapshot.get("stages")
    if not isinstance(stages, dict) or not stages:
        return True
    return bool(expected_artifact_keys(job))


def snapshot_allows_skipped_no_targets(job: ScanJob) -> bool:
    if snapshot_is_dry_run(job):
        return False
    snapshot = job.execution_snapshot if isinstance(job.execution_snapshot, dict) else {}
    stages = snapshot.get("stages")
    if not isinstance(stages, dict):
        return False
    if not stages.get("discovery"):
        return False
    port_scope = str(stages.get("port_scope") or PORT_SCOPE_DETECTED)
    return port_scope == PORT_SCOPE_DETECTED


def job_has_ingested_scan_results(db: Session, job: ScanJob) -> bool:
    from app.models import AssetObservation, Finding, ScanRunDetectorCoverage

    if (
        db.query(AssetObservation.id)
        .filter(AssetObservation.scan_job_id == job.id, AssetObservation.tenant_id == job.tenant_id)
        .first()
        is not None
    ):
        return True
    if (
        db.query(Finding.id)
        .filter(Finding.scan_job_id == job.id, Finding.tenant_id == job.tenant_id)
        .first()
        is not None
    ):
        return True
    return (
        db.query(ScanRunDetectorCoverage.id)
        .filter(
            ScanRunDetectorCoverage.scan_job_id == job.id,
            ScanRunDetectorCoverage.tenant_id == job.tenant_id,
        )
        .first()
        is not None
    )


def apply_raw_evidence_declaration(
    db: Session,
    job: ScanJob,
    *,
    ok: bool,
    declaration: RawEvidenceDeclaration | dict[str, Any] | None,
) -> None:
    if not ok:
        return
    if declaration is None:
        raise RawEvidenceError("Raw evidence declaration is required to complete a successful run")
    if isinstance(declaration, RawEvidenceDeclaration):
        status = declaration.status
        keys = list(declaration.artifact_keys or [])
    else:
        status = declaration.get("status")
        keys = list(declaration.get("artifact_keys") or [])
    if status not in RAW_EVIDENCE_STATUSES:
        raise RawEvidenceError("Raw evidence status is invalid")
    normalized_keys = [validate_artifact_key(str(key)) for key in keys]
    existing = {
        row.artifact_key
        for row in db.query(ScanArtifact).filter(ScanArtifact.scan_job_id == job.id).all()
    }
    if status == RAW_EVIDENCE_CAPTURED:
        if snapshot_is_dry_run(job):
            raise RawEvidenceError("dry_run execution cannot declare captured artifacts")
        if not normalized_keys:
            raise RawEvidenceError("captured raw evidence requires artifact_keys")
        expected = set(expected_artifact_keys(job))
        declared = set(normalized_keys)
        if expected - existing:
            raise RawEvidenceError("Required raw evidence artifacts were not persisted")
        if expected - declared:
            raise RawEvidenceError("Raw evidence declaration is missing required artifacts")
        missing = [key for key in normalized_keys if key not in existing]
        if missing:
            raise RawEvidenceError("Declared raw evidence artifacts were not persisted")
    elif status == RAW_EVIDENCE_SKIPPED_NO_TARGETS:
        if snapshot_is_dry_run(job):
            raise RawEvidenceError("dry_run execution must declare dry_run raw evidence")
        if not snapshot_allows_skipped_no_targets(job):
            raise RawEvidenceError("skipped_no_targets requires detected-host discovery")
        if job_has_ingested_scan_results(db, job):
            raise RawEvidenceError(
                "skipped_no_targets is not valid after hosts, findings, or coverage were ingested"
            )
        if existing & DOWNSTREAM_ARTIFACT_KEYS:
            raise RawEvidenceError("skipped_no_targets cannot complete with downstream raw artifacts")
        if DISCOVERY_NAABU_KEY not in existing:
            raise RawEvidenceError("detected-host discovery still requires discovery.naabu evidence")
        if set(normalized_keys) != existing:
            raise RawEvidenceError("skipped_no_targets declaration must match persisted discovery evidence")
    else:
        if normalized_keys:
            raise RawEvidenceError(f"{status} raw evidence must not declare artifact_keys")
        if existing:
            raise RawEvidenceError(f"{status} raw evidence cannot complete with persisted artifacts")
        if status == RAW_EVIDENCE_DRY_RUN and not snapshot_is_dry_run(job):
            raise RawEvidenceError("dry_run is not permitted for this execution snapshot")
        if status == RAW_EVIDENCE_NONE_EXECUTED:
            if snapshot_is_dry_run(job):
                raise RawEvidenceError("dry_run execution must declare dry_run raw evidence")
            if snapshot_requires_raw_artifacts(job):
                raise RawEvidenceError("Execution snapshot requires raw evidence artifacts")
    job.runtime_provenance = merge_provenance(
        job.runtime_provenance,
        {"raw_evidence": {"status": status, "artifact_keys": normalized_keys}},
    )


def raise_http(exc: ArtifactError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


def list_job_artifacts(db: Session, job: ScanJob) -> list[ScanArtifact]:
    return (
        db.query(ScanArtifact)
        .filter(ScanArtifact.scan_job_id == job.id)
        .order_by(ScanArtifact.created_at.asc(), ScanArtifact.id.asc())
        .all()
    )


def get_artifact(db: Session, artifact_id: int) -> ScanArtifact | None:
    return db.query(ScanArtifact).filter(ScanArtifact.id == artifact_id).first()


def readable_artifact_path(artifact: ScanArtifact) -> Path:
    if artifact_is_expired(artifact):
        raise ArtifactError("Raw artifact is no longer available", status_code=410)
    try:
        path = resolve_storage_path(artifact.storage_key)
    except ArtifactStorageError as exc:
        log.error("scan artifact %s storage key rejected: %s", artifact.id, exc.detail)
        raise ArtifactError("Raw artifact bytes are unavailable", status_code=409) from exc
    if path.is_symlink() or not path.is_file():
        log.error("scan artifact %s bytes are missing at controlled storage path", artifact.id)
        raise ArtifactError("Raw artifact bytes are missing from storage", status_code=409)
    return path


def cleanup_expired_artifacts(db: Session, *, now: datetime | None = None, batch_size: int = CLEANUP_BATCH_SIZE) -> int:
    current = now or utcnow()
    limit = max(1, min(int(batch_size), CLEANUP_BATCH_SIZE))
    rows = (
        db.query(ScanArtifact)
        .filter(
            ScanArtifact.deleted_at.is_(None),
            ScanArtifact.retention_expires_at <= current,
        )
        .order_by(ScanArtifact.retention_expires_at.asc(), ScanArtifact.id.asc())
        .limit(limit)
        .all()
    )
    cleaned = 0
    for row in rows:
        try:
            path = resolve_storage_path(row.storage_key)
            if path.is_file() or path.is_symlink():
                path.unlink(missing_ok=True)
        except ArtifactError:
            log.error("scan artifact %s retention cleanup skipped unsafe storage key", row.id)
            continue
        except OSError:
            log.exception("scan artifact %s retention byte delete failed", row.id)
            continue
        row.deleted_at = current
        row.delete_reason = DELETE_REASON_RETENTION
        job = db.get(ScanJob, row.scan_job_id)
        record_audit(
            db,
            actor=None,
            action="scan_artifact.retention_delete",
            object_type="scan_artifact",
            object_id=row.id,
            tenant_id=row.tenant_id,
            site_id=site_id_from_job(job),
            details={
                "artifact_id": row.id,
                "scan_job_id": row.scan_job_id,
                "tool": row.tool,
                "stage": row.stage,
                "sha256": row.sha256,
                "size_bytes": row.size_bytes,
                "retention_expires_at": row.retention_expires_at.isoformat() if row.retention_expires_at else None,
            },
        )
        cleaned += 1
    return cleaned


def assert_no_artifact_body_columns() -> None:
    forbidden = {"body", "bytes", "content", "payload", "raw_bytes", "artifact_body"}
    for column in ScanArtifact.__table__.columns:
        if column.name in forbidden:
            raise RuntimeError(f"ScanArtifact must not persist artifact bytes in {column.name}")
        if str(column.type).upper() in {"BYTEA", "BLOB"}:
            raise RuntimeError("ScanArtifact must not use BYTEA for artifact bytes")


def is_safe_sha256(value: str) -> bool:
    return bool(_SHA256_RE.fullmatch(value or ""))
