from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from api_client import ApiError
from artifact_io import cleanup_staging
from ingest_chunks import iter_ingest_chunks
from scan_progress import note_stage
from spool import JobSpool

UploadFn = Callable[[dict[str, Any]], Any]
JsonFn = Callable[..., Any]
CompleteFn = Callable[..., Any]


def persist_artifacts(
    upload: UploadFn,
    artifacts: list[dict[str, Any]],
    provenance: dict[str, Any] | None,
    *,
    skip_missing: bool = False,
) -> None:
    for artifact in artifacts:
        path = artifact.get("path")
        if path and not Path(str(path)).exists():
            if skip_missing:
                continue
        payload = dict(artifact)
        extra = dict(payload.get("provenance") or {})
        if provenance:
            for key, value in provenance.items():
                extra.setdefault(key, value)
        payload["provenance"] = extra
        upload(payload)


def submit_normalized(
    *,
    provenance_fn: JsonFn | None,
    devices_fn: JsonFn | None,
    coverage_fn: JsonFn | None,
    findings_fn: JsonFn | None,
    result: dict[str, Any],
) -> None:
    spool = result.get("spool")
    if isinstance(spool, JobSpool):
        _submit_spool(
            spool,
            devices_fn=devices_fn,
            findings_fn=findings_fn,
            coverage_fn=coverage_fn,
        )
        return
    if result.get("devices") and devices_fn is not None:
        for chunk in iter_ingest_chunks(list(result["devices"]), kind="device"):
            devices_fn(chunk)
    if result.get("findings") and findings_fn is not None:
        for chunk in iter_ingest_chunks(list(result["findings"]), kind="finding"):
            findings_fn(chunk)
    for coverage in result.get("detector_coverage") or []:
        if coverage_fn is None:
            raise ApiError("detector coverage could not be persisted")
        targets = list(coverage.get("targets") or [])
        if not targets:
            coverage_fn(coverage)
            continue
        payload = dict(coverage)
        for chunk in iter_ingest_chunks(targets, kind="coverage"):
            next_payload = dict(payload)
            next_payload["targets"] = chunk
            coverage_fn(next_payload)


def _submit_spool(
    spool: JobSpool,
    *,
    devices_fn: JsonFn | None,
    findings_fn: JsonFn | None,
    coverage_fn: JsonFn | None,
) -> None:
    spool.seal_all()
    for path in spool.ready_chunks("devices"):
        if devices_fn is None:
            raise ApiError("device chunk could not be persisted")
        devices_fn(spool.read_chunk(path))
        spool.ack_delete(path)
    for path in spool.ready_chunks("findings"):
        if findings_fn is not None:
            findings_fn(spool.read_chunk(path))
            spool.ack_delete(path)
    for path in spool.ready_chunks("coverage"):
        if coverage_fn is None:
            raise ApiError("detector coverage could not be persisted")
        for record in spool.read_chunk(path):
            coverage_fn(record)
        spool.ack_delete(path)


def finish_pipeline_run(
    *,
    result: dict[str, Any],
    upload: UploadFn,
    complete: CompleteFn,
    provenance_fn: JsonFn | None = None,
    devices_fn: JsonFn | None = None,
    coverage_fn: JsonFn | None = None,
    findings_fn: JsonFn | None = None,
    pipeline_error: str | None = None,
) -> None:
    artifacts = list(result.get("artifacts") or [])
    note_stage("upload", "Uploading results")
    try:
        persist_artifacts(
            upload,
            artifacts,
            result.get("provenance"),
            skip_missing=bool(result.get("spool_resume")),
        )
    except Exception:
        cleanup_staging(result.get("staging_dir"))
        raise
    cleanup_staging(result.get("staging_dir"))
    provenance_error: str | None = None
    dry_run = bool(result.get("dry_run"))
    if provenance_fn is not None:
        if result.get("provenance"):
            try:
                provenance_fn(result["provenance"])
            except Exception as exc:
                provenance_error = f"version provenance persistence failed: {exc}"
        elif not dry_run and not pipeline_error:
            provenance_error = "required version provenance was not collected"
    coverage_error: str | None = None
    try:
        submit_normalized(
            provenance_fn=None,
            devices_fn=devices_fn,
            coverage_fn=coverage_fn,
            findings_fn=findings_fn,
            result=result,
        )
    except Exception as exc:
        coverage_error = f"normalized result persistence failed: {exc}"
    if pipeline_error:
        complete(False, pipeline_error)
        return
    if provenance_error:
        complete(False, provenance_error)
        return
    if coverage_error:
        complete(False, coverage_error)
        return
    spool = result.get("spool")
    if isinstance(spool, JobSpool) and spool.has_pending():
        complete(False, "normalized spool still has pending chunks")
        return
    note_stage("upload", "Upload complete", complete=True)
    complete(True, None, raw_evidence=raw_evidence_declaration(result))


def raw_evidence_declaration(result: dict[str, Any]) -> dict[str, Any]:
    artifacts = list(result.get("artifacts") or [])
    keys = [str(row["artifact_key"]) for row in artifacts if row.get("artifact_key")]
    if result.get("dry_run"):
        return {"status": "dry_run", "artifact_keys": []}
    if keys:
        return {"status": "captured", "artifact_keys": keys}
    return {"status": "none_executed", "artifact_keys": []}


def provenance_form_value(payload: dict[str, Any] | None) -> str:
    if not payload:
        return ""
    return json.dumps(payload, default=str)
