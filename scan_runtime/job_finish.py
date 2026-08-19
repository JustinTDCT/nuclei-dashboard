from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from api_client import ApiError
from artifact_io import cleanup_staging

UploadFn = Callable[[dict[str, Any]], Any]
JsonFn = Callable[..., Any]
CompleteFn = Callable[..., Any]


def persist_artifacts(upload: UploadFn, artifacts: list[dict[str, Any]], provenance: dict[str, Any] | None) -> None:
    for artifact in artifacts:
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
    if result.get("provenance") and provenance_fn is not None:
        try:
            provenance_fn(result["provenance"])
        except ApiError:
            pass
    if result.get("devices") and devices_fn is not None:
        devices_fn(result["devices"])
    for coverage in result.get("detector_coverage") or []:
        if coverage_fn is None:
            continue
        try:
            coverage_fn(coverage)
        except ApiError:
            pass
    if result.get("findings") and findings_fn is not None:
        findings_fn(result["findings"])


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
    try:
        persist_artifacts(upload, artifacts, result.get("provenance"))
    except Exception:
        cleanup_staging(result.get("staging_dir"))
        raise
    cleanup_staging(result.get("staging_dir"))
    submit_normalized(
        provenance_fn=provenance_fn,
        devices_fn=devices_fn,
        coverage_fn=coverage_fn,
        findings_fn=findings_fn,
        result=result,
    )
    if pipeline_error:
        complete(False, pipeline_error)
        return
    complete(True, None)


def provenance_form_value(payload: dict[str, Any] | None) -> str:
    if not payload:
        return ""
    return json.dumps(payload, default=str)
