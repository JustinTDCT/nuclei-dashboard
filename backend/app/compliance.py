"""Generic compliance Framework/Control catalog and evidence references."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.audit import record_audit
from app.models import (
    CONTROL_REFERENCE_TYPES,
    CONTROL_REF_RELATED,
    CONTROL_SUBJECT_ASSET,
    CONTROL_SUBJECT_ASSET_FINDING,
    CONTROL_SUBJECT_FINDING,
    CONTROL_SUBJECT_SCAN_JOB,
    CONTROL_SUBJECT_TREATMENT,
    CONTROL_SUBJECT_TYPES,
    Asset,
    AssetFinding,
    ComplianceControl,
    ComplianceControlReference,
    ComplianceFramework,
    Finding,
    FindingTreatment,
    ScanJob,
    User,
)

COMPLIANCE_DATA_DIR = Path(__file__).resolve().parent / "data" / "compliance"
INDEX_PATH = COMPLIANCE_DATA_DIR / "index.json"

SUBJECT_FIELDS = {
    CONTROL_SUBJECT_ASSET: "asset_id",
    CONTROL_SUBJECT_ASSET_FINDING: "asset_finding_id",
    CONTROL_SUBJECT_FINDING: "finding_id",
    CONTROL_SUBJECT_TREATMENT: "treatment_id",
    CONTROL_SUBJECT_SCAN_JOB: "scan_job_id",
}

COMPLIANCE_MAPPING_DISCLAIMER = (
    "A control mapping means this evidence is related to the selected control. "
    "It does not mean the control is implemented, assessed, satisfied, or certified."
)
MERGE_REFERENCE_MOVE_REASON = "Asset finding merge reassigned this mapping to the keeper finding."
MERGE_REFERENCE_REMOVE_REASON = "Duplicate mapping after asset finding merge"


class ComplianceError(Exception):
    def __init__(self, detail: str, status_code: int = 400):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_date(value: Any) -> date | None:
    if value in (None, ""):
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    text = str(value).strip()
    return date.fromisoformat(text[:10])


def create_framework(
    db: Session,
    *,
    actor: User,
    slug: str,
    name: str,
    version: str,
    publisher: str = "",
    description: str = "",
    source_url: str = "",
    source_release_date: date | None = None,
    source_metadata: dict | None = None,
    builtin: bool = False,
) -> ComplianceFramework:
    key = (slug or "").strip().lower()
    ver = (version or "").strip()
    title = (name or "").strip()
    if not key or not ver or not title:
        raise ComplianceError("Framework slug, name, and version are required")
    existing = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.slug == key, ComplianceFramework.version == ver)
        .first()
    )
    if existing is not None:
        raise ComplianceError("A framework with this key and version already exists", 409)
    now = utcnow()
    row = ComplianceFramework(
        slug=key,
        name=title,
        version=ver,
        publisher=(publisher or "").strip(),
        description=(description or "").strip(),
        source_url=(source_url or "").strip(),
        source_release_date=source_release_date,
        source_metadata=source_metadata or {},
        builtin=builtin,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="compliance_framework.created",
        object_type="compliance_framework",
        object_id=row.id,
        details={"slug": row.slug, "version": row.version, "name": row.name, "builtin": row.builtin},
    )
    return row


def update_framework(
    db: Session,
    *,
    actor: User,
    framework_id: int,
    name: str | None = None,
    publisher: str | None = None,
    description: str | None = None,
    source_url: str | None = None,
    source_release_date: date | None | object = None,
    source_metadata: dict | None = None,
) -> ComplianceFramework:
    row = db.get(ComplianceFramework, framework_id)
    if row is None:
        raise ComplianceError("Framework not found", 404)
    before = {
        "name": row.name,
        "publisher": row.publisher,
        "description": row.description,
        "source_url": row.source_url,
    }
    if name is not None:
        title = name.strip()
        if not title:
            raise ComplianceError("Framework name is required")
        row.name = title
    if publisher is not None:
        row.publisher = publisher.strip()
    if description is not None:
        row.description = description.strip()
    if source_url is not None:
        row.source_url = source_url.strip()
    if source_release_date is not None:
        row.source_release_date = source_release_date if isinstance(source_release_date, date) else _parse_date(source_release_date)
    if source_metadata is not None:
        row.source_metadata = source_metadata
    row.updated_at = utcnow()
    record_audit(
        db,
        actor=actor,
        action="compliance_framework.changed",
        object_type="compliance_framework",
        object_id=row.id,
        details={"before": before, "after": {"name": row.name, "publisher": row.publisher, "description": row.description, "source_url": row.source_url}},
    )
    return row


def archive_framework(db: Session, *, actor: User, framework_id: int) -> ComplianceFramework:
    row = db.get(ComplianceFramework, framework_id)
    if row is None:
        raise ComplianceError("Framework not found", 404)
    if row.archived_at is not None:
        raise ComplianceError("Framework is already archived")
    row.archived_at = utcnow()
    row.updated_at = row.archived_at
    record_audit(
        db,
        actor=actor,
        action="compliance_framework.archived",
        object_type="compliance_framework",
        object_id=row.id,
        details={"slug": row.slug, "version": row.version},
    )
    return row


def create_control(
    db: Session,
    *,
    actor: User,
    framework_id: int,
    control_key: str,
    title: str,
    description: str = "",
    family: str | None = None,
    source_metadata: dict | None = None,
    sort_order: int | None = None,
) -> ComplianceControl:
    framework = db.get(ComplianceFramework, framework_id)
    if framework is None:
        raise ComplianceError("Framework not found", 404)
    if framework.archived_at is not None:
        raise ComplianceError("Cannot add a control to an archived framework")
    key = (control_key or "").strip()
    heading = (title or "").strip()
    if not key or not heading:
        raise ComplianceError("Control ID and title are required")
    existing = (
        db.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == framework.id, ComplianceControl.control_key == key)
        .first()
    )
    if existing is not None:
        raise ComplianceError("A control with this ID already exists in the framework", 409)
    now = utcnow()
    row = ComplianceControl(
        framework_id=framework.id,
        control_key=key,
        family=(family or "").strip() or None,
        title=heading,
        description=(description or "").strip(),
        source_metadata=source_metadata or {},
        sort_order=sort_order,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="compliance_control.created",
        object_type="compliance_control",
        object_id=row.id,
        details={"framework_id": framework.id, "control_key": row.control_key, "title": row.title},
    )
    return row


def update_control(
    db: Session,
    *,
    actor: User,
    control_id: int,
    title: str | None = None,
    description: str | None = None,
    family: str | None = None,
    sort_order: int | None = None,
) -> ComplianceControl:
    row = db.get(ComplianceControl, control_id)
    if row is None:
        raise ComplianceError("Control not found", 404)
    before = {"title": row.title, "description": row.description, "family": row.family, "sort_order": row.sort_order}
    if title is not None:
        heading = title.strip()
        if not heading:
            raise ComplianceError("Control title is required")
        row.title = heading
    if description is not None:
        row.description = description.strip()
    if family is not None:
        row.family = family.strip() or None
    if sort_order is not None:
        row.sort_order = sort_order
    row.updated_at = utcnow()
    record_audit(
        db,
        actor=actor,
        action="compliance_control.changed",
        object_type="compliance_control",
        object_id=row.id,
        details={"before": before, "after": {"title": row.title, "description": row.description, "family": row.family, "sort_order": row.sort_order}},
    )
    return row


def archive_control(db: Session, *, actor: User, control_id: int) -> ComplianceControl:
    row = db.get(ComplianceControl, control_id)
    if row is None:
        raise ComplianceError("Control not found", 404)
    if row.archived_at is not None:
        raise ComplianceError("Control is already archived")
    row.archived_at = utcnow()
    row.updated_at = row.archived_at
    record_audit(
        db,
        actor=actor,
        action="compliance_control.archived",
        object_type="compliance_control",
        object_id=row.id,
        details={"framework_id": row.framework_id, "control_key": row.control_key},
    )
    return row


def _validate_bundle(payload: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(payload, dict):
        raise ComplianceError("Built-in framework file must be a JSON object")
    framework = payload.get("framework")
    controls = payload.get("controls")
    if not isinstance(framework, dict):
        raise ComplianceError("Built-in framework file is missing framework metadata")
    if not isinstance(controls, list) or not controls:
        raise ComplianceError("Built-in framework file must include a non-empty controls list")
    slug = str(framework.get("slug") or "").strip().lower()
    version = str(framework.get("version") or "").strip()
    name = str(framework.get("name") or "").strip()
    if not slug or not version or not name:
        raise ComplianceError("Built-in framework slug, name, and version are required")
    seen: set[str] = set()
    cleaned: list[dict[str, Any]] = []
    for index, item in enumerate(controls):
        if not isinstance(item, dict):
            raise ComplianceError(f"Control at index {index} is malformed")
        key = str(item.get("control_key") or "").strip()
        title = str(item.get("title") or "").strip()
        if not key:
            raise ComplianceError(f"Control at index {index} is missing control_key")
        if key in seen:
            raise ComplianceError(f"Duplicate control_key in built-in source: {key}")
        seen.add(key)
        cleaned.append(
            {
                "control_key": key,
                "family": (str(item.get("family") or "").strip() or None),
                "title": title or key,
                "description": str(item.get("description") or "").strip(),
                "source_metadata": item.get("source_metadata") if isinstance(item.get("source_metadata"), dict) else {},
                "sort_order": item.get("sort_order") if isinstance(item.get("sort_order"), int) else index + 1,
            }
        )
    return framework, cleaned


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bundle_controls_checksum(controls: list[Any]) -> str:
    return hashlib.sha256(_canonical_json(controls)).hexdigest()


def bundle_content_checksum(payload: dict[str, Any]) -> str:
    stripped = copy.deepcopy(payload)
    provenance = stripped.get("provenance")
    if isinstance(provenance, dict):
        provenance.pop("checksum_sha256", None)
        provenance.pop("controls_checksum_sha256", None)
    return hashlib.sha256(_canonical_json(stripped)).hexdigest()


def _verify_bundle_provenance(payload: dict[str, Any], controls: list[dict[str, Any]]) -> None:
    provenance = payload.get("provenance")
    if not isinstance(provenance, dict) or not provenance:
        raise ComplianceError("Built-in framework file is missing provenance")
    expected_count = provenance.get("oscal_control_count_with_statement")
    if expected_count is None:
        raise ComplianceError("Built-in framework provenance is missing control count")
    try:
        count = int(expected_count)
    except (TypeError, ValueError) as exc:
        raise ComplianceError("Built-in framework provenance control count is invalid") from exc
    if count != len(controls):
        raise ComplianceError("Built-in framework control count does not match recorded provenance")
    recorded_controls = str(provenance.get("controls_checksum_sha256") or "").strip().lower()
    actual_controls = bundle_controls_checksum(payload.get("controls") or [])
    if not recorded_controls or recorded_controls != actual_controls:
        raise ComplianceError("Built-in framework controls checksum does not match recorded provenance")
    recorded_bundle = str(provenance.get("checksum_sha256") or "").strip().lower()
    actual_bundle = bundle_content_checksum(payload)
    if not recorded_bundle or recorded_bundle != actual_bundle:
        raise ComplianceError("Built-in framework content checksum does not match recorded provenance")


def import_builtin_framework(db: Session, path: Path, *, actor: User | None = None) -> ComplianceFramework:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ComplianceError(f"Built-in framework file is unreadable: {path.name}") from exc
    framework_data, controls = _validate_bundle(payload)
    _verify_bundle_provenance(payload, controls)
    slug = str(framework_data["slug"]).strip().lower()
    version = str(framework_data["version"]).strip()
    nested = db.begin_nested()
    try:
        row = (
            db.query(ComplianceFramework)
            .filter(ComplianceFramework.slug == slug, ComplianceFramework.version == version)
            .first()
        )
        created = False
        if row is None:
            now = utcnow()
            row = ComplianceFramework(
                slug=slug,
                name=str(framework_data.get("name") or "").strip(),
                version=version,
                publisher=str(framework_data.get("publisher") or "").strip(),
                description=str(framework_data.get("description") or "").strip(),
                source_url=str(framework_data.get("source_url") or "").strip(),
                source_release_date=_parse_date(framework_data.get("source_release_date")),
                source_metadata={
                    **(framework_data.get("source_metadata") if isinstance(framework_data.get("source_metadata"), dict) else {}),
                    "provenance": payload.get("provenance") if isinstance(payload.get("provenance"), dict) else {},
                },
                builtin=True,
                created_at=now,
                updated_at=now,
            )
            db.add(row)
            db.flush()
            created = True
        existing = {
            item.control_key: item
            for item in db.query(ComplianceControl).filter(ComplianceControl.framework_id == row.id).all()
        }
        added = 0
        for item in controls:
            if item["control_key"] in existing:
                continue
            db.add(
                ComplianceControl(
                    framework_id=row.id,
                    control_key=item["control_key"],
                    family=item["family"],
                    title=item["title"],
                    description=item["description"],
                    source_metadata=item["source_metadata"],
                    sort_order=item["sort_order"],
                    created_at=utcnow(),
                    updated_at=utcnow(),
                )
            )
            added += 1
        db.flush()
        nested.commit()
    except Exception:
        nested.rollback()
        raise
    record_audit(
        db,
        actor=actor,
        action="compliance_framework.imported",
        object_type="compliance_framework",
        object_id=row.id,
        details={
            "slug": row.slug,
            "version": row.version,
            "source_file": path.name,
            "created": created,
            "controls_added": added,
            "disclaimer": COMPLIANCE_MAPPING_DISCLAIMER,
        },
    )
    return row


def import_builtin_frameworks(db: Session, *, actor: User | None = None) -> list[ComplianceFramework]:
    if not INDEX_PATH.is_file():
        raise ComplianceError("Built-in compliance index is missing")
    try:
        index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ComplianceError("Built-in compliance index is malformed") from exc
    entries = index.get("builtin_frameworks")
    if not isinstance(entries, list):
        raise ComplianceError("Built-in compliance index is missing builtin_frameworks")
    imported: list[ComplianceFramework] = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("file"):
            raise ComplianceError("Built-in compliance index entry is malformed")
        path = COMPLIANCE_DATA_DIR / str(entry["file"])
        if not path.is_file():
            raise ComplianceError(f"Built-in framework file is missing: {entry['file']}")
        imported.append(import_builtin_framework(db, path, actor=actor))
    return imported


def _subject_tenant_id(obj: Asset | AssetFinding | Finding | FindingTreatment | ScanJob) -> int | None:
    return getattr(obj, "tenant_id", None)


def resolve_subject(
    db: Session,
    *,
    tenant_id: int,
    subject_type: str,
    subject_id: int,
):
    kind = (subject_type or "").strip()
    if kind not in CONTROL_SUBJECT_TYPES:
        raise ComplianceError("Unsupported evidence object type")
    model = {
        CONTROL_SUBJECT_ASSET: Asset,
        CONTROL_SUBJECT_ASSET_FINDING: AssetFinding,
        CONTROL_SUBJECT_FINDING: Finding,
        CONTROL_SUBJECT_TREATMENT: FindingTreatment,
        CONTROL_SUBJECT_SCAN_JOB: ScanJob,
    }[kind]
    obj = db.get(model, subject_id)
    if obj is None:
        raise ComplianceError("Evidence object not found", 404)
    obj_tenant = _subject_tenant_id(obj)
    if obj_tenant is None or obj_tenant != tenant_id:
        raise ComplianceError("Evidence object not found", 404)
    return obj, kind


def add_control_reference(
    db: Session,
    *,
    tenant_id: int,
    control_id: int,
    subject_type: str,
    subject_id: int,
    actor: User,
    reference_type: str = CONTROL_REF_RELATED,
    notes: str = "",
) -> ComplianceControlReference:
    rel = (reference_type or CONTROL_REF_RELATED).strip()
    if rel not in CONTROL_REFERENCE_TYPES:
        raise ComplianceError("Unsupported reference type")
    control = db.get(ComplianceControl, control_id)
    if control is None:
        raise ComplianceError("Control not found", 404)
    if control.archived_at is not None:
        raise ComplianceError("Archived controls cannot receive a new mapping")
    framework = db.get(ComplianceFramework, control.framework_id)
    if framework is not None and framework.archived_at is not None:
        raise ComplianceError("Controls from an archived framework cannot receive a new mapping")
    _obj, kind = resolve_subject(db, tenant_id=tenant_id, subject_type=subject_type, subject_id=subject_id)
    field = SUBJECT_FIELDS[kind]
    values = {name: None for name in SUBJECT_FIELDS.values()}
    values[field] = subject_id
    now = utcnow()
    row = ComplianceControlReference(
        tenant_id=tenant_id,
        control_id=control.id,
        reference_type=rel,
        notes=(notes or "").strip(),
        created_by_user_id=actor.id,
        created_at=now,
        **values,
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError as exc:
        raise ComplianceError("An active mapping to this control already exists for that object", 409) from exc
    record_audit(
        db,
        actor=actor,
        action="control_reference.added",
        object_type="control_reference",
        object_id=row.id,
        tenant_id=tenant_id,
        details={
            "control_id": control.id,
            "control_key": control.control_key,
            "subject_type": kind,
            "subject_id": subject_id,
            "reference_type": rel,
            "disclaimer": COMPLIANCE_MAPPING_DISCLAIMER,
        },
    )
    return row


def remove_control_reference(
    db: Session,
    *,
    tenant_id: int,
    reference_id: int,
    actor: User,
    reason: str,
) -> ComplianceControlReference:
    text = (reason or "").strip()
    if not text:
        raise ComplianceError("Removal reason is required")
    row = (
        db.query(ComplianceControlReference)
        .filter(ComplianceControlReference.id == reference_id, ComplianceControlReference.tenant_id == tenant_id)
        .first()
    )
    if row is None:
        raise ComplianceError("Control mapping not found", 404)
    if row.removed_at is not None:
        raise ComplianceError("Control mapping is already removed")
    row.removed_at = utcnow()
    row.removed_by_user_id = actor.id
    row.removal_reason = text
    record_audit(
        db,
        actor=actor,
        action="control_reference.removed",
        object_type="control_reference",
        object_id=row.id,
        tenant_id=tenant_id,
        details={
            "control_id": row.control_id,
            "reason": text,
            "disclaimer": COMPLIANCE_MAPPING_DISCLAIMER,
        },
    )
    return row


def list_control_references(
    db: Session,
    *,
    tenant_id: int,
    subject_type: str,
    subject_id: int,
    include_removed: bool = False,
) -> list[ComplianceControlReference]:
    _obj, kind = resolve_subject(db, tenant_id=tenant_id, subject_type=subject_type, subject_id=subject_id)
    field = SUBJECT_FIELDS[kind]
    query = (
        db.query(ComplianceControlReference)
        .options(selectinload(ComplianceControlReference.control).selectinload(ComplianceControl.framework))
        .filter(
            ComplianceControlReference.tenant_id == tenant_id,
            getattr(ComplianceControlReference, field) == subject_id,
        )
    )
    if not include_removed:
        query = query.filter(ComplianceControlReference.removed_at.is_(None))
    return query.order_by(ComplianceControlReference.created_at.asc(), ComplianceControlReference.id.asc()).all()


def list_asset_finding_control_references(
    db: Session,
    *,
    tenant_id: int,
    asset_finding: AssetFinding,
    include_removed: bool = False,
) -> list[ComplianceControlReference]:
    treatment_ids = [row.id for row in asset_finding.treatments]
    evidence_ids = [row.id for row in asset_finding.evidence]
    clauses = [ComplianceControlReference.asset_finding_id == asset_finding.id]
    if treatment_ids:
        clauses.append(ComplianceControlReference.treatment_id.in_(treatment_ids))
    if evidence_ids:
        clauses.append(ComplianceControlReference.finding_id.in_(evidence_ids))
    query = (
        db.query(ComplianceControlReference)
        .options(selectinload(ComplianceControlReference.control).selectinload(ComplianceControl.framework))
        .filter(ComplianceControlReference.tenant_id == tenant_id, or_(*clauses))
    )
    if not include_removed:
        query = query.filter(ComplianceControlReference.removed_at.is_(None))
    return query.order_by(ComplianceControlReference.created_at.asc(), ComplianceControlReference.id.asc()).all()


def reassign_asset_finding_control_references(
    db: Session,
    *,
    keeper: AssetFinding,
    donor: AssetFinding,
    now: datetime,
) -> None:
    donor_refs = (
        db.query(ComplianceControlReference)
        .filter(
            ComplianceControlReference.asset_finding_id == donor.id,
            ComplianceControlReference.removed_at.is_(None),
        )
        .all()
    )
    keeper_keys = {
        row.control_id
        for row in db.query(ComplianceControlReference)
        .filter(
            ComplianceControlReference.asset_finding_id == keeper.id,
            ComplianceControlReference.removed_at.is_(None),
        )
        .all()
    }
    for row in donor_refs:
        old_subject_id = row.asset_finding_id
        if row.control_id in keeper_keys:
            row.removed_at = now
            row.removed_by_user_id = None
            row.removal_reason = MERGE_REFERENCE_REMOVE_REASON
            record_audit(
                db,
                actor=None,
                action="control_reference.removed",
                object_type="control_reference",
                object_id=row.id,
                tenant_id=keeper.tenant_id,
                details={
                    "control_id": row.control_id,
                    "reference_id": row.id,
                    "donor_asset_finding_id": donor.id,
                    "keeper_asset_finding_id": keeper.id,
                    "old_subject": {"subject_type": "asset_finding", "subject_id": old_subject_id},
                    "new_disposition": "removed",
                    "reason": MERGE_REFERENCE_REMOVE_REASON,
                    "disclaimer": COMPLIANCE_MAPPING_DISCLAIMER,
                    "actor": "system",
                },
            )
            continue
        row.asset_finding_id = keeper.id
        row.tenant_id = keeper.tenant_id
        keeper_keys.add(row.control_id)
        record_audit(
            db,
            actor=None,
            action="control_reference.moved",
            object_type="control_reference",
            object_id=row.id,
            tenant_id=keeper.tenant_id,
            details={
                "control_id": row.control_id,
                "reference_id": row.id,
                "donor_asset_finding_id": donor.id,
                "keeper_asset_finding_id": keeper.id,
                "old_subject": {"subject_type": "asset_finding", "subject_id": old_subject_id},
                "new_subject": {"subject_type": "asset_finding", "subject_id": keeper.id},
                "new_disposition": "moved",
                "reason": MERGE_REFERENCE_MOVE_REASON,
                "disclaimer": COMPLIANCE_MAPPING_DISCLAIMER,
                "actor": "system",
            },
        )


__all__ = [
    "COMPLIANCE_MAPPING_DISCLAIMER",
    "ComplianceError",
    "add_control_reference",
    "archive_control",
    "archive_framework",
    "create_control",
    "create_framework",
    "import_builtin_framework",
    "import_builtin_frameworks",
    "list_asset_finding_control_references",
    "list_control_references",
    "reassign_asset_finding_control_references",
    "remove_control_reference",
    "resolve_subject",
    "update_control",
    "update_framework",
]
