from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from app.auth import require_admin, require_any, require_user
from app.compliance import (
    COMPLIANCE_MAPPING_DISCLAIMER,
    ComplianceError,
    add_control_reference,
    archive_control,
    archive_framework,
    create_control,
    create_framework,
    import_builtin_frameworks,
    list_control_references,
    remove_control_reference,
    update_control,
    update_framework,
)
from app.database import get_db
from app.models import (
    CONTROL_SUBJECT_TYPES,
    ComplianceControl,
    ComplianceControlReference,
    ComplianceFramework,
    Tenant,
    User,
)
from app.usernames import load_usernames
from app.schemas import (
    ControlIn,
    ControlOut,
    ControlReferenceIn,
    ControlReferenceOut,
    ControlReferenceRemoveIn,
    ControlUpdateIn,
    FrameworkDetailOut,
    FrameworkIn,
    FrameworkOut,
    FrameworkUpdateIn,
)

router = APIRouter(tags=["compliance"])


def _require_tenant(db: Session, tenant_id: int) -> Tenant:
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def _run(fn, db: Session):
    try:
        result = fn()
        db.commit()
        return result
    except ComplianceError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


def serialize_control(row: ComplianceControl) -> ControlOut:
    framework = row.framework
    return ControlOut(
        id=row.id,
        framework_id=row.framework_id,
        control_key=row.control_key,
        family=row.family,
        title=row.title,
        description=row.description,
        source_metadata=row.source_metadata or {},
        sort_order=row.sort_order,
        archived_at=row.archived_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
        framework_slug=framework.slug if framework else None,
        framework_name=framework.name if framework else None,
        framework_version=framework.version if framework else None,
        framework_publisher=framework.publisher if framework else None,
    )


def serialize_framework(row: ComplianceFramework, control_count: int = 0) -> FrameworkOut:
    return FrameworkOut(
        id=row.id,
        slug=row.slug,
        name=row.name,
        version=row.version,
        publisher=row.publisher,
        description=row.description,
        source_url=row.source_url,
        source_release_date=row.source_release_date,
        source_metadata=row.source_metadata or {},
        builtin=row.builtin,
        archived_at=row.archived_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
        control_count=control_count,
        mapping_disclaimer=COMPLIANCE_MAPPING_DISCLAIMER,
    )


def _subject_of(row: ComplianceControlReference) -> tuple[str, int]:
    if row.asset_id is not None:
        return "asset", row.asset_id
    if row.asset_finding_id is not None:
        return "asset_finding", row.asset_finding_id
    if row.finding_id is not None:
        return "finding", row.finding_id
    if row.treatment_id is not None:
        return "treatment", row.treatment_id
    if row.scan_job_id is not None:
        return "scan_job", row.scan_job_id
    raise ComplianceError("Control mapping is missing a subject")


def serialize_reference(
    db: Session,
    row: ComplianceControlReference,
    names: dict[int, str] | None = None,
) -> ControlReferenceOut:
    resolved = names if names is not None else load_usernames(db, (row.created_by_user_id, row.removed_by_user_id))
    subject_type, subject_id = _subject_of(row)
    control = row.control
    framework = control.framework if control else None
    return ControlReferenceOut(
        id=row.id,
        tenant_id=row.tenant_id,
        control_id=row.control_id,
        subject_type=subject_type,
        subject_id=subject_id,
        reference_type=row.reference_type,
        notes=row.notes,
        created_by_user_id=row.created_by_user_id,
        created_by_username=resolved.get(row.created_by_user_id) if row.created_by_user_id else None,
        created_at=row.created_at,
        removed_at=row.removed_at,
        removed_by_user_id=row.removed_by_user_id,
        removed_by_username=resolved.get(row.removed_by_user_id) if row.removed_by_user_id else None,
        removal_reason=row.removal_reason,
        control_key=control.control_key if control else "",
        control_title=control.title if control else "",
        control_family=control.family if control else None,
        framework_name=framework.name if framework else "",
        framework_version=framework.version if framework else "",
        framework_slug=framework.slug if framework else "",
        mapping_disclaimer=COMPLIANCE_MAPPING_DISCLAIMER,
    )


def serialize_references(db: Session, rows: list[ComplianceControlReference]) -> list[ControlReferenceOut]:
    names = load_usernames(
        db,
        [item.created_by_user_id for item in rows] + [item.removed_by_user_id for item in rows],
    )
    return [serialize_reference(db, row, names=names) for row in rows]


@router.get("/compliance/frameworks", response_model=list[FrameworkOut])
def get_frameworks(
    include_archived: bool = False,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    query = db.query(ComplianceFramework)
    if not include_archived:
        query = query.filter(ComplianceFramework.archived_at.is_(None))
    rows = query.order_by(ComplianceFramework.slug.asc(), ComplianceFramework.version.asc()).all()
    counts = dict(
        db.query(ComplianceControl.framework_id, func.count(ComplianceControl.id))
        .group_by(ComplianceControl.framework_id)
        .all()
    )
    return [serialize_framework(row, control_count=int(counts.get(row.id, 0))) for row in rows]


@router.get("/compliance/frameworks/{framework_id}", response_model=FrameworkDetailOut)
def get_framework(
    framework_id: int,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    row = (
        db.query(ComplianceFramework)
        .options(selectinload(ComplianceFramework.controls))
        .filter(ComplianceFramework.id == framework_id)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Framework not found")
    controls = sorted(row.controls, key=lambda item: (item.sort_order is None, item.sort_order or 0, item.control_key))
    base = serialize_framework(row, control_count=len(controls))
    return FrameworkDetailOut(**base.model_dump(), controls=[serialize_control(item) for item in controls])


@router.get("/compliance/frameworks/{framework_id}/controls", response_model=list[ControlOut])
def get_controls(
    framework_id: int,
    q: str | None = None,
    family: str | None = None,
    control_key: str | None = None,
    include_archived: bool = False,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    framework = db.get(ComplianceFramework, framework_id)
    if framework is None:
        raise HTTPException(status_code=404, detail="Framework not found")
    query = (
        db.query(ComplianceControl)
        .options(selectinload(ComplianceControl.framework))
        .filter(ComplianceControl.framework_id == framework_id)
    )
    if not include_archived:
        query = query.filter(ComplianceControl.archived_at.is_(None))
    if family:
        query = query.filter(ComplianceControl.family.ilike(f"%{family.strip()}%"))
    if control_key:
        query = query.filter(ComplianceControl.control_key.ilike(f"%{control_key.strip()}%"))
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(
            (ComplianceControl.control_key.ilike(like))
            | (ComplianceControl.title.ilike(like))
            | (ComplianceControl.family.ilike(like))
        )
    rows = query.order_by(ComplianceControl.sort_order.asc().nulls_last(), ComplianceControl.control_key.asc()).limit(2000).all()
    return [serialize_control(row) for row in rows]


@router.post("/compliance/frameworks", response_model=FrameworkOut)
def post_framework(body: FrameworkIn, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    row = _run(
        lambda: create_framework(
            db,
            actor=user,
            slug=body.slug,
            name=body.name,
            version=body.version,
            publisher=body.publisher,
            description=body.description,
            source_url=body.source_url,
            source_release_date=body.source_release_date,
            source_metadata=body.source_metadata,
        ),
        db,
    )
    return serialize_framework(row)


@router.patch("/compliance/frameworks/{framework_id}", response_model=FrameworkOut)
def patch_framework(
    framework_id: int,
    body: FrameworkUpdateIn,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    row = _run(
        lambda: update_framework(
            db,
            actor=user,
            framework_id=framework_id,
            name=body.name,
            publisher=body.publisher,
            description=body.description,
            source_url=body.source_url,
            source_release_date=body.source_release_date,
            source_metadata=body.source_metadata,
        ),
        db,
    )
    return serialize_framework(row)


@router.post("/compliance/frameworks/{framework_id}/archive", response_model=FrameworkOut)
def post_archive_framework(
    framework_id: int,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return serialize_framework(_run(lambda: archive_framework(db, actor=user, framework_id=framework_id), db))


@router.post("/compliance/frameworks/import-builtin", response_model=list[FrameworkOut])
def post_import_builtin(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = _run(lambda: import_builtin_frameworks(db, actor=user), db)
    counts = dict(
        db.query(ComplianceControl.framework_id, func.count(ComplianceControl.id))
        .group_by(ComplianceControl.framework_id)
        .all()
    )
    return [serialize_framework(row, control_count=int(counts.get(row.id, 0))) for row in rows]


@router.post("/compliance/frameworks/{framework_id}/controls", response_model=ControlOut)
def post_control(
    framework_id: int,
    body: ControlIn,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    row = _run(
        lambda: create_control(
            db,
            actor=user,
            framework_id=framework_id,
            control_key=body.control_key,
            title=body.title,
            description=body.description,
            family=body.family,
            source_metadata=body.source_metadata,
            sort_order=body.sort_order,
        ),
        db,
    )
    row = db.query(ComplianceControl).options(selectinload(ComplianceControl.framework)).filter(ComplianceControl.id == row.id).one()
    return serialize_control(row)


@router.patch("/compliance/controls/{control_id}", response_model=ControlOut)
def patch_control(
    control_id: int,
    body: ControlUpdateIn,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    row = _run(
        lambda: update_control(
            db,
            actor=user,
            control_id=control_id,
            title=body.title,
            description=body.description,
            family=body.family,
            sort_order=body.sort_order,
        ),
        db,
    )
    row = db.query(ComplianceControl).options(selectinload(ComplianceControl.framework)).filter(ComplianceControl.id == row.id).one()
    return serialize_control(row)


@router.post("/compliance/controls/{control_id}/archive", response_model=ControlOut)
def post_archive_control(control_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    row = _run(lambda: archive_control(db, actor=user, control_id=control_id), db)
    row = db.query(ComplianceControl).options(selectinload(ComplianceControl.framework)).filter(ComplianceControl.id == row.id).one()
    return serialize_control(row)


@router.get("/tenants/{tenant_id}/control-references", response_model=list[ControlReferenceOut])
def get_references(
    tenant_id: int,
    subject_type: str = Query(...),
    subject_id: int = Query(...),
    include_removed: bool = False,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    if subject_type not in CONTROL_SUBJECT_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported evidence object type")
    try:
        rows = list_control_references(
            db,
            tenant_id=tenant_id,
            subject_type=subject_type,
            subject_id=subject_id,
            include_removed=include_removed,
        )
    except ComplianceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return serialize_references(db, rows)


@router.post("/tenants/{tenant_id}/control-references", response_model=ControlReferenceOut)
def post_reference(
    tenant_id: int,
    body: ControlReferenceIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    row = _run(
        lambda: add_control_reference(
            db,
            tenant_id=tenant_id,
            control_id=body.control_id,
            subject_type=body.subject_type,
            subject_id=body.subject_id,
            actor=user,
            reference_type=body.reference_type,
            notes=body.notes,
        ),
        db,
    )
    row = (
        db.query(ComplianceControlReference)
        .options(selectinload(ComplianceControlReference.control).selectinload(ComplianceControl.framework))
        .filter(ComplianceControlReference.id == row.id)
        .one()
    )
    return serialize_reference(db, row)


@router.post("/tenants/{tenant_id}/control-references/{reference_id}/remove", response_model=ControlReferenceOut)
def post_remove_reference(
    tenant_id: int,
    reference_id: int,
    body: ControlReferenceRemoveIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    row = _run(
        lambda: remove_control_reference(
            db,
            tenant_id=tenant_id,
            reference_id=reference_id,
            actor=user,
            reason=body.reason,
        ),
        db,
    )
    row = (
        db.query(ComplianceControlReference)
        .options(selectinload(ComplianceControlReference.control).selectinload(ComplianceControl.framework))
        .filter(ComplianceControlReference.id == row.id)
        .one()
    )
    return serialize_reference(db, row)
