"""Isolated tenant + WAN ScanJob world for S2A ingest measurement."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import (
    SNAPSHOT_VERSION,
    Finding,
    Scan,
    ScanJob,
    Tenant,
)
from tests.scale_s2.workloads import IngestWorkload


@dataclass
class IngestWorld:
    tenant_id: int
    scan_id: int
    job_id: int


def create_ingest_world(db: Session, *, label: str = "s2a") -> IngestWorld:
    suffix = uuid4().hex[:8]
    tenant = Tenant(name=f"{label}-{suffix}", notes="s2a-harness")
    db.add(tenant)
    db.flush()
    scan = Scan(
        tenant_id=tenant.id,
        name=f"{label}-wan",
        scope="wan",
        profile="discovery_nuclei",
    )
    db.add(scan)
    db.flush()
    job = ScanJob(
        scan_id=scan.id,
        tenant_id=tenant.id,
        status="running",
        snapshot_version=SNAPSHOT_VERSION,
        execution_snapshot={
            "scope": "wan",
            "site": {},
            "targets": {"wan_targets": [], "networks": []},
            "stages": {"discovery": True, "fingerprint": True, "vulnerability": True},
        },
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return IngestWorld(tenant_id=tenant.id, scan_id=scan.id, job_id=job.id)


def seed_historical_findings(db: Session, world: IngestWorld, workload: IngestWorkload) -> int:
    added = 0
    for row in workload.historical:
        db.add(
            Finding(
                tenant_id=world.tenant_id,
                scan_job_id=None,
                detector_type=row["detector_type"],
                detector_key=row["detector_key"],
                evidence_key=row["evidence_key"],
                template_id=row["template_id"],
                name=row["name"],
                severity=row["severity"],
                host=row["host"],
                matched_at=row["matched_at"],
                raw_json=row["raw_json"],
            )
        )
        added += 1
    if added:
        db.commit()
    return added


def reset_schema() -> None:
    from sqlalchemy import text

    from app.database import engine
    from app.migrate import apply_schema

    engine.dispose()
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()
    apply_schema()
