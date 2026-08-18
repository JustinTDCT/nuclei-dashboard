"""Phase 2A finding identity repair and detector coverage.

Revision ID: 0008_phase2a_finding_identity_repair
Revises: 0007_vulnerability_finding_lifecycle
Create Date: 2026-08-18 18:45:00.000000+00:00

Do not import live application models. Do not edit 0001–0007.

Repairs catalog/mapping inconsistency created when the same detector key
appeared first without CVE metadata and later with a CVE. Creates
catalog/mapping rows for unlinked evidence that has a known detector
identity. Adds explicit Run detector-coverage evidence.

Downgrade is refused: reverting would destroy coverage evidence and
reintroduce inconsistent catalog identity.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

revision: str = "0008_phase2a_finding_identity_repair"
down_revision: str | None = "0007_vulnerability_finding_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _parse_raw(value) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _explicit_cves(raw: dict) -> list[str]:
    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    candidates: list[str] = []
    for key in ("cve-id", "cve_id", "cve"):
        value = classification.get(key)
        if isinstance(value, list):
            candidates.extend(str(item) for item in value if item)
        elif value:
            candidates.append(str(value))
    seen: list[str] = []
    for item in candidates:
        token = item.strip().upper()
        if CVE_RE.match(token) and token not in seen:
            seen.append(token)
    return seen


def _single_cve(raw: dict) -> str | None:
    cves = _explicit_cves(raw)
    if len(cves) == 1:
        return cves[0]
    return None


def upgrade() -> None:
    op.create_table(
        "scan_run_detector_coverage",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("detector_type", sa.String(length=40), nullable=False),
        sa.Column("target", sa.String(length=500), nullable=False),
        sa.Column("normalized_host", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("target_kind", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint(
            "scan_job_id",
            "detector_type",
            "target",
            name="uq_scan_run_detector_coverage_job_detector_target",
        ),
        sa.CheckConstraint(
            "target_kind IN ('url', 'ip', 'ip_port', 'fqdn', 'cidr', 'other')",
            name="ck_scan_run_detector_coverage_target_kind",
        ),
    )
    op.create_index("ix_scan_run_detector_coverage_tenant_id", "scan_run_detector_coverage", ["tenant_id"])
    op.create_index("ix_scan_run_detector_coverage_scan_job_id", "scan_run_detector_coverage", ["scan_job_id"])
    op.create_index(
        "ix_scan_run_detector_coverage_scan_job_id_detector_type",
        "scan_run_detector_coverage",
        ["scan_job_id", "detector_type"],
    )
    _repair_catalog_identity()


def _upsert_vulnerability(bind, cache: dict[str, int], canonical_key: str, cve_id: str | None, title: str) -> int:
    if canonical_key in cache:
        return cache[canonical_key]
    existing = bind.execute(
        text("SELECT id FROM vulnerabilities WHERE canonical_key = :k"),
        {"k": canonical_key},
    ).scalar()
    if existing is None:
        vuln_id = bind.execute(
            text(
                """
                INSERT INTO vulnerabilities (canonical_key, cve_id, title, description)
                VALUES (:k, :cve, :title, '')
                RETURNING id
                """
            ),
            {"k": canonical_key, "cve": cve_id, "title": title},
        ).scalar_one()
    else:
        vuln_id = int(existing)
        if cve_id:
            bind.execute(
                text(
                    """
                    UPDATE vulnerabilities
                    SET cve_id = COALESCE(NULLIF(cve_id, ''), :cve),
                        title = CASE WHEN title = '' THEN :title ELSE title END,
                        updated_at = NOW()
                    WHERE id = :id
                    """
                ),
                {"cve": cve_id, "title": title, "id": vuln_id},
            )
    cache[canonical_key] = int(vuln_id)
    return int(vuln_id)


def _merge_asset_finding(bind, keeper_id: int, donor_id: int) -> None:
    if keeper_id == donor_id:
        return
    keeper = bind.execute(
        text(
            """
            SELECT first_seen, last_seen, technical_state, resolved_at, consecutive_clean_scans,
                   reopened_count, treatment_state
            FROM asset_findings WHERE id = :id
            """
        ),
        {"id": keeper_id},
    ).mappings().one()
    donor = bind.execute(
        text(
            """
            SELECT first_seen, last_seen, technical_state, resolved_at, consecutive_clean_scans,
                   reopened_count, treatment_state
            FROM asset_findings WHERE id = :id
            """
        ),
        {"id": donor_id},
    ).mappings().one()
    first_seen = min(keeper["first_seen"], donor["first_seen"])
    last_seen = max(keeper["last_seen"], donor["last_seen"])
    reopened = int(keeper["reopened_count"] or 0) + int(donor["reopened_count"] or 0)
    if keeper["technical_state"] == "open" or donor["technical_state"] == "open":
        technical = "open"
        resolved_at = None
        clean = min(int(keeper["consecutive_clean_scans"] or 0), int(donor["consecutive_clean_scans"] or 0))
    else:
        technical = "resolved"
        stamps = [stamp for stamp in (keeper["resolved_at"], donor["resolved_at"]) if stamp]
        resolved_at = max(stamps) if stamps else keeper["resolved_at"]
        clean = max(int(keeper["consecutive_clean_scans"] or 0), int(donor["consecutive_clean_scans"] or 0))
    treatment = keeper["treatment_state"]
    if keeper["treatment_state"] != donor["treatment_state"]:
        treatment = "unaddressed"
    bind.execute(
        text(
            """
            UPDATE asset_findings
            SET first_seen = :first, last_seen = :last, technical_state = :tech,
                resolved_at = :resolved, consecutive_clean_scans = :clean,
                reopened_count = :reopened, treatment_state = :treatment, updated_at = NOW()
            WHERE id = :id
            """
        ),
        {
            "first": first_seen,
            "last": last_seen,
            "tech": technical,
            "resolved": resolved_at,
            "clean": clean,
            "reopened": reopened,
            "treatment": treatment,
            "id": keeper_id,
        },
    )
    bind.execute(
        text(
            """
            UPDATE findings
            SET asset_finding_id = :keeper
            WHERE asset_finding_id = :donor
            """
        ),
        {"keeper": keeper_id, "donor": donor_id},
    )
    bind.execute(
        text(
            """
            UPDATE asset_finding_history
            SET asset_finding_id = :keeper
            WHERE asset_finding_id = :donor
            """
        ),
        {"keeper": keeper_id, "donor": donor_id},
    )
    donor_evals = bind.execute(
        text("SELECT id, scan_job_id, outcome FROM asset_finding_run_evaluations WHERE asset_finding_id = :id"),
        {"id": donor_id},
    ).mappings().all()
    for evaluation in donor_evals:
        collision = bind.execute(
            text(
                """
                SELECT id, outcome FROM asset_finding_run_evaluations
                WHERE asset_finding_id = :keeper AND scan_job_id = :job
                """
            ),
            {"keeper": keeper_id, "job": evaluation["scan_job_id"]},
        ).mappings().first()
        if collision is None:
            bind.execute(
                text("UPDATE asset_finding_run_evaluations SET asset_finding_id = :keeper WHERE id = :id"),
                {"keeper": keeper_id, "id": evaluation["id"]},
            )
        elif collision["outcome"] != "detected" and evaluation["outcome"] == "detected":
            bind.execute(text("DELETE FROM asset_finding_run_evaluations WHERE id = :id"), {"id": collision["id"]})
            bind.execute(
                text("UPDATE asset_finding_run_evaluations SET asset_finding_id = :keeper WHERE id = :id"),
                {"keeper": keeper_id, "id": evaluation["id"]},
            )
        else:
            bind.execute(text("DELETE FROM asset_finding_run_evaluations WHERE id = :id"), {"id": evaluation["id"]})
    bind.execute(text("DELETE FROM asset_findings WHERE id = :id"), {"id": donor_id})


def _repair_catalog_identity() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        text(
            """
            SELECT id, template_id, name, severity, tags, raw_json, detector_type, detector_key,
                   asset_id, asset_finding_id
            FROM findings
            ORDER BY id
            """
        )
    ).mappings().all()

    grouped: dict[tuple[str, str], list] = defaultdict(list)
    for row in rows:
        raw = _parse_raw(row["raw_json"])
        detector_key = (row["detector_key"] or row["template_id"] or raw.get("template-id") or "").strip()
        detector_type = (row["detector_type"] or ("nuclei" if detector_key else "")).strip()
        if not detector_key or not detector_type:
            continue
        grouped[(detector_type, detector_key)].append(row)
        if not row["detector_key"] or not row["detector_type"]:
            bind.execute(
                text(
                    """
                    UPDATE findings
                    SET detector_type = :dtype, detector_key = :dkey
                    WHERE id = :id
                    """
                ),
                {"dtype": detector_type, "dkey": detector_key, "id": row["id"]},
            )

    vuln_cache: dict[str, int] = {}
    for (detector_type, detector_key), items in grouped.items():
        cves = set()
        title = ""
        severity = ""
        tags = ""
        for item in items:
            raw = _parse_raw(item["raw_json"])
            extracted = _single_cve(raw)
            if extracted:
                cves.add(extracted)
            title = title or (item["name"] or "").strip()
            severity = severity or (item["severity"] or "").strip().lower()
            tags = tags or (item["tags"] or "").strip()
        if len(cves) == 1:
            cve_id = next(iter(cves))
            canonical_key = f"cve:{cve_id}"
        else:
            cve_id = None
            canonical_key = f"{detector_type}:{detector_key}"
        vuln_id = _upsert_vulnerability(bind, vuln_cache, canonical_key, cve_id, title)
        existing_map = bind.execute(
            text(
                """
                SELECT id, vulnerability_id FROM vulnerability_detector_mappings
                WHERE detector_type = :t AND detector_key = :k
                """
            ),
            {"t": detector_type, "k": detector_key},
        ).mappings().first()
        if existing_map is None:
            bind.execute(
                text(
                    """
                    INSERT INTO vulnerability_detector_mappings
                        (vulnerability_id, detector_type, detector_key, last_severity, last_tags)
                    VALUES (:v, :t, :k, :sev, :tags)
                    """
                ),
                {"v": vuln_id, "t": detector_type, "k": detector_key, "sev": severity, "tags": tags},
            )
        elif int(existing_map["vulnerability_id"]) != vuln_id:
            bind.execute(
                text(
                    """
                    UPDATE vulnerability_detector_mappings
                    SET vulnerability_id = :v,
                        last_severity = CASE WHEN last_severity = '' THEN :sev ELSE last_severity END,
                        last_tags = CASE WHEN last_tags = '' THEN :tags ELSE last_tags END
                    WHERE id = :id
                    """
                ),
                {"v": vuln_id, "sev": severity, "tags": tags, "id": existing_map["id"]},
            )
        affected = bind.execute(
            text(
                """
                SELECT DISTINCT asset_finding_id
                FROM findings
                WHERE detector_type = :t AND detector_key = :k AND asset_finding_id IS NOT NULL
                """
            ),
            {"t": detector_type, "k": detector_key},
        ).scalars().all()
        for asset_finding_id in affected:
            af = bind.execute(
                text("SELECT id, asset_id, vulnerability_id, tenant_id FROM asset_findings WHERE id = :id"),
                {"id": int(asset_finding_id)},
            ).mappings().first()
            if af is None or int(af["vulnerability_id"]) == vuln_id:
                continue
            collision = bind.execute(
                text(
                    """
                    SELECT id FROM asset_findings
                    WHERE asset_id = :asset AND vulnerability_id = :vuln AND id <> :id
                    """
                ),
                {"asset": af["asset_id"], "vuln": vuln_id, "id": af["id"]},
            ).scalar()
            if collision is None:
                bind.execute(
                    text("UPDATE asset_findings SET vulnerability_id = :v, updated_at = NOW() WHERE id = :id"),
                    {"v": vuln_id, "id": af["id"]},
                )
            else:
                _merge_asset_finding(bind, int(collision), int(af["id"]))


def downgrade() -> None:
    raise RuntimeError(
        "Refusing to downgrade 0008_phase2a_finding_identity_repair: this would destroy "
        "Run detector-coverage evidence and reintroduce inconsistent catalog/mapping identity. "
        "Restore from backup instead."
    )
