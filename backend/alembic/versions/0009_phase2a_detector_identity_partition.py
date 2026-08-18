"""Phase 2A detector identity partition.

Revision ID: 0009_phase2a_detector_identity_partition
Revises: 0008_phase2a_finding_identity_repair
Create Date: 2026-08-18 19:05:00.000000+00:00

Do not import live application models. Do not edit 0001–0008.

Uses the union of every explicit valid CVE across all evidence for a
detector key. CVE identity is used only when that union has exactly one
member. When a detector mapping diverges from a shared Vulnerability,
Detection Evidence is partitioned by detector support instead of moving
the whole Asset Finding.

Downgrade is refused.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0009_phase2a_detector_identity_partition"
down_revision: str | None = "0008_phase2a_finding_identity_repair"
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


def _recompute_seen(bind, asset_finding_id: int) -> None:
    bind.execute(
        text(
            """
            UPDATE asset_findings
            SET first_seen = src.first_seen,
                last_seen = src.last_seen,
                updated_at = NOW()
            FROM (
                SELECT MIN(found_at) AS first_seen, MAX(found_at) AS last_seen
                FROM findings
                WHERE asset_finding_id = :id
            ) src
            WHERE asset_findings.id = :id AND src.first_seen IS NOT NULL
            """
        ),
        {"id": asset_finding_id},
    )


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
    bind.execute(text("UPDATE findings SET asset_finding_id = :keeper WHERE asset_finding_id = :donor"), {"keeper": keeper_id, "donor": donor_id})
    bind.execute(
        text("UPDATE asset_finding_history SET asset_finding_id = :keeper WHERE asset_finding_id = :donor"),
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


def _partition_or_move(bind, *, donor_id: int, target_vuln: int, detector_type: str, detector_key: str) -> None:
    donor = bind.execute(
        text("SELECT id, tenant_id, asset_id, vulnerability_id FROM asset_findings WHERE id = :id"),
        {"id": donor_id},
    ).mappings().first()
    if donor is None or int(donor["vulnerability_id"]) == target_vuln:
        return
    other = bind.execute(
        text(
            """
            SELECT id FROM findings
            WHERE asset_finding_id = :af
              AND (detector_type <> :t OR detector_key <> :k)
            LIMIT 1
            """
        ),
        {"af": donor_id, "t": detector_type, "k": detector_key},
    ).first()
    collision = bind.execute(
        text("SELECT id FROM asset_findings WHERE asset_id = :a AND vulnerability_id = :v AND id <> :id"),
        {"a": donor["asset_id"], "v": target_vuln, "id": donor_id},
    ).scalar()
    if other is None:
        if collision is None:
            bind.execute(
                text("UPDATE asset_findings SET vulnerability_id = :v, updated_at = NOW() WHERE id = :id"),
                {"v": target_vuln, "id": donor_id},
            )
        else:
            _merge_asset_finding(bind, int(collision), donor_id)
        return
    keeper_id = int(collision) if collision is not None else None
    if keeper_id is None:
        bounds = bind.execute(
            text(
                """
                SELECT MIN(found_at) AS first_seen, MAX(found_at) AS last_seen
                FROM findings
                WHERE asset_finding_id = :af AND detector_type = :t AND detector_key = :k
                """
            ),
            {"af": donor_id, "t": detector_type, "k": detector_key},
        ).mappings().one()
        keeper_id = bind.execute(
            text(
                """
                INSERT INTO asset_findings (
                    tenant_id, asset_id, vulnerability_id, technical_state, treatment_state,
                    first_seen, last_seen, resolved_at, consecutive_clean_scans, reopened_count
                )
                VALUES (
                    :tenant, :asset, :vuln, 'open', 'unaddressed',
                    :first, :last, NULL, 0, 0
                )
                RETURNING id
                """
            ),
            {
                "tenant": donor["tenant_id"],
                "asset": donor["asset_id"],
                "vuln": target_vuln,
                "first": bounds["first_seen"],
                "last": bounds["last_seen"],
            },
        ).scalar_one()
        bind.execute(
            text(
                """
                INSERT INTO asset_finding_history (
                    asset_finding_id, tenant_id, transition_type, previous_technical_state,
                    new_technical_state, scan_job_id, occurred_at, details, idempotence_key
                )
                VALUES (
                    :af, :tenant, 'opened', NULL, 'open', NULL, :seen,
                    CAST(:details AS jsonb), :key
                )
                """
            ),
            {
                "af": keeper_id,
                "tenant": donor["tenant_id"],
                "seen": bounds["first_seen"],
                "details": json.dumps(
                    {
                        "reason": "detector_identity_partition",
                        "source": "0009_phase2a_detector_identity_partition",
                        "source_asset_finding_id": donor_id,
                        "detector_type": detector_type,
                        "detector_key": detector_key,
                    }
                ),
                "key": f"partition-opened:{keeper_id}:{detector_type}:{detector_key}",
            },
        )
    bind.execute(
        text(
            """
            UPDATE findings
            SET asset_finding_id = :keeper
            WHERE asset_finding_id = :donor AND detector_type = :t AND detector_key = :k
            """
        ),
        {"keeper": keeper_id, "donor": donor_id, "t": detector_type, "k": detector_key},
    )
    _recompute_seen(bind, int(keeper_id))
    _recompute_seen(bind, donor_id)


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        text(
            """
            SELECT id, template_id, name, raw_json, detector_type, detector_key
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

    vuln_cache: dict[str, int] = {}
    for detector_type, detector_key in sorted(grouped):
        items = grouped[(detector_type, detector_key)]
        cves: set[str] = set()
        title = ""
        for item in items:
            raw = _parse_raw(item["raw_json"])
            cves.update(_explicit_cves(raw))
            title = title or (item["name"] or "").strip()
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
                    VALUES (:v, :t, :k, '', '')
                    """
                ),
                {"v": vuln_id, "t": detector_type, "k": detector_key},
            )
        elif int(existing_map["vulnerability_id"]) != vuln_id:
            bind.execute(
                text("UPDATE vulnerability_detector_mappings SET vulnerability_id = :v WHERE id = :id"),
                {"v": vuln_id, "id": existing_map["id"]},
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
            _partition_or_move(
                bind,
                donor_id=int(asset_finding_id),
                target_vuln=vuln_id,
                detector_type=detector_type,
                detector_key=detector_key,
            )


def downgrade() -> None:
    raise RuntimeError(
        "Refusing to downgrade 0009_phase2a_detector_identity_partition: this would rejoin "
        "partitioned detector evidence onto the wrong Vulnerability and restore incorrect "
        "CVE identity from mixed multi-CVE history. Restore from backup instead."
    )
