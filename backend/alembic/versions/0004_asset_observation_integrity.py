"""Phase 1B corrective: observation integrity and expected lifecycle.

Revision ID: 0004_asset_observation_integrity
Revises: 0003_assets_observations
Create Date: 2026-08-18 13:20:00.000000+00:00

Do not import live application models. Do not edit 0001, 0002, or 0003.

- Observation idempotence becomes (scan_job_id, asset_id, observation_key)
  so one ScanJob can record distinct reports for the same Asset.
- Expected / not-yet-observed Assets store lifecycle_state NULL.
- Hostname identifiers that are only IP/placeholder values are removed.

Downgrade is refused.
"""

from collections.abc import Sequence
from hashlib import sha256
from ipaddress import ip_address
import json

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

revision: str = "0004_asset_observation_integrity"
down_revision: str | None = "0003_assets_observations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _is_ip(value: str) -> bool:
    try:
        ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def _normalize_hostname(value: str) -> str:
    name = (value or "").strip().rstrip(".").lower()
    if name.startswith("*."):
        name = name[2:]
    return name


def _is_placeholder_hostname(value: str, ip: str = "") -> bool:
    name = _normalize_hostname(value)
    return not name or _is_ip(name) or name.startswith("dev-") or bool(ip and name == ip.strip())


def _canonical_ports(ports) -> list[dict]:
    rows: list[dict] = []
    for item in ports or []:
        port = None
        protocol = "tcp"
        if isinstance(item, dict):
            try:
                port = int(item.get("port"))
            except (TypeError, ValueError):
                continue
            protocol = str(item.get("protocol") or "tcp").lower() or "tcp"
        else:
            try:
                port = int(item)
            except (TypeError, ValueError):
                continue
        if port is None:
            continue
        rows.append({"port": port, "protocol": protocol})
    rows.sort(key=lambda row: (row["port"], row["protocol"]))
    return rows


def observation_fingerprint(hostname: str, ip: str, scope: str, ports) -> str:
    host = _normalize_hostname(hostname)
    if _is_placeholder_hostname(host, ip):
        host = ""
    payload = json.dumps(
        {
            "hostname": host,
            "ip": (ip or "").strip(),
            "ports": _canonical_ports(ports),
            "scope": (scope or "").strip().lower(),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return sha256(payload.encode("utf-8")).hexdigest()


def upgrade() -> None:
    op.drop_constraint("ck_assets_lifecycle_state", "assets", type_="check")
    op.alter_column("assets", "lifecycle_state", existing_type=sa.String(length=20), nullable=True)
    op.create_check_constraint(
        "ck_assets_lifecycle_state",
        "assets",
        "lifecycle_state IS NULL OR lifecycle_state IN ('active', 'inactive')",
    )
    op.execute(
        text(
            """
            UPDATE assets
            SET lifecycle_state = NULL
            WHERE is_expected IS TRUE AND first_seen IS NULL
            """
        )
    )

    op.add_column("asset_observations", sa.Column("observation_key", sa.String(length=64), nullable=True))
    conn = op.get_bind()
    rows = conn.execute(
        text(
            """
            SELECT id, hostname, ip, scope, snapshot
            FROM asset_observations
            """
        )
    ).fetchall()
    for row_id, hostname, ip, scope, snapshot in rows:
        snap = snapshot or {}
        if isinstance(snap, str):
            try:
                snap = json.loads(snap)
            except json.JSONDecodeError:
                snap = {}
        if not isinstance(snap, dict):
            snap = {}
        key = observation_fingerprint(
            snap.get("hostname") or hostname or "",
            snap.get("ip") or ip or "",
            snap.get("scope") or scope or "",
            snap.get("ports") if "ports" in snap else [],
        )
        conn.execute(
            text("UPDATE asset_observations SET observation_key = :key WHERE id = :id"),
            {"key": key, "id": row_id},
        )
    conn.execute(text("UPDATE asset_observations SET observation_key = 'unspecified' WHERE observation_key IS NULL"))
    op.alter_column("asset_observations", "observation_key", existing_type=sa.String(length=64), nullable=False)
    op.drop_constraint("uq_asset_observations_scan_job_id_asset_id", "asset_observations", type_="unique")
    op.create_unique_constraint(
        "uq_asset_observations_job_asset_key",
        "asset_observations",
        ["scan_job_id", "asset_id", "observation_key"],
    )

    identifiers = conn.execute(
        text(
            """
            SELECT id, value, normalized_value
            FROM asset_identifiers
            WHERE identifier_type = 'hostname'
            """
        )
    ).fetchall()
    for row_id, value, normalized in identifiers:
        candidate = normalized or value or ""
        if _is_placeholder_hostname(candidate):
            conn.execute(text("DELETE FROM asset_identifiers WHERE id = :id"), {"id": row_id})


def downgrade() -> None:
    raise NotImplementedError(
        "Refusing to downgrade 0004_asset_observation_integrity: this would restore "
        "over-coarse observation idempotence and discard expected-lifecycle and "
        "identifier hygiene corrections. Restore from a database backup instead."
    )
