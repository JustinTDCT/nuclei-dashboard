"""Phase 1B persistent Asset / observation / tag model.

Revision ID: 0003_assets_observations
Revises: 0002_sites_networks
Create Date: 2026-08-18 14:00:00.000000+00:00

Do not import live application models. This revision is immutable once shipped.

Each existing Device is mapped to exactly one Asset. Device.asset_id is
indexed and is intentionally not unique. LAN Site is taken from
Device.last_scan_job_id → ScanJob → Scan → Agent → Site when that chain
is complete. Otherwise the tenant's existing "Imported Site" is reused,
or a deterministic "Unassigned Assets" Site is created. WAN Devices keep
site_id NULL.

A single observation with provenance source=legacy_migration is created
from the current Device row. That is a migration snapshot, not a
fabricated scanner timeline.

Downgrade is refused: reverting this revision would destroy Asset,
identifier, address, service, observation, and tag history.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision: str = "0003_assets_observations"
down_revision: str | None = "0002_sites_networks"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

COMPATIBILITY_SITE_NAME = "Imported Site"
UNASSIGNED_SITE_NAME = "Unassigned Assets"
SOURCE_LEGACY_MIGRATION = "legacy_migration"


def upgrade() -> None:
    op.create_table(
        "tags",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("normalized_name", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="tags_tenant_id_fkey", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "normalized_name", name="uq_tags_tenant_id_normalized_name"),
    )
    op.create_index("ix_tags_tenant_id", "tags", ["tenant_id"], unique=False)

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=True),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("classification", sa.String(length=80), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("lifecycle_state", sa.String(length=20), nullable=False),
        sa.Column("disposition", sa.String(length=20), nullable=False),
        sa.Column("criticality", sa.String(length=20), nullable=False),
        sa.Column("is_expected", sa.Boolean(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("lifecycle_state IN ('active', 'inactive')", name="ck_assets_lifecycle_state"),
        sa.CheckConstraint(
            "disposition IN ('unreviewed', 'approved', 'unauthorized', 'ignored')",
            name="ck_assets_disposition",
        ),
        sa.CheckConstraint(
            "criticality IN ('low', 'normal', 'high', 'critical')",
            name="ck_assets_criticality",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="assets_tenant_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], name="assets_site_id_fkey", ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_assets_tenant_id", "assets", ["tenant_id"], unique=False)
    op.create_index("ix_assets_site_id", "assets", ["site_id"], unique=False)
    op.create_index("ix_assets_tenant_id_last_seen", "assets", ["tenant_id", "last_seen"], unique=False)
    op.create_index("ix_assets_tenant_id_site_id", "assets", ["tenant_id", "site_id"], unique=False)

    op.create_table(
        "asset_identifiers",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("identifier_type", sa.String(length=40), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("normalized_value", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "identifier_type IN ('mac', 'hostname', 'fqdn', 'dns_name', 'tls_name', 'serial', 'device_id', 'other')",
            name="ck_asset_identifiers_type",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name="asset_identifiers_asset_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="asset_identifiers_tenant_id_fkey", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "identifier_type", "normalized_value", name="uq_asset_identifiers_asset_type_value"),
    )
    op.create_index("ix_asset_identifiers_asset_id", "asset_identifiers", ["asset_id"], unique=False)
    op.create_index("ix_asset_identifiers_tenant_id", "asset_identifiers", ["tenant_id"], unique=False)
    op.create_index(
        "ix_asset_identifiers_tenant_type_value",
        "asset_identifiers",
        ["tenant_id", "identifier_type", "normalized_value"],
        unique=False,
    )

    op.create_table(
        "asset_addresses",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=True),
        sa.Column("network_id", sa.Integer(), nullable=True),
        sa.Column("ip", sa.String(length=80), nullable=False),
        sa.Column("address_family", sa.String(length=8), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("address_family IN ('ipv4', 'ipv6')", name="ck_asset_addresses_family"),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name="asset_addresses_asset_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="asset_addresses_tenant_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], name="asset_addresses_site_id_fkey", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["network_id"], ["networks.id"], name="asset_addresses_network_id_fkey", ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "ip", name="uq_asset_addresses_asset_id_ip"),
    )
    op.create_index("ix_asset_addresses_asset_id", "asset_addresses", ["asset_id"], unique=False)
    op.create_index("ix_asset_addresses_tenant_id", "asset_addresses", ["tenant_id"], unique=False)
    op.create_index("ix_asset_addresses_site_id", "asset_addresses", ["site_id"], unique=False)
    op.create_index("ix_asset_addresses_network_id", "asset_addresses", ["network_id"], unique=False)
    op.create_index("ix_asset_addresses_tenant_id_ip", "asset_addresses", ["tenant_id", "ip"], unique=False)

    op.create_table(
        "asset_services",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("address_id", sa.Integer(), nullable=True),
        sa.Column("ip", sa.String(length=80), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("product", sa.String(length=200), nullable=False),
        sa.Column("version", sa.String(length=80), nullable=False),
        sa.Column("tls_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("web_title", sa.String(length=500), nullable=False),
        sa.Column("tech", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name="asset_services_asset_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="asset_services_tenant_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["address_id"], ["asset_addresses.id"], name="asset_services_address_id_fkey", ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "ip", "port", "protocol", name="uq_asset_services_asset_ip_port_proto"),
    )
    op.create_index("ix_asset_services_asset_id", "asset_services", ["asset_id"], unique=False)
    op.create_index("ix_asset_services_tenant_id", "asset_services", ["tenant_id"], unique=False)
    op.create_index("ix_asset_services_address_id", "asset_services", ["address_id"], unique=False)
    op.create_index("ix_asset_services_tenant_ip_port", "asset_services", ["tenant_id", "ip", "port"], unique=False)

    op.create_table(
        "asset_observations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=True),
        sa.Column("network_id", sa.Integer(), nullable=True),
        sa.Column("agent_id", sa.Integer(), nullable=True),
        sa.Column("scan_job_id", sa.Integer(), nullable=True),
        sa.Column("scope", sa.String(length=10), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("ip", sa.String(length=80), nullable=False),
        sa.Column("snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("provenance", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name="asset_observations_asset_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="asset_observations_tenant_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], name="asset_observations_site_id_fkey", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["network_id"], ["networks.id"], name="asset_observations_network_id_fkey", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name="asset_observations_agent_id_fkey", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"], ["scan_jobs.id"], name="asset_observations_scan_job_id_fkey", ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_job_id", "asset_id", name="uq_asset_observations_scan_job_id_asset_id"),
    )
    op.create_index("ix_asset_observations_asset_id", "asset_observations", ["asset_id"], unique=False)
    op.create_index("ix_asset_observations_tenant_id", "asset_observations", ["tenant_id"], unique=False)
    op.create_index("ix_asset_observations_site_id", "asset_observations", ["site_id"], unique=False)
    op.create_index("ix_asset_observations_network_id", "asset_observations", ["network_id"], unique=False)
    op.create_index("ix_asset_observations_agent_id", "asset_observations", ["agent_id"], unique=False)
    op.create_index("ix_asset_observations_scan_job_id", "asset_observations", ["scan_job_id"], unique=False)
    op.create_index(
        "ix_asset_observations_asset_id_observed_at",
        "asset_observations",
        ["asset_id", "observed_at"],
        unique=False,
    )
    op.create_index(
        "ix_asset_observations_tenant_id_observed_at",
        "asset_observations",
        ["tenant_id", "observed_at"],
        unique=False,
    )

    op.create_table(
        "asset_tags",
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("tag_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], name="asset_tags_asset_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tag_id"], ["tags.id"], name="asset_tags_tag_id_fkey", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("asset_id", "tag_id"),
    )
    op.create_index("ix_asset_tags_tag_id", "asset_tags", ["tag_id"], unique=False)

    op.create_table(
        "site_tags",
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("tag_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], name="site_tags_site_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tag_id"], ["tags.id"], name="site_tags_tag_id_fkey", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("site_id", "tag_id"),
    )
    op.create_index("ix_site_tags_tag_id", "site_tags", ["tag_id"], unique=False)

    op.create_table(
        "network_tags",
        sa.Column("network_id", sa.Integer(), nullable=False),
        sa.Column("tag_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["network_id"], ["networks.id"], name="network_tags_network_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["tag_id"], ["tags.id"], name="network_tags_tag_id_fkey", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("network_id", "tag_id"),
    )
    op.create_index("ix_network_tags_tag_id", "network_tags", ["tag_id"], unique=False)

    op.add_column("devices", sa.Column("asset_id", sa.Integer(), nullable=True))
    op.create_index("ix_devices_asset_id", "devices", ["asset_id"], unique=False)
    op.create_foreign_key(
        "devices_asset_id_fkey",
        "devices",
        "assets",
        ["asset_id"],
        ["id"],
        ondelete="SET NULL",
    )

    _backfill_devices()


def _backfill_devices() -> None:
    conn = op.get_bind()
    conn.execute(
        text(
            """
            INSERT INTO sites (tenant_id, name, created_at)
            SELECT DISTINCT d.tenant_id, :unassigned, now()
            FROM devices d
            WHERE d.scope = 'lan'
              AND NOT EXISTS (
                  SELECT 1
                  FROM scan_jobs sj
                  JOIN scans sc ON sc.id = sj.scan_id
                  JOIN agents a ON a.id = sc.agent_id
                  WHERE sj.id = d.last_scan_job_id
                    AND a.site_id IS NOT NULL
              )
              AND NOT EXISTS (
                  SELECT 1 FROM sites s
                  WHERE s.tenant_id = d.tenant_id AND s.name = :imported
              )
              AND NOT EXISTS (
                  SELECT 1 FROM sites s
                  WHERE s.tenant_id = d.tenant_id AND s.name = :unassigned
              )
            """
        ),
        {"imported": COMPATIBILITY_SITE_NAME, "unassigned": UNASSIGNED_SITE_NAME},
    )

    conn.execute(text("ALTER TABLE assets ADD COLUMN legacy_device_id INTEGER"))
    conn.execute(
        text(
            """
            INSERT INTO assets (
                tenant_id, site_id, display_name, classification, description,
                lifecycle_state, disposition, criticality, is_expected,
                first_seen, last_seen, created_at, updated_at, legacy_device_id
            )
            SELECT
                d.tenant_id,
                CASE
                    WHEN d.scope = 'wan' THEN NULL
                    ELSE COALESCE(
                        proven.site_id,
                        imported.id,
                        unassigned.id
                    )
                END,
                COALESCE(NULLIF(btrim(d.hostname), ''), NULLIF(btrim(d.auto_label), ''), d.ip, ''),
                COALESCE(NULLIF(btrim(d.classification), ''), 'Unknown'),
                COALESCE(d.description, ''),
                'active',
                'unreviewed',
                'normal',
                false,
                d.first_seen,
                d.last_seen,
                COALESCE(d.first_seen, now()),
                now(),
                d.id
            FROM devices d
            LEFT JOIN LATERAL (
                SELECT a.site_id
                FROM scan_jobs sj
                JOIN scans sc ON sc.id = sj.scan_id
                JOIN agents a ON a.id = sc.agent_id
                WHERE sj.id = d.last_scan_job_id
                  AND a.site_id IS NOT NULL
                LIMIT 1
            ) proven ON true
            LEFT JOIN sites imported
                ON imported.tenant_id = d.tenant_id AND imported.name = :imported
            LEFT JOIN sites unassigned
                ON unassigned.tenant_id = d.tenant_id AND unassigned.name = :unassigned
            """
        ),
        {"imported": COMPATIBILITY_SITE_NAME, "unassigned": UNASSIGNED_SITE_NAME},
    )

    conn.execute(
        text(
            """
            UPDATE devices d
            SET asset_id = a.id
            FROM assets a
            WHERE a.legacy_device_id = d.id
            """
        )
    )

    conn.execute(
        text(
            """
            INSERT INTO asset_identifiers (
                asset_id, tenant_id, identifier_type, value, normalized_value,
                source, first_seen, last_seen, created_at
            )
            SELECT
                a.id,
                d.tenant_id,
                'hostname',
                btrim(d.hostname),
                lower(rtrim(btrim(d.hostname), '.')),
                :source,
                d.first_seen,
                d.last_seen,
                now()
            FROM devices d
            JOIN assets a ON a.legacy_device_id = d.id
            WHERE d.hostname IS NOT NULL AND btrim(d.hostname) <> ''
            """
        ),
        {"source": SOURCE_LEGACY_MIGRATION},
    )

    conn.execute(
        text(
            """
            INSERT INTO asset_addresses (
                asset_id, tenant_id, site_id, network_id, ip, address_family,
                source, first_seen, last_seen, created_at
            )
            SELECT
                a.id,
                d.tenant_id,
                a.site_id,
                NULL,
                btrim(d.ip),
                CASE WHEN position(':' in btrim(d.ip)) > 0 THEN 'ipv6' ELSE 'ipv4' END,
                :source,
                d.first_seen,
                d.last_seen,
                now()
            FROM devices d
            JOIN assets a ON a.legacy_device_id = d.id
            WHERE d.ip IS NOT NULL AND btrim(d.ip) <> ''
            """
        ),
        {"source": SOURCE_LEGACY_MIGRATION},
    )

    conn.execute(
        text(
            """
            INSERT INTO asset_services (
                asset_id, tenant_id, address_id, ip, port, protocol, product, version,
                tls_metadata, web_title, tech, source, first_seen, last_seen, created_at
            )
            SELECT
                a.id,
                d.tenant_id,
                addr.id,
                COALESCE(NULLIF(btrim(d.ip), ''), ''),
                CASE
                    WHEN jsonb_typeof(elem) = 'number' THEN (elem #>> '{}')::int
                    WHEN jsonb_typeof(elem) = 'object' THEN NULLIF(elem->>'port', '')::int
                    WHEN jsonb_typeof(elem) = 'string' AND (elem #>> '{}') ~ '^[0-9]+$'
                        THEN (elem #>> '{}')::int
                    ELSE NULL
                END,
                COALESCE(NULLIF(elem->>'protocol', ''), 'tcp'),
                COALESCE(elem->>'product', elem->>'service', ''),
                COALESCE(elem->>'version', ''),
                '{}'::jsonb,
                COALESCE(d.title, ''),
                COALESCE(d.tech, ''),
                :source,
                d.first_seen,
                d.last_seen,
                now()
            FROM devices d
            JOIN assets a ON a.legacy_device_id = d.id
            LEFT JOIN asset_addresses addr ON addr.asset_id = a.id AND addr.ip = btrim(d.ip)
            CROSS JOIN LATERAL jsonb_array_elements(
                CASE WHEN jsonb_typeof(d.ports) = 'array' THEN d.ports ELSE '[]'::jsonb END
            ) AS elem
            WHERE CASE
                WHEN jsonb_typeof(elem) = 'number' THEN (elem #>> '{}')::int
                WHEN jsonb_typeof(elem) = 'object' THEN NULLIF(elem->>'port', '')::int
                WHEN jsonb_typeof(elem) = 'string' AND (elem #>> '{}') ~ '^[0-9]+$'
                    THEN (elem #>> '{}')::int
                ELSE NULL
            END IS NOT NULL
            ON CONFLICT (asset_id, ip, port, protocol) DO NOTHING
            """
        ),
        {"source": SOURCE_LEGACY_MIGRATION},
    )

    conn.execute(
        text(
            """
            INSERT INTO asset_observations (
                asset_id, tenant_id, site_id, network_id, agent_id, scan_job_id,
                scope, source, observed_at, hostname, ip, snapshot, provenance, created_at
            )
            SELECT
                a.id,
                d.tenant_id,
                a.site_id,
                NULL,
                CASE WHEN d.scope = 'lan' THEN sc.agent_id ELSE NULL END,
                d.last_scan_job_id,
                COALESCE(NULLIF(d.scope, ''), ''),
                :source,
                COALESCE(d.last_seen, d.first_seen, now()),
                COALESCE(d.hostname, ''),
                COALESCE(d.ip, ''),
                jsonb_build_object(
                    'hostname', COALESCE(d.hostname, ''),
                    'ip', COALESCE(d.ip, ''),
                    'ports', COALESCE(d.ports, '[]'::jsonb),
                    'title', COALESCE(d.title, ''),
                    'tech', COALESCE(d.tech, ''),
                    'auto_label', COALESCE(d.auto_label, ''),
                    'classification', COALESCE(d.classification, ''),
                    'scope', COALESCE(d.scope, ''),
                    'legacy_device_id', d.id
                ),
                :source,
                now()
            FROM devices d
            JOIN assets a ON a.legacy_device_id = d.id
            LEFT JOIN scan_jobs sj ON sj.id = d.last_scan_job_id
            LEFT JOIN scans sc ON sc.id = sj.scan_id
            """
        ),
        {"source": SOURCE_LEGACY_MIGRATION},
    )

    conn.execute(text("ALTER TABLE assets DROP COLUMN legacy_device_id"))


def downgrade() -> None:
    raise NotImplementedError(
        "Refusing to downgrade 0003_assets_observations: this would destroy Asset, "
        "identifier, address, service, observation, and tag history. Restore from a "
        "database backup instead."
    )
