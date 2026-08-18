from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from sqlalchemy import event, text

from tests.conftest import requires_postgres
from tests.test_phase1d import _client, _create_staff, _headers, _login, _world
from tests.test_phase2a import _finding_payload, _run_detected

PHASE2A_HEAD = "0009_phase2a_detector_identity_partition"
PHASE2B_HEAD = "0010_cve_intelligence_priority"
PHASE2C_HEAD = "0011_phase2c_treatments_compliance"
CVE = "CVE-2024-1234"


def _nvd_item(cve=CVE, score=9.8, version="3.1"):
    metrics = {}
    if score is not None:
        metrics = {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": version,
                        "baseScore": score,
                        "baseSeverity": "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }
            ]
        }
    return {
        "cve": {
            "id": cve,
            "vulnStatus": "Analyzed",
            "published": "2024-01-01T00:00:00.000Z",
            "lastModified": "2024-02-01T00:00:00.000Z",
            "descriptions": [{"lang": "en", "value": "NVD description"}],
            "metrics": metrics,
            "weaknesses": [{"source": "nvd@nist.gov", "description": [{"lang": "en", "value": "CWE-79"}]}],
            "references": [{"url": "https://example.test/nvd", "source": "nvd@nist.gov", "tags": ["Patch"]}],
        }
    }


def _nvd_body(cve=CVE, score=9.8, version="3.1", cves=None):
    items = [_nvd_item(item, score=score, version=version) for item in (cves or [cve])]
    return json.dumps({"vulnerabilities": items}).encode()


def _epss_csv(rows=None):
    body = "#model_version:v2025.03.14,score_date:2026-08-18\ncve,epss,percentile\n"
    for cve, score, percentile in rows or [(CVE, "0.420000000", "0.972000000")]:
        body += f"{cve},{score},{percentile}\n"
    return body.encode()


def _kev_body(cves=None, extra=None):
    rows = extra or []
    for cve in cves or [CVE]:
        rows.append(
            {
                "cveID": cve,
                "vendorProject": "Example",
                "product": "Widget",
                "dateAdded": "2024-06-01",
                "dueDate": "2024-06-22",
                "requiredAction": "Apply updates",
                "knownRansomwareCampaignUse": "Known",
            }
        )
    return json.dumps(
        {
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": "2026.08.18",
            "dateReleased": "2026-08-18T12:00:00.000Z",
            "count": len(rows),
            "vulnerabilities": rows,
        }
    ).encode()


class ScriptedFetch:
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def __call__(self, url, **kwargs):
        from app.intel.http import HttpResponse, IntelligenceHttpError

        self.calls.append(url)
        for prefix, payload in self.mapping.items():
            if prefix in url:
                if isinstance(payload, Exception):
                    raise payload
                status, body = payload
                if status >= 400:
                    raise IntelligenceHttpError(f"HTTP {status}", status_code=status, permanent=status < 500 and status != 429)
                return HttpResponse(status, body, {})
        raise IntelligenceHttpError(f"unexpected URL {url}", permanent=True)


@requires_postgres
def test_fresh_db_reaches_0010(reset_db):
    from app.database import engine
    from app.migrate import apply_schema, current_revision, head_revision
    from sqlalchemy import inspect

    revision = apply_schema()
    assert revision == head_revision() == current_revision() == PHASE2C_HEAD
    tables = set(inspect(engine).get_table_names())
    assert {
        "vulnerability_intelligence",
        "vulnerability_cwes",
        "vulnerability_references",
        "vulnerability_intelligence_sync",
    }.issubset(tables)


@requires_postgres
def test_0009_to_0010_preserves_phase2a_identity(reset_db):
    from alembic import command

    from app.database import SessionLocal, engine
    from app.migrate import alembic_config, current_revision
    from app.models import AssetFinding, Finding, Vulnerability, VulnerabilityDetectorMapping

    command.upgrade(alembic_config(), PHASE2A_HEAD)
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        tenant_id = conn.execute(text("INSERT INTO tenants (name, notes) VALUES ('Keep 2B', '') RETURNING id")).scalar_one()
        site_id = conn.execute(
            text("INSERT INTO sites (tenant_id, name, created_at) VALUES (:t, 'HQ', :n) RETURNING id"),
            {"t": tenant_id, "n": now},
        ).scalar_one()
        asset_id = conn.execute(
            text(
                """
                INSERT INTO assets (tenant_id, site_id, display_name, classification, description, lifecycle_state, disposition, criticality, is_expected, created_at, updated_at)
                VALUES (:t, :s, 'srv', 'Server', '', 'active', 'unreviewed', 'normal', false, :n, :n)
                RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id, "n": now},
        ).scalar_one()
        vuln_id = conn.execute(
            text("INSERT INTO vulnerabilities (canonical_key, cve_id, title, description) VALUES ('cve:CVE-2024-1234', 'CVE-2024-1234', 'Old', 'kept') RETURNING id")
        ).scalar_one()
        mapping_id = conn.execute(
            text(
                "INSERT INTO vulnerability_detector_mappings (vulnerability_id, detector_type, detector_key, last_severity) VALUES (:v, 'nuclei', 'tpl', 'high') RETURNING id"
            ),
            {"v": vuln_id},
        ).scalar_one()
        af_id = conn.execute(
            text(
                """
                INSERT INTO asset_findings (tenant_id, asset_id, vulnerability_id, technical_state, treatment_state, first_seen, last_seen, consecutive_clean_scans, reopened_count)
                VALUES (:t, :a, :v, 'open', 'unaddressed', :n, :n, 1, 0)
                RETURNING id
                """
            ),
            {"t": tenant_id, "a": asset_id, "v": vuln_id, "n": now},
        ).scalar_one()
        finding_id = conn.execute(
            text(
                """
                INSERT INTO findings (tenant_id, asset_id, asset_finding_id, detector_type, detector_key, template_id, name, severity, hostname, host, matched_at, tags, found_at, raw_json)
                VALUES (:t, :a, :af, 'nuclei', 'tpl', 'tpl', 'Old', 'high', 'srv', '10.1.0.10', '', '', :n, '{}'::jsonb)
                RETURNING id
                """
            ),
            {"t": tenant_id, "a": asset_id, "af": af_id, "n": now},
        ).scalar_one()
        hist_id = conn.execute(
            text(
                """
                INSERT INTO asset_finding_history (asset_finding_id, tenant_id, transition_type, new_technical_state, occurred_at, details, idempotence_key)
                VALUES (:af, :t, 'opened', 'open', :n, '{}'::jsonb, 'opened-keep')
                RETURNING id
                """
            ),
            {"af": af_id, "t": tenant_id, "n": now},
        ).scalar_one()

    command.upgrade(alembic_config(), PHASE2B_HEAD)
    assert current_revision() == PHASE2B_HEAD
    db = SessionLocal()
    try:
        vuln = db.get(Vulnerability, vuln_id)
        assert vuln is not None
        assert vuln.canonical_key == "cve:CVE-2024-1234"
        assert vuln.cve_id == "CVE-2024-1234"
        mapping = db.get(VulnerabilityDetectorMapping, mapping_id)
        assert mapping.vulnerability_id == vuln_id
        af = db.get(AssetFinding, af_id)
        assert af.vulnerability_id == vuln_id
        assert af.priority is None
        assert db.get(Finding, finding_id).asset_finding_id == af_id
        from app.models import AssetFindingHistory, VulnerabilityIntelligence

        assert db.get(AssetFindingHistory, hist_id) is not None
        assert db.get(VulnerabilityIntelligence, vuln_id) is None
    finally:
        db.close()


@requires_postgres
def test_downgrade_from_0010_is_refused(reset_db):
    from alembic import command
    from alembic.util import CommandError

    from app.migrate import alembic_config

    command.upgrade(alembic_config(), PHASE2B_HEAD)
    try:
        command.downgrade(alembic_config(), PHASE2A_HEAD)
    except (CommandError, RuntimeError) as exc:
        assert "Refusing to downgrade 0010_cve_intelligence_priority" in str(exc)
        return
    raise AssertionError("0010 downgrade must refuse")


def _cve_finding(client, token, world, hostname="asset-a", ip="10.1.0.10", severity="critical"):
    return _run_detected(
        client,
        token,
        world,
        hostname=hostname,
        ip=ip,
        findings=[
            _finding_payload(
                template="cve-template",
                name="Remote code exec",
                severity=severity,
                host=f"https://{ip}",
                extra_raw={"info": {"classification": {"cve-id": [CVE]}, "name": "Remote code exec", "severity": severity}},
            )
        ],
    )


def _set_intel(vuln_id, **values):
    from app.database import SessionLocal
    from app.intel.priority import recalculate_priorities_for_vulnerabilities
    from app.intel.sync import _intel_row
    from app.models import Vulnerability

    db = SessionLocal()
    try:
        vuln = db.get(Vulnerability, vuln_id)
        row = _intel_row(db, vuln)
        for key, value in values.items():
            setattr(row, key, value)
        db.flush()
        recalculate_priorities_for_vulnerabilities(db, [vuln_id])
        db.commit()
    finally:
        db.close()


@requires_postgres
def test_intelligence_and_priority_context(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _cve_finding(client, token, world)
        listed = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(token)).json()
        assert listed[0]["cve_id"] == CVE
        vuln_id = listed[0]["vulnerability_id"]
        af_id = listed[0]["id"]
        asset_id = listed[0]["asset_id"]
        _set_intel(
            vuln_id,
            cvss_version="3.1",
            cvss_base_score=Decimal("9.8"),
            cvss_base_severity="CRITICAL",
            cvss_vector="CVSS:3.1/AV:N",
            cvss_source="nvd@nist.gov",
            epss_score=Decimal("0.42000000000"),
            epss_percentile=Decimal("0.97200000000"),
            kev=False,
        )
        patched = client.patch(
            f"/api/assets/{asset_id}",
            headers=_headers(token),
            json={"criticality": "critical"},
        )
        assert patched.status_code == 200, patched.text
        tagged = client.post(f"/api/assets/{asset_id}/tags", headers=_headers(token), json={"name": "CUI"})
        assert tagged.status_code == 200, tagged.text
        from app.database import SessionLocal
        from app.intel.priority import recalculate_asset_finding_priorities
        from app.models import AssetFinding, ScanJob

        db = SessionLocal()
        try:
            af = db.get(AssetFinding, af_id)
            job = db.get(ScanJob, db.query(ScanJob.id).first()[0])
            snapshot = dict(job.execution_snapshot or {})
            snapshot["scope"] = "wan"
            job.execution_snapshot = snapshot
            db.flush()
            recalculate_asset_finding_priorities(db, [af])
            db.commit()
            db.refresh(af)
            assert af.priority == "p1"
            reasons = " ".join(item.get("factor", "") for item in (af.priority_explanation or {}).get("factors", []))
            assert "cvss" in reasons
        finally:
            db.close()

        _set_intel(vuln_id, kev=True)
        detail = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings/{af_id}", headers=_headers(token)).json()
        assert detail["priority"] == "p1"
        assert detail["kev"] is True
        assert any(
            "CISA KEV" in (item.get("reason") or item.get("note") or "")
            for item in (detail["priority_explanation"] or {}).get("overrides", [])
            + (detail["priority_explanation"] or {}).get("factors", [])
        )

        other = _cve_finding(client, token, world, hostname="asset-b", ip="10.1.0.11", severity="critical")
        listed = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(token)).json()
        b = next(row for row in listed if row["asset_hostname"] == "asset-b" or row["asset_id"] != asset_id)
        client.patch(f"/api/assets/{b['asset_id']}", headers=_headers(token), json={"criticality": "low"})
        from app.database import SessionLocal as SL
        from app.intel.priority import recalculate_priorities_for_assets

        db = SL()
        try:
            recalculate_priorities_for_assets(db, [b["asset_id"]])
            db.commit()
        finally:
            db.close()
        again = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(token)).json()
        a_row = next(row for row in again if row["id"] == af_id)
        b_row = next(row for row in again if row["id"] != af_id)
        assert a_row["vulnerability_id"] == b_row["vulnerability_id"]
        assert a_row["priority"] != b_row["priority"] or a_row["priority_score"] != b_row["priority_score"]


@requires_postgres
def test_non_cve_has_local_priority_without_fake_intel(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _run_detected(client, token, world)
        rows = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(token)).json()
        assert rows[0]["cve_id"] is None
        assert rows[0]["cvss_base_score"] is None
        assert rows[0]["epss_score"] is None
        assert rows[0]["kev"] is None
        assert rows[0]["priority"] in {"p1", "p2", "p3", "p4"}


@requires_postgres
def test_refresh_success_and_failure_semantics(reset_db):
    from app.database import SessionLocal
    from app.intel.http import IntelligenceHttpError
    from app.intel.sync import apply_nvd_record, refresh_epss, refresh_kev, refresh_nvd
    from app.models import Vulnerability, VulnerabilityIntelligence

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _cve_finding(client, token, world)

    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == CVE).one()
        good = ScriptedFetch({"cves/2.0": (200, _nvd_body())})
        result = refresh_nvd(db, fetch=good, sleep=lambda _: None, force=True)
        db.commit()
        assert "error" not in result
        intel = db.get(VulnerabilityIntelligence, vuln.id)
        assert float(intel.cvss_base_score) == 9.8
        previous = intel.cvss_base_score
        failed = ScriptedFetch({"cves/2.0": IntelligenceHttpError("timeout")})
        refresh_nvd(db, fetch=failed, sleep=lambda _: None, force=True)
        db.commit()
        db.refresh(intel)
        assert intel.cvss_base_score == previous

        refresh_epss(db, fetch=ScriptedFetch({"epss_scores-current": (200, _epss_csv())}), sleep=lambda _: None, force=True)
        db.commit()
        db.refresh(intel)
        assert float(intel.epss_percentile) == pytest.approx(0.972)
        refresh_epss(db, fetch=ScriptedFetch({"epss_scores-current": (200, b"truncated")}), sleep=lambda _: None, force=True)
        db.commit()
        db.refresh(intel)
        assert float(intel.epss_percentile) == pytest.approx(0.972)

        refresh_kev(db, fetch=ScriptedFetch({"known_exploited_vulnerabilities.json": (200, _kev_body())}), sleep=lambda _: None, force=True)
        db.commit()
        db.refresh(intel)
        assert intel.kev is True
        refresh_kev(db, fetch=ScriptedFetch({"known_exploited_vulnerabilities.json": (500, b"nope")}), sleep=lambda _: None, force=True)
        db.commit()
        db.refresh(intel)
        assert intel.kev is True
        empty_ok = _kev_body(cves=["CVE-2020-0001"])
        refresh_kev(db, fetch=ScriptedFetch({"known_exploited_vulnerabilities.json": (200, empty_ok)}), sleep=lambda _: None, force=True)
        db.commit()
        db.refresh(intel)
        assert intel.kev is False
        identity = vuln.canonical_key
        assert identity == f"cve:{CVE}"
        apply_nvd_record(db, vuln, __import__("app.intel.nvd", fromlist=["parse_nvd_cve"]).parse_nvd_cve(json.loads(_nvd_body())["vulnerabilities"][0]))
        assert vuln.canonical_key == identity
    finally:
        db.close()


@requires_postgres
def test_list_filters_apply_before_limit_and_query_count_is_bounded(reset_db):
    from app.database import SessionLocal, engine
    from app.models import AssetFinding

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _cve_finding(client, token, world)
        listed = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(token)).json()
        seed = listed[0]
        now = datetime.now(timezone.utc)
        with engine.begin() as conn:
            for index in range(2004):
                # Oldest matching rows must be excluded if a caller limits first, then filters.
                priority = "p1" if index >= 1999 else "p4"
                vuln_id = conn.execute(
                    text(
                        "INSERT INTO vulnerabilities (canonical_key, title, description) VALUES (:k, '', '') RETURNING id"
                    ),
                    {"k": f"nuclei:bulk-{index}"},
                ).scalar_one()
                if index >= 1999:
                    conn.execute(
                        text(
                            """
                            INSERT INTO vulnerability_intelligence (vulnerability_id, kev, created_at, updated_at)
                            VALUES (:v, true, :n, :n)
                            """
                        ),
                        {"v": vuln_id, "n": now},
                    )
                conn.execute(
                    text(
                        """
                        INSERT INTO asset_findings (
                            tenant_id, asset_id, vulnerability_id, technical_state, treatment_state,
                            first_seen, last_seen, consecutive_clean_scans, reopened_count, priority, priority_score
                        )
                        VALUES (:t, :a, :v, 'open', 'unaddressed', :n, :n, 0, 0, :p, 10)
                        """
                    ),
                    {
                        "t": seed["tenant_id"],
                        "a": seed["asset_id"],
                        "v": vuln_id,
                        "p": priority,
                        "n": now - timedelta(minutes=index),
                    },
                )
        from app.intel.sync import _intel_row
        from app.models import Vulnerability

        db = SessionLocal()
        try:
            vuln = db.get(Vulnerability, seed["vulnerability_id"])
            intel = _intel_row(db, vuln)
            intel.kev = True
            db.commit()
        finally:
            db.close()

        queries = []

        def before_cursor(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
            queries.append(statement)

        event.listen(engine.sync_engine if hasattr(engine, "sync_engine") else engine, "before_cursor_execute", before_cursor)
        try:
            p1 = client.get(
                f"/api/tenants/{world['tenant']['id']}/asset-findings?priority=p1",
                headers=_headers(token),
            )
            assert p1.status_code == 200
            assert all(row["priority"] == "p1" for row in p1.json())
            assert len(p1.json()) >= 5
            kev_rows = client.get(
                f"/api/tenants/{world['tenant']['id']}/asset-findings?kev=true",
                headers=_headers(token),
            )
            assert kev_rows.status_code == 200
            assert len(kev_rows.json()) >= 5
            assert len(kev_rows.json()) <= 2000
            assert all(row.get("kev") is True for row in kev_rows.json())
            dash = client.get("/api/dashboard", headers=_headers(token))
            assert dash.status_code == 200
            assert "priorities" in dash.json()
            summary = client.get(f"/api/tenants/{world['tenant']['id']}/summary", headers=_headers(token))
            assert summary.status_code == 200
            assert "priorities" in summary.json()
            assert len(queries) < 80
        finally:
            event.remove(engine.sync_engine if hasattr(engine, "sync_engine") else engine, "before_cursor_execute", before_cursor)


@requires_postgres
def test_viewer_can_read_but_not_refresh(reset_db):
    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        _cve_finding(client, admin, world)
        viewer = _create_staff(client, admin, "viewer2b", "viewer")
        rows = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(viewer))
        assert rows.status_code == 200
        detail = client.get(
            f"/api/tenants/{world['tenant']['id']}/asset-findings/{rows.json()[0]['id']}",
            headers=_headers(viewer),
        )
        assert detail.status_code == 200
        intel = client.get(
            f"/api/vulnerabilities/{rows.json()[0]['vulnerability_id']}?tenant_id={world['tenant']['id']}",
            headers=_headers(viewer),
        )
        assert intel.status_code == 200
        refresh = client.post("/api/admin/vulnerability-intelligence/refresh", headers=_headers(viewer))
        assert refresh.status_code == 403
        settings = client.put("/api/admin/settings", headers=_headers(viewer), json={"central_host": "x"})
        assert settings.status_code == 403
        missing = client.get("/api/tenants/999999/asset-findings", headers=_headers(viewer))
        assert missing.status_code == 404


def _seed_cve_rows(tenant_id, asset_id, cves, *, cvss=1.0, priority="p4", kev=None):
    from app.database import engine

    now = datetime.now(timezone.utc)
    ids = []
    with engine.begin() as conn:
        for cve in cves:
            vuln_id = conn.execute(
                text(
                    "INSERT INTO vulnerabilities (canonical_key, cve_id, title, description) VALUES (:k, :c, :c, '') RETURNING id"
                ),
                {"k": f"cve:{cve}", "c": cve},
            ).scalar_one()
            conn.execute(
                text(
                    """
                    INSERT INTO vulnerability_intelligence (
                        vulnerability_id, cvss_version, cvss_base_score, kev, created_at, updated_at
                    )
                    VALUES (:v, '3.1', :cvss, :kev, :n, :n)
                    """
                ),
                {"v": vuln_id, "cvss": cvss, "kev": kev, "n": now},
            )
            af_id = conn.execute(
                text(
                    """
                    INSERT INTO asset_findings (
                        tenant_id, asset_id, vulnerability_id, technical_state, treatment_state,
                        first_seen, last_seen, consecutive_clean_scans, reopened_count, priority, priority_score
                    )
                    VALUES (:t, :a, :v, 'open', 'unaddressed', :n, :n, 0, 0, :p, 10)
                    RETURNING id
                    """
                ),
                {"t": tenant_id, "a": asset_id, "v": vuln_id, "p": priority, "n": now},
            ).scalar_one()
            ids.append((vuln_id, af_id, cve))
    return ids


@requires_postgres
def test_nvd_second_batch_failure_rolls_back_all_batches(reset_db):
    from urllib.parse import parse_qs, urlparse

    from app.database import SessionLocal
    from app.intel.http import HttpResponse, IntelligenceHttpError
    from app.intel.sync import NVD_BATCH_SIZE, refresh_nvd
    from app.models import AssetFinding, Vulnerability, VulnerabilityIntelligence

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _cve_finding(client, token, world)
        listed = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(token)).json()
        asset_id = listed[0]["asset_id"]

    cves = [f"CVE-2024-{20000 + index}" for index in range(NVD_BATCH_SIZE + NVD_BATCH_SIZE + 1)]
    seeded = _seed_cve_rows(world["tenant"]["id"], asset_id, cves)
    calls = {"n": 0}

    def fail_after_first_batch(url, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            ids = [item for item in parse_qs(urlparse(url).query).get("cveIds", [""])[0].split(",") if item]
            assert len(ids) == NVD_BATCH_SIZE
            return HttpResponse(200, _nvd_body(cves=ids, score=9.8), {})
        raise IntelligenceHttpError("batch 2 failed", permanent=True)

    db = SessionLocal()
    try:
        result = refresh_nvd(db, fetch=fail_after_first_batch, sleep=lambda _: None, force=True)
        assert "error" in result
        db.commit()
    finally:
        db.close()

    assert calls["n"] >= 2
    db = SessionLocal()
    try:
        for vuln_id, af_id, _cve in seeded:
            intel = db.get(VulnerabilityIntelligence, vuln_id)
            af = db.get(AssetFinding, af_id)
            assert float(intel.cvss_base_score) == 1.0
            assert af.priority == "p4"
            assert af.priority_score == 10
        assert db.query(Vulnerability).filter(Vulnerability.cve_id.in_(cves)).count() == len(cves)
        original = db.query(Vulnerability).filter(Vulnerability.cve_id == CVE).one()
        assert db.get(VulnerabilityIntelligence, original.id) is None
    finally:
        db.close()


@requires_postgres
def test_nvd_successful_record_without_cvss_clears_old_score(reset_db):
    from app.database import SessionLocal
    from app.intel.priority import recalculate_priorities_for_vulnerabilities
    from app.intel.sync import refresh_nvd
    from app.models import AssetFinding, Vulnerability, VulnerabilityIntelligence

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _cve_finding(client, token, world, severity="high")
        listed = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(token)).json()
        vuln_id = listed[0]["vulnerability_id"]
        af_id = listed[0]["id"]

    _set_intel(
        vuln_id,
        cvss_version="3.1",
        cvss_base_score=Decimal("9.8"),
        cvss_base_severity="CRITICAL",
        cvss_vector="CVSS:3.1/AV:N",
        cvss_source="nvd@nist.gov",
    )
    db = SessionLocal()
    try:
        recalculate_priorities_for_vulnerabilities(db, [vuln_id])
        db.commit()
        af = db.get(AssetFinding, af_id)
        assert af.priority == "p2"
        assert float(db.get(VulnerabilityIntelligence, vuln_id).cvss_base_score) == 9.8
        result = refresh_nvd(
            db,
            fetch=ScriptedFetch({"cves/2.0": (200, _nvd_body(score=None))}),
            sleep=lambda _: None,
            force=True,
        )
        assert "error" not in result
        db.commit()
    finally:
        db.close()

    db = SessionLocal()
    try:
        intel = db.get(VulnerabilityIntelligence, vuln_id)
        af = db.get(AssetFinding, af_id)
        assert intel.cvss_base_score is None
        assert intel.cvss_version is None
        assert intel.nvd_fetched_at is not None
        assert db.get(Vulnerability, vuln_id).canonical_key == f"cve:{CVE}"
        assert any(item.get("factor") == "detector_severity" for item in (af.priority_explanation or {}).get("factors", []))
        assert not any(item.get("factor") == "cvss" for item in (af.priority_explanation or {}).get("factors", []))
    finally:
        db.close()


@requires_postgres
def test_well_formed_partial_epss_does_not_clear_missing_cves(reset_db):
    from app.database import SessionLocal
    from app.intel.sync import apply_epss_dataset, refresh_epss
    from app.intel.epss import parse_epss_csv
    from app.models import Vulnerability, VulnerabilityIntelligence

    other = "CVE-2024-9999"
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _cve_finding(client, token, world)
        listed = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(token)).json()
        _seed_cve_rows(world["tenant"]["id"], listed[0]["asset_id"], [other], cvss=None)

    db = SessionLocal()
    try:
        tracked = db.query(Vulnerability).filter(Vulnerability.cve_id.in_([CVE, other])).order_by(Vulnerability.id).all()
        apply_epss_dataset(
            db,
            parse_epss_csv(_epss_csv([(CVE, "0.420000000", "0.972000000"), (other, "0.110000000", "0.440000000")])),
            tracked,
        )
        db.commit()
        other_intel = (
            db.query(VulnerabilityIntelligence)
            .join(Vulnerability, Vulnerability.id == VulnerabilityIntelligence.vulnerability_id)
            .filter(Vulnerability.cve_id == other)
            .one()
        )
        assert float(other_intel.epss_percentile) == pytest.approx(0.44)
        result = refresh_epss(
            db,
            fetch=ScriptedFetch({"epss_scores-current": (200, _epss_csv([(CVE, "0.500000000", "0.800000000")]))}),
            sleep=lambda _: None,
            force=True,
        )
        assert "error" not in result
        db.commit()
        db.expire_all()
        intel_cve = (
            db.query(VulnerabilityIntelligence)
            .join(Vulnerability, Vulnerability.id == VulnerabilityIntelligence.vulnerability_id)
            .filter(Vulnerability.cve_id == CVE)
            .one()
        )
        intel_other = (
            db.query(VulnerabilityIntelligence)
            .join(Vulnerability, Vulnerability.id == VulnerabilityIntelligence.vulnerability_id)
            .filter(Vulnerability.cve_id == other)
            .one()
        )
        assert float(intel_cve.epss_percentile) == pytest.approx(0.80)
        assert float(intel_other.epss_percentile) == pytest.approx(0.44)
        assert float(intel_other.epss_score) == pytest.approx(0.11)
    finally:
        db.close()


@requires_postgres
def test_kev_null_excluded_from_false_filter(reset_db):
    from app.database import SessionLocal
    from app.intel.priority import recalculate_priorities_for_vulnerabilities
    from app.intel.sync import _intel_row
    from app.models import AssetFinding, Vulnerability

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _cve_finding(client, token, world)
        listed = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(token)).json()
        unknown_id = listed[0]["id"]
        confirmed_false = _seed_cve_rows(
            world["tenant"]["id"], listed[0]["asset_id"], ["CVE-2024-2222"], kev=False
        )[0]
        confirmed_true = _seed_cve_rows(
            world["tenant"]["id"], listed[0]["asset_id"], ["CVE-2024-3333"], kev=True
        )[0]

        db = SessionLocal()
        try:
            vuln = db.get(Vulnerability, listed[0]["vulnerability_id"])
            row = _intel_row(db, vuln)
            assert row.kev is None
            recalculate_priorities_for_vulnerabilities(
                db, [listed[0]["vulnerability_id"], confirmed_false[0], confirmed_true[0]]
            )
            db.commit()
            unknown = db.get(AssetFinding, unknown_id)
            factor = next(
                item for item in (unknown.priority_explanation or {}).get("factors", []) if item.get("factor") == "cisa_kev"
            )
            assert factor["value"] is None
            assert "unknown" in (factor.get("note") or "").lower()
            assert "not synchronized" in (factor.get("note") or "").lower()
        finally:
            db.close()

        false_rows = client.get(
            f"/api/tenants/{world['tenant']['id']}/asset-findings?kev=false",
            headers=_headers(token),
        )
        assert false_rows.status_code == 200
        ids = {row["id"] for row in false_rows.json()}
        assert confirmed_false[1] in ids
        assert unknown_id not in ids
        assert confirmed_true[1] not in ids
        assert all(row.get("kev") is False for row in false_rows.json())


@requires_postgres
def test_vulnerability_detail_requires_tenant_linkage(reset_db):
    from app.database import SessionLocal, engine
    from app.models import Vulnerability

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        _cve_finding(client, admin, world)
        listed = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(admin)).json()
        linked_id = listed[0]["vulnerability_id"]
        other = client.post("/api/tenants", headers=_headers(admin), json={"name": "Other 2B", "notes": ""}).json()
        with engine.begin() as conn:
            orphan_id = conn.execute(
                text(
                    "INSERT INTO vulnerabilities (canonical_key, title, description) VALUES ('nuclei:orphan-2b', '', '') RETURNING id"
                )
            ).scalar_one()
        viewer = _create_staff(client, admin, "viewer-link", "viewer")
        user = _create_staff(client, admin, "user-link", "user")
        for token in (viewer, user):
            omitted = client.get(f"/api/vulnerabilities/{linked_id}", headers=_headers(token))
            assert omitted.status_code in {400, 403, 404, 422}
            foreign = client.get(
                f"/api/vulnerabilities/{linked_id}?tenant_id={other['id']}",
                headers=_headers(token),
            )
            assert foreign.status_code == 404
            orphan = client.get(
                f"/api/vulnerabilities/{orphan_id}?tenant_id={world['tenant']['id']}",
                headers=_headers(token),
            )
            assert orphan.status_code == 404
            ok = client.get(
                f"/api/vulnerabilities/{linked_id}?tenant_id={world['tenant']['id']}",
                headers=_headers(token),
            )
            assert ok.status_code == 200, ok.text
            assert ok.json()["vulnerability_id"] == linked_id
        db = SessionLocal()
        try:
            assert db.get(Vulnerability, orphan_id) is not None
        finally:
            db.close()


@requires_postgres
def test_failed_refresh_updates_last_attempt_and_keeps_success(reset_db):
    from app.database import SessionLocal
    from app.intel.http import IntelligenceHttpError
    from app.intel.sync import refresh_epss, refresh_kev, refresh_nvd
    from app.models import INTEL_SOURCE_CISA_KEV, INTEL_SOURCE_EPSS, INTEL_SOURCE_NVD, VulnerabilityIntelligenceSync

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _cve_finding(client, token, world)

    db = SessionLocal()
    try:
        refresh_nvd(db, fetch=ScriptedFetch({"cves/2.0": (200, _nvd_body())}), sleep=lambda _: None, force=True)
        refresh_epss(db, fetch=ScriptedFetch({"epss_scores-current": (200, _epss_csv())}), sleep=lambda _: None, force=True)
        refresh_kev(
            db,
            fetch=ScriptedFetch({"known_exploited_vulnerabilities.json": (200, _kev_body())}),
            sleep=lambda _: None,
            force=True,
        )
        db.commit()
        stale = datetime(2024, 1, 1, tzinfo=timezone.utc)
        successes = {}
        for source in (INTEL_SOURCE_NVD, INTEL_SOURCE_EPSS, INTEL_SOURCE_CISA_KEV):
            row = db.get(VulnerabilityIntelligenceSync, source)
            assert row.last_success_at is not None
            successes[source] = row.last_success_at
            row.last_attempt_at = stale
        db.commit()

        refresh_nvd(db, fetch=ScriptedFetch({"cves/2.0": IntelligenceHttpError("nvd down")}), sleep=lambda _: None, force=True)
        db.commit()
        refresh_epss(
            db,
            fetch=ScriptedFetch({"epss_scores-current": IntelligenceHttpError("epss down")}),
            sleep=lambda _: None,
            force=True,
        )
        db.commit()
        refresh_kev(
            db,
            fetch=ScriptedFetch({"known_exploited_vulnerabilities.json": IntelligenceHttpError("kev down")}),
            sleep=lambda _: None,
            force=True,
        )
        db.commit()
        db.expire_all()
        for source in (INTEL_SOURCE_NVD, INTEL_SOURCE_EPSS, INTEL_SOURCE_CISA_KEV):
            row = db.get(VulnerabilityIntelligenceSync, source)
            assert row.last_attempt_at is not None
            assert row.last_attempt_at > stale
            assert row.last_success_at == successes[source]
            assert row.last_error
    finally:
        db.close()
