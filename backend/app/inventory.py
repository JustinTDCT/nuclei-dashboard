from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.alerts import create_alert
from app.assets import ingest_device_report, observation_context
from app.classify import clean_tech, identity_name, infer_class, infer_label, is_ip, is_placeholder_name, normalize_hostname
from app.models import Alert, Device, Finding
from app.schemas import DEVICE_CLASSES, DeviceReport, FindingReport


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _suggested_class(report: DeviceReport) -> str:
    suggested = (report.classification or "").strip()
    if suggested in DEVICE_CLASSES and suggested not in ("", "Unknown", "Other"):
        return suggested
    guessed = infer_class(report.hostname, report.ports, report.title, report.tech)
    if guessed not in ("", "Unknown", "Other"):
        return guessed
    return ""


def _apply_class(device: Device, report: DeviceReport) -> None:
    suggested = _suggested_class(report)
    if suggested and device.classification in ("", "Unknown"):
        device.classification = suggested


def _label_for(report: DeviceReport) -> str:
    return (report.auto_label or "").strip() or infer_label(
        report.hostname, report.ports, report.title, report.tech
    )


def _is_placeholder(device: Device) -> bool:
    return is_placeholder_name(device.hostname or "", device.ip or "")


def _find_by_hostname(
    db: Session,
    tenant_id: int,
    scope: str,
    hostname: str,
    *,
    site_id: int | None = None,
    asset_id: int | None = None,
) -> Device | None:
    if not hostname:
        return None
    query = db.query(Device).filter(
        Device.tenant_id == tenant_id,
        Device.hostname == hostname,
        Device.scope == scope,
    )
    if site_id is None:
        query = query.filter(Device.site_id.is_(None))
    else:
        query = query.filter(Device.site_id == site_id)
    if asset_id is not None:
        query = query.filter(Device.asset_id == asset_id)
    return query.order_by(Device.last_seen.desc()).first()


def _find_placeholder_by_ip(
    db: Session,
    tenant_id: int,
    scope: str,
    ip: str,
    *,
    site_id: int | None = None,
    asset_id: int | None = None,
) -> Device | None:
    if not ip:
        return None
    query = db.query(Device).filter(
        Device.tenant_id == tenant_id,
        Device.ip == ip,
        Device.scope == scope,
    )
    if site_id is None:
        query = query.filter(Device.site_id.is_(None))
    else:
        query = query.filter(Device.site_id == site_id)
    if asset_id is not None:
        query = query.filter(Device.asset_id == asset_id)
    rows = query.order_by(Device.last_seen.desc()).all()
    for row in rows:
        if _is_placeholder(row):
            return row
    return None


def _find_device(
    db: Session,
    tenant_id: int,
    scope: str,
    hostname: str,
    ip: str,
    *,
    site_id: int | None = None,
    asset_id: int | None = None,
) -> Device | None:
    if asset_id is not None:
        existing = (
            db.query(Device)
            .filter(
                Device.tenant_id == tenant_id,
                Device.asset_id == asset_id,
                Device.scope == scope,
            )
            .order_by(Device.last_seen.desc())
            .all()
        )
        if site_id is None:
            scoped = [row for row in existing if row.site_id is None]
        else:
            scoped = [row for row in existing if row.site_id == site_id]
        if scoped:
            return scoped[0]
        if existing:
            return existing[0]
    if hostname and not is_placeholder_name(hostname, ip):
        found = _find_by_hostname(db, tenant_id, scope, hostname, site_id=site_id, asset_id=asset_id)
        if found and (asset_id is None or found.asset_id in {None, asset_id}):
            return found
        return _find_placeholder_by_ip(db, tenant_id, scope, ip, site_id=site_id, asset_id=asset_id)
    if ip:
        query = db.query(Device).filter(Device.tenant_id == tenant_id, Device.ip == ip, Device.scope == scope)
        if site_id is None:
            query = query.filter(Device.site_id.is_(None))
        else:
            query = query.filter(Device.site_id == site_id)
        if asset_id is not None:
            query = query.filter(Device.asset_id == asset_id)
        return query.order_by(Device.last_seen.desc()).first()
    return None


def _merge_into(db: Session, keeper: Device, donor: Device) -> Device:
    """Merge compatibility rows only when they already share Asset identity."""
    if donor.id == keeper.id:
        return keeper
    if keeper.asset_id and donor.asset_id and keeper.asset_id != donor.asset_id:
        return keeper
    if donor.ip and (not keeper.ip or (donor.last_seen or donor.first_seen) >= (keeper.last_seen or keeper.first_seen)):
        keeper.ip = donor.ip
    if donor.ports:
        keeper.ports = sorted({*(keeper.ports or []), *(donor.ports or [])})
    if donor.title and not keeper.title:
        keeper.title = donor.title
    if donor.tech and not keeper.tech:
        keeper.tech = donor.tech
    if donor.auto_label and not keeper.auto_label:
        keeper.auto_label = donor.auto_label
    if donor.description and not keeper.description:
        keeper.description = donor.description
    if keeper.classification in ("", "Unknown") and donor.classification not in ("", "Unknown", "Other"):
        keeper.classification = donor.classification
    if donor.first_seen and (not keeper.first_seen or donor.first_seen < keeper.first_seen):
        keeper.first_seen = donor.first_seen
    if keeper.asset_id is None and donor.asset_id is not None:
        keeper.asset_id = donor.asset_id
    if keeper.site_id is None and donor.site_id is not None:
        keeper.site_id = donor.site_id
    db.query(Finding).filter(Finding.device_id == donor.id).update({Finding.device_id: keeper.id}, synchronize_session=False)
    db.query(Alert).filter(Alert.device_id == donor.id).update({Alert.device_id: keeper.id}, synchronize_session=False)
    db.delete(donor)
    db.flush()
    return keeper


def _promote_hostname(
    db: Session,
    device: Device,
    hostname: str,
    tenant_id: int,
    scope: str,
    *,
    site_id: int | None = None,
) -> Device:
    if not hostname or device.hostname == hostname:
        return device
    if not _is_placeholder(device) and not is_ip(device.hostname or ""):
        return device
    other = _find_by_hostname(db, tenant_id, scope, hostname, site_id=site_id, asset_id=device.asset_id)
    if other and other.id != device.id:
        if other.asset_id and device.asset_id and other.asset_id != device.asset_id:
            return device
        return _merge_into(db, other, device)
    device.hostname = hostname
    return device


def _project_device(
    db: Session,
    *,
    tenant_id: int,
    job_id: int,
    report: DeviceReport,
    asset,
    retry: bool,
) -> tuple[Device, bool]:
    hostname = identity_name(report.hostname, report.ip)
    ip = (report.ip or "").strip()
    context = observation_context(db, job_id, ip, report.scope)
    scope = context.get("scope") or report.scope
    site_id = asset.site_id if scope == "lan" else None
    if scope == "lan" and context.get("site_id"):
        site_id = context.get("site_id")
    device = _find_device(
        db,
        tenant_id,
        scope,
        hostname,
        ip,
        site_id=site_id,
        asset_id=asset.id,
    )
    created = False
    if device is None:
        device = Device(
            tenant_id=tenant_id,
            site_id=site_id,
            ip=ip,
            hostname=hostname,
            scope=scope,
            status="new",
            classification=asset.classification or "Unknown",
            description=asset.description or "",
            title=report.title,
            tech=clean_tech(report.tech),
            auto_label=_label_for(report),
            ports=report.ports,
            first_seen=_now(),
            last_seen=_now(),
            last_scan_job_id=job_id,
            asset_id=asset.id,
        )
        _apply_class(device, report)
        db.add(device)
        db.flush()
        created = True
    elif not retry:
        previous_job = device.last_scan_job_id
        if not is_placeholder_name(hostname, ip):
            device = _promote_hostname(db, device, hostname, tenant_id, scope, site_id=site_id)
        if ip:
            device.ip = ip
        device.site_id = site_id
        device.asset_id = asset.id
        device.last_seen = _now()
        device.last_scan_job_id = job_id
        if report.ports:
            device.ports = report.ports
        if report.title:
            device.title = report.title
        if report.tech:
            device.tech = clean_tech(report.tech)
        label = _label_for(report)
        if label:
            device.auto_label = label
        _apply_class(device, report)
        if device.status == "stale":
            device.status = "known"
        elif device.status == "new" and previous_job and previous_job != job_id:
            device.status = "known"
    else:
        device.asset_id = asset.id
        if site_id and device.site_id is None:
            device.site_id = site_id
    db.flush()
    return device, created


def upsert_devices(db: Session, tenant_id: int, job_id: int, reports: list[DeviceReport]) -> tuple[int, list[Device]]:
    created: list[Device] = []
    for report in reports:
        asset, retry = ingest_device_report(db, tenant_id, report, job_id)
        device, created_device = _project_device(
            db,
            tenant_id=tenant_id,
            job_id=job_id,
            report=report,
            asset=asset,
            retry=retry,
        )
        if created_device:
            created.append(device)
            hostname = identity_name(report.hostname, report.ip)
            create_alert(
                db,
                alert_type="new_device",
                title=f"New {report.scope.upper()} device: {hostname}",
                body=(
                    f"A new device was discovered on tenant #{tenant_id}.\n"
                    f"Hostname: {hostname}\nIP: {(report.ip or '').strip()}\n"
                    f"Scope: {report.scope}\nClass: {device.classification}\n"
                    f"Label: {device.auto_label or '-'}\nPorts: {report.ports}"
                ),
                tenant_id=tenant_id,
                device_id=device.id,
            )
            db.flush()
    return len(created), created


def host_to_ip(host: str) -> str | None:
    value = host.strip()
    if not value:
        return None
    if "://" in value:
        value = urlparse(value).hostname or value
    value = value.split("/")[0].split(":")[0]
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def store_findings(
    db: Session,
    tenant_id: int,
    job_id: int,
    scope: str,
    reports: list[FindingReport],
) -> int:
    from app.finding_lifecycle import ingest_findings

    return ingest_findings(db, tenant_id, job_id, scope, reports)


def refresh_discovery_metadata(db: Session) -> int:
    updated = 0
    for device in db.query(Device).all():
        changed = False
        if device.classification in ("", "Unknown"):
            guessed = infer_class(device.hostname or "", device.ports, device.title or "", device.tech or "")
            if guessed not in ("", "Unknown", "Other"):
                device.classification = guessed
                changed = True
        label = infer_label(device.hostname or "", device.ports, device.title or "", device.tech or "")
        if label != (device.auto_label or ""):
            device.auto_label = label
            changed = True
        cleaned = clean_tech(device.tech or "")
        if cleaned != (device.tech or ""):
            device.tech = cleaned
            changed = True
        if changed:
            updated += 1
    if updated:
        db.commit()
    return updated
