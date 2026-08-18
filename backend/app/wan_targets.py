"""Authorized WAN target normalization and lookup.

Workers must never receive arbitrary WAN scope. Only same-tenant, active
AuthorizedWanTarget records may be referenced by a Scan Definition.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import (
    WAN_TARGET_CIDR,
    WAN_TARGET_FQDN,
    WAN_TARGET_IP,
    WAN_TARGET_TYPES,
    AuthorizedWanTarget,
)

_FQDN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SCHEME_PREFIX = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


class WanTargetInvalidError(ValueError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def normalize_wan_target(target_type: str, value: str) -> tuple[str, str]:
    if target_type not in WAN_TARGET_TYPES:
        raise WanTargetInvalidError("WAN target type must be ip, cidr, or fqdn")
    raw = (value or "").strip()
    if not raw:
        raise WanTargetInvalidError("WAN target value is required")
    if target_type == WAN_TARGET_IP:
        return WAN_TARGET_IP, _normalize_ip(raw)
    if target_type == WAN_TARGET_CIDR:
        return WAN_TARGET_CIDR, _normalize_cidr(raw)
    return WAN_TARGET_FQDN, _normalize_fqdn(raw)


def _normalize_ip(value: str) -> str:
    if "/" in value:
        raise WanTargetInvalidError("IP targets cannot include a prefix length")
    if _looks_like_url_or_port(value):
        raise WanTargetInvalidError("IP targets cannot include a URL scheme or port")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise WanTargetInvalidError("Invalid IP address") from exc


def _normalize_cidr(value: str) -> str:
    if _looks_like_url_or_port(value.split("/")[0]):
        raise WanTargetInvalidError("CIDR targets cannot include a URL scheme or port")
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise WanTargetInvalidError("Invalid CIDR") from exc


def _normalize_fqdn(value: str) -> str:
    if _SCHEME_PREFIX.match(value) or "://" in value:
        raise WanTargetInvalidError("FQDN targets cannot include a URL scheme")
    parsed = urlparse(value if "://" in value else f"//{value}", scheme="")
    if parsed.path not in {"", "/"} or parsed.query or parsed.params or parsed.fragment:
        raise WanTargetInvalidError("FQDN targets cannot include a path or query")
    host = (parsed.hostname or value).strip().lower().rstrip(".")
    if parsed.port is not None or ":" in host:
        raise WanTargetInvalidError("FQDN targets cannot include a port")
    if "*" in host or "?" in host:
        raise WanTargetInvalidError("Wildcard FQDN syntax is not allowed")
    if not host or host == "localhost":
        raise WanTargetInvalidError("Invalid FQDN")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise WanTargetInvalidError("FQDN targets cannot be an IP address")
    labels = host.split(".")
    if len(labels) < 2 or any(not _FQDN_LABEL.match(label) for label in labels):
        raise WanTargetInvalidError("Invalid FQDN")
    return host


def _looks_like_url_or_port(value: str) -> bool:
    if _SCHEME_PREFIX.match(value) or "://" in value:
        return True
    if "]" in value:
        return False
    return value.count(":") == 1 and value.rsplit(":", 1)[-1].isdigit()


def require_active_wan_target(
    db: Session, target_id: int, *, tenant_id: int
) -> AuthorizedWanTarget:
    target = db.query(AuthorizedWanTarget).filter(AuthorizedWanTarget.id == target_id).first()
    if not target or target.tenant_id != tenant_id:
        raise HTTPException(status_code=400, detail="Authorized WAN target not found for this tenant")
    if target.archived_at is not None:
        raise HTTPException(status_code=400, detail="Authorized WAN target is archived")
    return target


def active_wan_targets_for_tenant(db: Session, tenant_id: int) -> list[AuthorizedWanTarget]:
    return (
        db.query(AuthorizedWanTarget)
        .filter(AuthorizedWanTarget.tenant_id == tenant_id, AuthorizedWanTarget.archived_at.is_(None))
        .order_by(AuthorizedWanTarget.name, AuthorizedWanTarget.id)
        .all()
    )


def find_active_wan_target_by_normalized(
    db: Session, tenant_id: int, normalized_value: str
) -> AuthorizedWanTarget | None:
    return (
        db.query(AuthorizedWanTarget)
        .filter(
            AuthorizedWanTarget.tenant_id == tenant_id,
            AuthorizedWanTarget.normalized_value == normalized_value,
            AuthorizedWanTarget.archived_at.is_(None),
        )
        .first()
    )
