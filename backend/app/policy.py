"""Deterministic Phase 3A policy engine.

Evaluation is pure with respect to domain state. Apply/reconcile services
consume resolver results and perform the only mutations.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session, selectinload

from app.assets import normalize_tag_name, sync_linked_devices
from app.audit import record_audit
from app.classify import infer_class, normalize_hostname
from app.locality import get_network, get_site, get_tenant
from app.models import (
    ALERT_EMAIL_MODES,
    ALERT_SEVERITIES,
    CRITICALITIES,
    DISPOSITIONS,
    DOMAIN_EVENT_TYPES,
    IDENTIFIER_HOSTNAME,
    IDENTIFIER_VALIDITY_ACTIVE,
    LIFECYCLE_ACTIVE,
    MAX_SUPPRESS_FOR_MINUTES,
    POLICY_CATEGORIES,
    POLICY_CATEGORY_ALERTING,
    POLICY_CATEGORY_ASSET_HANDLING,
    POLICY_CATEGORY_ASSET_INACTIVITY,
    POLICY_CATEGORY_FINDING_LIFECYCLE,
    POLICY_SCOPE_GLOBAL,
    POLICY_SCOPE_NETWORK,
    POLICY_SCOPE_SITE,
    POLICY_SCOPE_TENANT,
    POLICY_SCOPES,
    PRIORITIES,
    TREATMENT_STATES,
    TREATMENT_STATUSES,
    Asset,
    AssetFinding,
    AssetIdentifier,
    AssetObservation,
    AssetService,
    Finding,
    PolicyRule,
    Tag,
    User,
    Vulnerability,
    tag_assets,
)
from app.schemas import DEVICE_CLASSES
from app.settings_store import get_settings

SCOPE_RANK = {
    POLICY_SCOPE_NETWORK: 4,
    POLICY_SCOPE_SITE: 3,
    POLICY_SCOPE_TENANT: 2,
    POLICY_SCOPE_GLOBAL: 1,
}

CONDITION_FIELDS_ASSET = frozenset({"hostname", "tag", "criticality", "is_expected", "observed_port"})
CONDITION_FIELDS_FINDING = frozenset({"severity", "priority", "has_cve"})
CONDITION_FIELDS_ALERTING = frozenset(
    {
        "event_type",
        "classification",
        "disposition",
        "criticality",
        "tag",
        "is_expected",
        "severity",
        "priority",
        "has_cve",
        "treatment_state",
        "source",
    }
)
CONDITION_FIELDS = CONDITION_FIELDS_ASSET | CONDITION_FIELDS_FINDING | CONDITION_FIELDS_ALERTING

OPERATORS = {
    "hostname": frozenset({"equals", "glob"}),
    "tag": frozenset({"has", "lacks"}),
    "criticality": frozenset({"equals"}),
    "is_expected": frozenset({"equals"}),
    "observed_port": frozenset({"equals"}),
    "severity": frozenset({"equals"}),
    "priority": frozenset({"equals"}),
    "has_cve": frozenset({"equals"}),
    "event_type": frozenset({"equals"}),
    "classification": frozenset({"equals"}),
    "disposition": frozenset({"equals"}),
    "treatment_state": frozenset({"equals"}),
    "source": frozenset({"equals"}),
}

ACTIONS_BY_CATEGORY = {
    POLICY_CATEGORY_ASSET_HANDLING: frozenset({"classification", "disposition"}),
    POLICY_CATEGORY_ASSET_INACTIVITY: frozenset({"inactive_after_days"}),
    POLICY_CATEGORY_FINDING_LIFECYCLE: frozenset({"resolution_clean_scans"}),
    POLICY_CATEGORY_ALERTING: frozenset({"severity", "dashboard", "email", "webhook", "suppress_for_minutes"}),
}

FINDING_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})
MAX_INACTIVE_AFTER_DAYS = 3650
MAX_RESOLUTION_CLEAN_SCANS = 30
RECONCILE_BATCH_SIZE = 250

FORBIDDEN_CONDITION_KEYS = frozenset(
    {"expr", "expression", "sql", "script", "code", "eval", "python", "javascript", "or", "any", "not"}
)


def system_default_alert_actions(event_type: str) -> dict[str, Any]:
    from app.models import (
        ALERT_EMAIL_ADMINS,
        ALERT_EMAIL_STAFF,
        ALERT_SEVERITY_CRITICAL,
        ALERT_SEVERITY_HIGH,
        EVENT_AGENT_IDENTITY_MISMATCH,
        EVENT_NEW_ASSET,
    )

    if event_type == EVENT_NEW_ASSET:
        return {
            "severity": ALERT_SEVERITY_HIGH,
            "dashboard": True,
            "email": ALERT_EMAIL_STAFF,
            "webhook": {"enabled": False},
            "suppress_for_minutes": 0,
        }
    if event_type == EVENT_AGENT_IDENTITY_MISMATCH:
        return {
            "severity": ALERT_SEVERITY_CRITICAL,
            "dashboard": True,
            "email": ALERT_EMAIL_ADMINS,
            "webhook": {"enabled": False},
            "suppress_for_minutes": 0,
        }
    return {}


class PolicyError(Exception):
    def __init__(self, detail: str, status_code: int = 400):
        self.detail = detail
        self.status_code = status_code
        super().__init__(detail)


@dataclass
class PolicyEvaluationContext:
    tenant_id: int | None = None
    site_id: int | None = None
    network_id: int | None = None
    asset_id: int | None = None
    asset_finding_id: int | None = None
    hostname: str = ""
    tags: frozenset[str] = field(default_factory=frozenset)
    tag_names: tuple[str, ...] = ()
    criticality: str = "normal"
    is_expected: bool = False
    observed_ports: frozenset[int] = field(default_factory=frozenset)
    severity: str | None = None
    priority: str | None = None
    has_cve: bool | None = None
    current_classification: str = "Unknown"
    current_disposition: str = "unreviewed"
    inference_classification: str | None = None
    event_type: str | None = None
    source: str | None = None
    treatment_state: str | None = None
    domain_event_id: int | None = None


@dataclass
class ConditionExplanation:
    field: str
    op: str
    value: Any
    matched: bool
    detail: str


@dataclass
class ActionExplanation:
    action: str
    value: Any
    source: str
    rule_id: int | None = None
    rule_name: str | None = None
    revision: int | None = None
    scope_type: str | None = None
    tenant_id: int | None = None
    site_id: int | None = None
    network_id: int | None = None
    priority: int | None = None
    matched_conditions: list[ConditionExplanation] = field(default_factory=list)
    overrode: dict[str, Any] | None = None


@dataclass
class ConsideredRule:
    rule_id: int
    name: str
    scope_type: str
    priority: int
    revision: int
    applicable: bool
    matched: bool
    enabled: bool
    archived: bool
    reason: str
    conditions: list[ConditionExplanation] = field(default_factory=list)


@dataclass
class PolicyEvaluationResult:
    category: str
    tenant_id: int | None
    site_id: int | None
    network_id: int | None
    asset_id: int | None
    asset_finding_id: int | None
    effective: dict[str, Any]
    actions: dict[str, ActionExplanation]
    matched_rules: list[dict[str, Any]]
    considered: list[ConsideredRule]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    raise PolicyError("Boolean condition value must be true or false")


def _as_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{field} must be an integer")
    return value


def _normalize_condition(raw: Any, *, category: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PolicyError("Each condition must be an object with field, op, and value")
    extra = set(raw) - {"field", "op", "value"}
    if extra & FORBIDDEN_CONDITION_KEYS:
        raise PolicyError("Arbitrary executable expressions are not allowed")
    if extra:
        raise PolicyError(f"Unsupported condition keys: {', '.join(sorted(extra))}")
    field_name = raw.get("field")
    op = raw.get("op")
    allowed_fields = CONDITION_FIELDS_ASSET
    if category == POLICY_CATEGORY_FINDING_LIFECYCLE:
        allowed_fields = CONDITION_FIELDS_ASSET | CONDITION_FIELDS_FINDING
    elif category == POLICY_CATEGORY_ALERTING:
        allowed_fields = CONDITION_FIELDS_ALERTING
    if field_name not in allowed_fields:
        raise PolicyError(f"Unsupported condition field: {field_name}")
    if category != POLICY_CATEGORY_FINDING_LIFECYCLE and field_name in CONDITION_FIELDS_FINDING and category != POLICY_CATEGORY_ALERTING:
        raise PolicyError(f"Field {field_name} is only valid on finding lifecycle policies")
    allowed_ops = OPERATORS[field_name]
    if op not in allowed_ops:
        raise PolicyError(f"Unsupported operator {op} for field {field_name}")
    value = raw.get("value")
    if field_name == "hostname":
        if not isinstance(value, str) or not value.strip():
            raise PolicyError("hostname value is required")
        value = value.strip()
    elif field_name == "tag":
        if not isinstance(value, str) or not value.strip():
            raise PolicyError("tag value is required")
        value = " ".join(value.strip().split())
    elif field_name == "criticality":
        if value not in CRITICALITIES:
            raise PolicyError("Invalid criticality")
    elif field_name == "is_expected":
        value = _as_bool(value)
    elif field_name == "observed_port":
        value = _as_int(value, field="observed_port")
        if value < 1 or value > 65535:
            raise PolicyError("observed_port must be between 1 and 65535")
    elif field_name == "severity":
        if not isinstance(value, str) or value.strip().lower() not in FINDING_SEVERITIES:
            raise PolicyError("Invalid finding severity")
        value = value.strip().lower()
    elif field_name == "priority":
        normalized = str(value).strip().lower()
        if normalized not in PRIORITIES:
            raise PolicyError("Invalid operational priority")
        value = normalized
    elif field_name == "has_cve":
        value = _as_bool(value)
    elif field_name == "event_type":
        if not isinstance(value, str) or value not in DOMAIN_EVENT_TYPES:
            raise PolicyError("Unsupported event type")
    elif field_name == "classification":
        if value not in DEVICE_CLASSES:
            raise PolicyError("Invalid classification")
    elif field_name == "disposition":
        if value not in DISPOSITIONS:
            raise PolicyError("Invalid disposition")
    elif field_name == "treatment_state":
        if value not in (TREATMENT_STATES | TREATMENT_STATUSES):
            raise PolicyError("Invalid treatment_state")
    elif field_name == "source":
        if not isinstance(value, str) or not value.strip() or len(value) > 40:
            raise PolicyError("Invalid source")
        value = value.strip()
    return {"field": field_name, "op": op, "value": value}


def validate_conditions(raw: Any, *, category: str) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise PolicyError("conditions must be a list; nested Boolean trees are not supported")
    cleaned = [_normalize_condition(item, category=category) for item in raw]
    if category == POLICY_CATEGORY_ALERTING and not any(item["field"] == "event_type" for item in cleaned):
        raise PolicyError("Alerting policy requires an explicit event_type condition")
    return cleaned


def validate_actions(raw: Any, *, category: str) -> dict[str, Any]:
    if not isinstance(raw, dict) or not raw:
        raise PolicyError("actions must be a non-empty object")
    allowed = ACTIONS_BY_CATEGORY[category]
    extra = set(raw) - allowed
    if extra:
        raise PolicyError(f"Unsupported action keys: {', '.join(sorted(extra))}")
    cleaned: dict[str, Any] = {}
    if "classification" in raw:
        classification = raw["classification"]
        if classification not in DEVICE_CLASSES:
            raise PolicyError("Invalid classification")
        cleaned["classification"] = classification
    if "disposition" in raw:
        disposition = raw["disposition"]
        if disposition not in DISPOSITIONS:
            raise PolicyError("Invalid disposition")
        cleaned["disposition"] = disposition
    if "inactive_after_days" in raw:
        days = _as_int(raw["inactive_after_days"], field="inactive_after_days")
        if days < 1 or days > MAX_INACTIVE_AFTER_DAYS:
            raise PolicyError(f"inactive_after_days must be between 1 and {MAX_INACTIVE_AFTER_DAYS}")
        cleaned["inactive_after_days"] = days
    if "resolution_clean_scans" in raw:
        scans = _as_int(raw["resolution_clean_scans"], field="resolution_clean_scans")
        if scans < 1 or scans > MAX_RESOLUTION_CLEAN_SCANS:
            raise PolicyError(f"resolution_clean_scans must be between 1 and {MAX_RESOLUTION_CLEAN_SCANS}")
        cleaned["resolution_clean_scans"] = scans
    if "severity" in raw:
        severity = raw["severity"]
        if severity not in ALERT_SEVERITIES:
            raise PolicyError("Invalid alert severity")
        cleaned["severity"] = severity
    if "dashboard" in raw:
        cleaned["dashboard"] = _as_bool(raw["dashboard"])
    if "email" in raw:
        email = raw["email"]
        if email not in ALERT_EMAIL_MODES:
            raise PolicyError("email must be off, staff, or admins")
        cleaned["email"] = email
    if "webhook" in raw:
        cleaned["webhook"] = validate_webhook_action(raw["webhook"])
    if "suppress_for_minutes" in raw:
        minutes = _as_int(raw["suppress_for_minutes"], field="suppress_for_minutes")
        if minutes < 0 or minutes > MAX_SUPPRESS_FOR_MINUTES:
            raise PolicyError(f"suppress_for_minutes must be between 0 and {MAX_SUPPRESS_FOR_MINUTES}")
        cleaned["suppress_for_minutes"] = minutes
    if not cleaned:
        raise PolicyError("At least one valid action is required")
    return cleaned


def validate_webhook_action(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PolicyError("webhook must be an object with enabled and optional url")
    extra = set(raw) - {"enabled", "url"}
    if extra:
        raise PolicyError(f"Unsupported webhook keys: {', '.join(sorted(extra))}")
    enabled = _as_bool(raw.get("enabled", False))
    if not enabled:
        return {"enabled": False}
    url = raw.get("url")
    if not isinstance(url, str) or not url.strip():
        raise PolicyError("Enabled webhook requires a URL")
    return {"enabled": True, "url": validate_webhook_url(url.strip())}


def validate_webhook_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise PolicyError("Webhook URL must use http or https")
    if not parsed.netloc:
        raise PolicyError("Webhook URL is malformed")
    if parsed.username or parsed.password:
        raise PolicyError("Webhook URL must not contain credentials")
    if " " in url:
        raise PolicyError("Webhook URL is malformed")
    return url


def validate_scope_shape(
    *,
    scope_type: str,
    tenant_id: int | None,
    site_id: int | None,
    network_id: int | None,
) -> None:
    if scope_type not in POLICY_SCOPES:
        raise PolicyError("Invalid scope_type")
    if scope_type == POLICY_SCOPE_GLOBAL:
        if tenant_id is not None or site_id is not None or network_id is not None:
            raise PolicyError("Global policy cannot reference tenant, site, or network")
        return
    if scope_type == POLICY_SCOPE_TENANT:
        if tenant_id is None or site_id is not None or network_id is not None:
            raise PolicyError("Tenant policy requires tenant_id and no site or network")
        return
    if scope_type == POLICY_SCOPE_SITE:
        if tenant_id is None or site_id is None or network_id is not None:
            raise PolicyError("Site policy requires tenant_id and site_id")
        return
    if tenant_id is None or site_id is None or network_id is None:
        raise PolicyError("Network policy requires tenant_id, site_id, and network_id")


def validate_scope_objects(
    db: Session,
    *,
    scope_type: str,
    tenant_id: int | None,
    site_id: int | None,
    network_id: int | None,
) -> None:
    validate_scope_shape(scope_type=scope_type, tenant_id=tenant_id, site_id=site_id, network_id=network_id)
    if scope_type == POLICY_SCOPE_GLOBAL:
        return
    get_tenant(db, tenant_id)
    if scope_type == POLICY_SCOPE_TENANT:
        return
    site = get_site(db, site_id, tenant_id=tenant_id)
    if site.tenant_id != tenant_id:
        raise PolicyError("Site does not belong to this tenant")
    if scope_type == POLICY_SCOPE_SITE:
        return
    network = get_network(db, network_id, tenant_id=tenant_id)
    if network.site_id != site_id or network.tenant_id != tenant_id:
        raise PolicyError("Network does not belong to the specified site and tenant")


def _validate_tag_exists(db: Session, tenant_id: int | None, conditions: list[dict[str, Any]]) -> None:
    if tenant_id is None:
        return
    needed = {normalize_tag_name(item["value"]) for item in conditions if item["field"] == "tag"}
    if not needed:
        return
    rows = (
        db.query(Tag.normalized_name)
        .filter(Tag.tenant_id == tenant_id, Tag.normalized_name.in_(needed))
        .all()
    )
    found = {row[0] for row in rows}
    missing = needed - found
    if missing:
        raise PolicyError(f"Unknown tag for this tenant: {', '.join(sorted(missing))}")


def normalize_rule_payload(
    db: Session,
    *,
    name: str,
    description: str,
    category: str,
    scope_type: str,
    tenant_id: int | None,
    site_id: int | None,
    network_id: int | None,
    priority: int,
    conditions: Any,
    actions: Any,
) -> dict[str, Any]:
    cleaned_name = " ".join((name or "").split())
    if not cleaned_name:
        raise PolicyError("Name is required")
    if category not in POLICY_CATEGORIES:
        raise PolicyError("Invalid category")
    if not isinstance(priority, int) or isinstance(priority, bool):
        raise PolicyError("priority must be an integer")
    validate_scope_objects(
        db,
        scope_type=scope_type,
        tenant_id=tenant_id,
        site_id=site_id,
        network_id=network_id,
    )
    cleaned_conditions = validate_conditions(conditions, category=category)
    cleaned_actions = validate_actions(actions, category=category)
    _validate_tag_exists(db, tenant_id, cleaned_conditions)
    return {
        "name": cleaned_name,
        "description": description or "",
        "category": category,
        "scope_type": scope_type,
        "tenant_id": tenant_id,
        "site_id": site_id,
        "network_id": network_id,
        "priority": priority,
        "conditions": cleaned_conditions,
        "actions": cleaned_actions,
    }


def _scope_applies(rule: PolicyRule, context: PolicyEvaluationContext) -> tuple[bool, str]:
    if rule.scope_type == POLICY_SCOPE_GLOBAL:
        return True, "global"
    if rule.scope_type == POLICY_SCOPE_TENANT:
        if context.tenant_id is None:
            return False, "no tenant context"
        if context.tenant_id != rule.tenant_id:
            return False, "tenant does not match"
        return True, "tenant"
    if rule.scope_type == POLICY_SCOPE_SITE:
        if context.site_id is None:
            return False, "no site context"
        if context.site_id != rule.site_id or context.tenant_id != rule.tenant_id:
            return False, "site does not match"
        return True, "site"
    if context.network_id is None:
        return False, "no network context"
    if (
        context.network_id != rule.network_id
        or context.site_id != rule.site_id
        or context.tenant_id != rule.tenant_id
    ):
        return False, "network does not match"
    return True, "network"


def _match_condition(condition: dict[str, Any], context: PolicyEvaluationContext) -> ConditionExplanation:
    field_name = condition["field"]
    op = condition["op"]
    value = condition["value"]
    matched = False
    detail = ""
    if field_name == "hostname":
        hostname = normalize_hostname(context.hostname)
        expected = value.lower()
        if not hostname:
            detail = "no hostname"
        elif op == "equals":
            matched = hostname == normalize_hostname(expected)
            detail = f"hostname {'equals' if matched else 'does not equal'} {value}"
        else:
            matched = fnmatch.fnmatch(hostname, expected)
            detail = f"hostname {'matched' if matched else 'did not match'} {value}"
    elif field_name == "tag":
        needle = normalize_tag_name(value)
        has = needle in context.tags
        matched = has if op == "has" else not has
        detail = f"tag {'has' if has else 'lacks'} {value}"
    elif field_name == "criticality":
        matched = context.criticality == value
        detail = f"criticality is {context.criticality}"
    elif field_name == "is_expected":
        matched = bool(context.is_expected) is bool(value)
        detail = f"is_expected is {context.is_expected}"
    elif field_name == "observed_port":
        matched = int(value) in context.observed_ports
        detail = f"observed ports {sorted(context.observed_ports)}"
    elif field_name == "severity":
        current = (context.severity or "").lower()
        matched = current == value
        detail = f"severity is {context.severity or 'unknown'}"
    elif field_name == "priority":
        current = (context.priority or "").lower()
        matched = current == value
        detail = f"priority is {context.priority or 'none'}"
    elif field_name == "has_cve":
        matched = bool(context.has_cve) is bool(value)
        detail = f"has_cve is {bool(context.has_cve)}"
    elif field_name == "event_type":
        matched = context.event_type == value
        detail = f"event_type is {context.event_type or 'none'}"
    elif field_name == "classification":
        matched = context.current_classification == value
        detail = f"classification is {context.current_classification}"
    elif field_name == "disposition":
        matched = context.current_disposition == value
        detail = f"disposition is {context.current_disposition}"
    elif field_name == "treatment_state":
        matched = context.treatment_state == value
        detail = f"treatment_state is {context.treatment_state or 'none'}"
    elif field_name == "source":
        matched = context.source == value
        detail = f"source is {context.source or 'none'}"
    return ConditionExplanation(field=field_name, op=op, value=value, matched=matched, detail=detail)


def _rule_sort_key(rule: PolicyRule) -> tuple[int, int, int]:
    return (SCOPE_RANK[rule.scope_type], rule.priority, -rule.id)


def _rule_summary(rule: PolicyRule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "category": rule.category,
        "scope_type": rule.scope_type,
        "tenant_id": rule.tenant_id,
        "site_id": rule.site_id,
        "network_id": rule.network_id,
        "priority": rule.priority,
        "revision": rule.revision,
        "enabled": rule.enabled,
        "archived": rule.archived_at is not None,
    }


def _overrode_payload(previous: ActionExplanation | None) -> dict[str, Any] | None:
    if previous is None or previous.source != "policy":
        return None
    return {
        "rule_id": previous.rule_id,
        "rule_name": previous.rule_name,
        "scope_type": previous.scope_type,
        "priority": previous.priority,
        "revision": previous.revision,
        "value": previous.value,
    }


def _fallback_action(action: str, value: Any, source: str) -> ActionExplanation:
    return ActionExplanation(action=action, value=value, source=source)


class PolicyResolver:
    """Request/run-scoped resolver. Do not reuse across requests."""

    def __init__(self, db: Session):
        self.db = db
        self._rules: dict[str, list[PolicyRule]] = {}
        self._settings: dict[str, Any] | None = None

    def settings(self) -> dict[str, Any]:
        if self._settings is None:
            self._settings = get_settings(self.db)
        return self._settings

    def fallback_inactive_days(self) -> int:
        from app.lifecycle import DEFAULT_ASSET_INACTIVE_DAYS

        raw = self.settings().get("asset_inactive_days", DEFAULT_ASSET_INACTIVE_DAYS)
        try:
            return max(1, int(raw))
        except (TypeError, ValueError):
            return DEFAULT_ASSET_INACTIVE_DAYS

    def fallback_resolution_clean_scans(self) -> int:
        from app.models import DEFAULT_FINDING_RESOLUTION_CLEAN_SCANS

        raw = self.settings().get("finding_resolution_clean_scans", DEFAULT_FINDING_RESOLUTION_CLEAN_SCANS)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = DEFAULT_FINDING_RESOLUTION_CLEAN_SCANS
        return max(1, value)

    def load_rules(self, category: str) -> list[PolicyRule]:
        if category not in self._rules:
            rows = (
                self.db.query(PolicyRule)
                .options(
                    selectinload(PolicyRule.tenant),
                    selectinload(PolicyRule.site),
                    selectinload(PolicyRule.network),
                )
                .filter(PolicyRule.category == category)
                .order_by(PolicyRule.id.asc())
                .all()
            )
            self._rules[category] = rows
        return self._rules[category]

    def evaluate(self, context: PolicyEvaluationContext, category: str) -> PolicyEvaluationResult:
        rules = self.load_rules(category)
        considered: list[ConsideredRule] = []
        winners: dict[str, ActionExplanation] = {}
        matched_rules: list[dict[str, Any]] = []
        for rule in rules:
            archived = rule.archived_at is not None
            if archived:
                considered.append(
                    ConsideredRule(
                        rule_id=rule.id,
                        name=rule.name,
                        scope_type=rule.scope_type,
                        priority=rule.priority,
                        revision=rule.revision,
                        applicable=False,
                        matched=False,
                        enabled=rule.enabled,
                        archived=True,
                        reason="archived",
                    )
                )
                continue
            if not rule.enabled:
                considered.append(
                    ConsideredRule(
                        rule_id=rule.id,
                        name=rule.name,
                        scope_type=rule.scope_type,
                        priority=rule.priority,
                        revision=rule.revision,
                        applicable=False,
                        matched=False,
                        enabled=False,
                        archived=False,
                        reason="disabled",
                    )
                )
                continue
            applicable, scope_reason = _scope_applies(rule, context)
            explanations = [_match_condition(item, context) for item in (rule.conditions or [])]
            matched = applicable and all(item.matched for item in explanations)
            if not applicable:
                reason = scope_reason
            elif matched:
                reason = "matched"
            else:
                failed = next((item for item in explanations if not item.matched), None)
                reason = failed.detail if failed else "conditions not matched"
            considered.append(
                ConsideredRule(
                    rule_id=rule.id,
                    name=rule.name,
                    scope_type=rule.scope_type,
                    priority=rule.priority,
                    revision=rule.revision,
                    applicable=applicable,
                    matched=matched,
                    enabled=True,
                    archived=False,
                    reason=reason,
                    conditions=explanations,
                )
            )
            if not matched:
                continue
            matched_rules.append(_rule_summary(rule))
            for action, value in (rule.actions or {}).items():
                current = winners.get(action)
                candidate = ActionExplanation(
                    action=action,
                    value=value,
                    source="policy",
                    rule_id=rule.id,
                    rule_name=rule.name,
                    revision=rule.revision,
                    scope_type=rule.scope_type,
                    tenant_id=rule.tenant_id,
                    site_id=rule.site_id,
                    network_id=rule.network_id,
                    priority=rule.priority,
                    matched_conditions=explanations,
                    overrode=_overrode_payload(current),
                )
                if current is None:
                    winners[action] = candidate
                    continue
                current_key = (
                    SCOPE_RANK.get(current.scope_type or POLICY_SCOPE_GLOBAL, 0),
                    current.priority or 0,
                    -(current.rule_id or 0),
                )
                next_key = _rule_sort_key(rule)
                if next_key > current_key:
                    candidate.overrode = _overrode_payload(current)
                    winners[action] = candidate
        effective: dict[str, Any] = {}
        actions: dict[str, ActionExplanation] = {}
        if category == POLICY_CATEGORY_ASSET_HANDLING:
            classification = winners.get("classification")
            if classification is None:
                fallback_value = context.inference_classification or context.current_classification or "Unknown"
                classification = _fallback_action(
                    "classification",
                    fallback_value,
                    "classification_inference" if context.inference_classification else "existing_classification",
                )
            disposition = winners.get("disposition")
            if disposition is None:
                disposition = _fallback_action(
                    "disposition",
                    context.current_disposition or "unreviewed",
                    "existing_disposition",
                )
            actions["classification"] = classification
            actions["disposition"] = disposition
            effective["classification"] = classification.value
            effective["disposition"] = disposition.value
        elif category == POLICY_CATEGORY_ASSET_INACTIVITY:
            inactivity = winners.get("inactive_after_days")
            if inactivity is None:
                inactivity = _fallback_action(
                    "inactive_after_days",
                    self.fallback_inactive_days(),
                    "global_setting",
                )
            actions["inactive_after_days"] = inactivity
            effective["inactive_after_days"] = inactivity.value
        elif category == POLICY_CATEGORY_FINDING_LIFECYCLE:
            threshold = winners.get("resolution_clean_scans")
            if threshold is None:
                threshold = _fallback_action(
                    "resolution_clean_scans",
                    self.fallback_resolution_clean_scans(),
                    "global_setting",
                )
            actions["resolution_clean_scans"] = threshold
            effective["resolution_clean_scans"] = threshold.value
        elif category == POLICY_CATEGORY_ALERTING:
            defaults = system_default_alert_actions(context.event_type or "")
            for name in ("severity", "dashboard", "email", "webhook", "suppress_for_minutes"):
                winner = winners.get(name)
                if winner is not None:
                    actions[name] = winner
                    effective[name] = winner.value
                elif name in defaults:
                    fallback = _fallback_action(name, defaults[name], "system_default")
                    actions[name] = fallback
                    effective[name] = fallback.value
        else:
            raise PolicyError(f"Unsupported category: {category}")
        return PolicyEvaluationResult(
            category=category,
            tenant_id=context.tenant_id,
            site_id=context.site_id,
            network_id=context.network_id,
            asset_id=context.asset_id,
            asset_finding_id=context.asset_finding_id,
            effective=effective,
            actions=actions,
            matched_rules=matched_rules,
            considered=considered,
        )


def _ports_from_snapshot(snapshot: dict | None) -> frozenset[int]:
    ports: set[int] = set()
    for item in (snapshot or {}).get("ports") or []:
        if isinstance(item, dict):
            raw = item.get("port")
        else:
            raw = item
        try:
            ports.add(int(raw))
        except (TypeError, ValueError):
            continue
    return frozenset(ports)


def _latest_observation_map(db: Session, asset_ids: list[int]) -> dict[int, AssetObservation]:
    if not asset_ids:
        return {}
    rows = (
        db.query(AssetObservation)
        .distinct(AssetObservation.asset_id)
        .filter(AssetObservation.asset_id.in_(asset_ids))
        .order_by(
            AssetObservation.asset_id.asc(),
            AssetObservation.observed_at.desc(),
            AssetObservation.id.desc(),
        )
        .all()
    )
    return {row.asset_id: row for row in rows}


def _tag_map(db: Session, asset_ids: list[int]) -> dict[int, list[Tag]]:
    if not asset_ids:
        return {}
    rows = (
        db.query(tag_assets.c.asset_id, Tag)
        .join(Tag, Tag.id == tag_assets.c.tag_id)
        .filter(tag_assets.c.asset_id.in_(asset_ids))
        .all()
    )
    grouped: dict[int, list[Tag]] = {asset_id: [] for asset_id in asset_ids}
    for asset_id, tag in rows:
        grouped.setdefault(asset_id, []).append(tag)
    return grouped


def _hostname_map(db: Session, assets: list[Asset], observations: dict[int, AssetObservation]) -> dict[int, str]:
    asset_ids = [asset.id for asset in assets]
    rows = (
        db.query(AssetIdentifier)
        .filter(
            AssetIdentifier.asset_id.in_(asset_ids),
            AssetIdentifier.identifier_type == IDENTIFIER_HOSTNAME,
            AssetIdentifier.validity == IDENTIFIER_VALIDITY_ACTIVE,
        )
        .order_by(
            AssetIdentifier.asset_id.asc(),
            AssetIdentifier.last_seen.desc().nullslast(),
            AssetIdentifier.id.desc(),
        )
        .all()
        if asset_ids
        else []
    )
    hostnames: dict[int, str] = {}
    for row in rows:
        if row.asset_id not in hostnames:
            hostnames[row.asset_id] = row.value
    for asset in assets:
        observation = observations.get(asset.id)
        if observation and observation.hostname:
            hostnames[asset.id] = observation.hostname
        elif asset.id not in hostnames:
            hostnames[asset.id] = asset.display_name or ""
    return hostnames


def _port_map(db: Session, asset_ids: list[int], observations: dict[int, AssetObservation]) -> dict[int, frozenset[int]]:
    ports: dict[int, set[int]] = {asset_id: set() for asset_id in asset_ids}
    if asset_ids:
        rows = db.query(AssetService.asset_id, AssetService.port).filter(AssetService.asset_id.in_(asset_ids)).all()
        for asset_id, port in rows:
            ports.setdefault(asset_id, set()).add(int(port))
    for asset_id, observation in observations.items():
        snap_ports = _ports_from_snapshot(observation.snapshot)
        if snap_ports:
            ports[asset_id] = set(snap_ports)
    return {asset_id: frozenset(values) for asset_id, values in ports.items()}


def contexts_for_assets(
    db: Session,
    assets: list[Asset],
    *,
    observation_overrides: dict[int, dict[str, Any]] | None = None,
) -> dict[int, PolicyEvaluationContext]:
    overrides = observation_overrides or {}
    asset_ids = [asset.id for asset in assets]
    observations = _latest_observation_map(db, asset_ids)
    tags = _tag_map(db, asset_ids)
    hostnames = _hostname_map(db, assets, observations)
    ports = _port_map(db, asset_ids, observations)
    contexts: dict[int, PolicyEvaluationContext] = {}
    for asset in assets:
        override = overrides.get(asset.id, {})
        observation = observations.get(asset.id)
        observation_matches_site = (
            observation is not None and observation.site_id == asset.site_id
        )
        if "site_id" in override:
            site_id = override["site_id"]
        elif observation_matches_site:
            site_id = observation.site_id
        else:
            site_id = asset.site_id
        if "network_id" in override:
            network_id = override["network_id"]
        elif observation_matches_site:
            network_id = observation.network_id
        else:
            network_id = None
        hostname = override.get("hostname", hostnames.get(asset.id, ""))
        observed_ports = override.get("observed_ports", ports.get(asset.id, frozenset()))
        tag_rows = tags.get(asset.id, [])
        inference = None
        if override.get("inference_classification"):
            inference = override["inference_classification"]
        elif hostname or observed_ports:
            inference = infer_class(hostname, list(observed_ports))
        contexts[asset.id] = PolicyEvaluationContext(
            tenant_id=asset.tenant_id,
            site_id=site_id,
            network_id=network_id,
            asset_id=asset.id,
            hostname=hostname or "",
            tags=frozenset(tag.normalized_name for tag in tag_rows),
            tag_names=tuple(tag.name for tag in tag_rows),
            criticality=asset.criticality,
            is_expected=bool(asset.is_expected),
            observed_ports=frozenset(int(port) for port in observed_ports),
            current_classification=asset.classification or "Unknown",
            current_disposition=asset.disposition or "unreviewed",
            inference_classification=inference,
        )
    return contexts


def context_for_findings(
    db: Session,
    findings: list[AssetFinding],
    *,
    assets: list[Asset] | None = None,
) -> dict[int, PolicyEvaluationContext]:
    if not findings:
        return {}
    asset_ids = list({row.asset_id for row in findings})
    if assets is None:
        assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
    asset_contexts = contexts_for_assets(db, assets)
    finding_ids = [row.id for row in findings]
    evidence_rows = (
        db.query(Finding)
        .distinct(Finding.asset_finding_id)
        .filter(Finding.asset_finding_id.in_(finding_ids))
        .order_by(Finding.asset_finding_id.asc(), Finding.found_at.desc(), Finding.id.desc())
        .all()
    )
    latest_severity: dict[int, str] = {}
    for row in evidence_rows:
        if row.severity:
            latest_severity[row.asset_finding_id] = row.severity.lower()
    vuln_ids = list({row.vulnerability_id for row in findings})
    vulns = {
        row.id: row
        for row in db.query(Vulnerability).filter(Vulnerability.id.in_(vuln_ids)).all()
    } if vuln_ids else {}
    contexts: dict[int, PolicyEvaluationContext] = {}
    for finding in findings:
        base = asset_contexts.get(finding.asset_id)
        if base is None:
            continue
        vuln = vulns.get(finding.vulnerability_id)
        contexts[finding.id] = PolicyEvaluationContext(
            tenant_id=finding.tenant_id,
            site_id=base.site_id,
            network_id=base.network_id,
            asset_id=finding.asset_id,
            asset_finding_id=finding.id,
            hostname=base.hostname,
            tags=base.tags,
            tag_names=base.tag_names,
            criticality=base.criticality,
            is_expected=base.is_expected,
            observed_ports=base.observed_ports,
            severity=latest_severity.get(finding.id),
            priority=finding.priority,
            has_cve=bool(vuln.cve_id) if vuln is not None else False,
            current_classification=base.current_classification,
            current_disposition=base.current_disposition,
            inference_classification=base.inference_classification,
        )
    return contexts


def serialize_evaluation(result: PolicyEvaluationResult) -> dict[str, Any]:
    actions = {}
    for key, item in result.actions.items():
        actions[key] = {
            "value": item.value,
            "source": item.source,
            "rule_id": item.rule_id,
            "rule_name": item.rule_name,
            "revision": item.revision,
            "scope_type": item.scope_type,
            "tenant_id": item.tenant_id,
            "site_id": item.site_id,
            "network_id": item.network_id,
            "priority": item.priority,
            "matched_conditions": [
                {
                    "field": cond.field,
                    "op": cond.op,
                    "value": cond.value,
                    "matched": cond.matched,
                    "detail": cond.detail,
                }
                for cond in item.matched_conditions
            ],
            "overrode": item.overrode,
        }
    return {
        "category": result.category,
        "tenant_id": result.tenant_id,
        "site_id": result.site_id,
        "network_id": result.network_id,
        "asset_id": result.asset_id,
        "asset_finding_id": result.asset_finding_id,
        "effective": result.effective,
        "actions": actions,
        "matched_rules": result.matched_rules,
        "considered": [
            {
                "rule_id": row.rule_id,
                "name": row.name,
                "scope_type": row.scope_type,
                "priority": row.priority,
                "revision": row.revision,
                "applicable": row.applicable,
                "matched": row.matched,
                "enabled": row.enabled,
                "archived": row.archived,
                "reason": row.reason,
                "conditions": [
                    {
                        "field": cond.field,
                        "op": cond.op,
                        "value": cond.value,
                        "matched": cond.matched,
                        "detail": cond.detail,
                    }
                    for cond in row.conditions
                ],
            }
            for row in result.considered
        ],
    }


def _audit_policy_asset_change(
    db: Session,
    *,
    asset: Asset,
    action: str,
    old: str,
    new: str,
    explanation: ActionExplanation,
    context: PolicyEvaluationContext,
) -> None:
    record_audit(
        db,
        actor=None,
        action=action,
        object_type="asset",
        object_id=asset.id,
        tenant_id=asset.tenant_id,
        site_id=context.site_id or asset.site_id,
        details={
            "asset_id": asset.id,
            "tenant_id": asset.tenant_id,
            "site_id": context.site_id,
            "network_id": context.network_id,
            "old": old,
            "new": new,
            "policy_rule_id": explanation.rule_id,
            "policy_revision": explanation.revision,
            "policy_name": explanation.rule_name,
            "policy_scope": explanation.scope_type,
            "policy_priority": explanation.priority,
            "matched_conditions": [
                {"field": cond.field, "op": cond.op, "value": cond.value, "detail": cond.detail}
                for cond in explanation.matched_conditions
                if cond.matched
            ],
        },
    )


def apply_asset_handling(
    db: Session,
    asset: Asset,
    *,
    resolver: PolicyResolver | None = None,
    context: PolicyEvaluationContext | None = None,
    observation_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if asset.merged_into_asset_id is not None:
        return {}
    engine = resolver or PolicyResolver(db)
    if context is None:
        contexts = contexts_for_assets(
            db,
            [asset],
            observation_overrides={asset.id: observation_override} if observation_override else None,
        )
        context = contexts[asset.id]
    result = engine.evaluate(context, POLICY_CATEGORY_ASSET_HANDLING)
    changed: dict[str, Any] = {}
    classification = result.actions["classification"]
    if classification.source == "policy" and classification.value != asset.classification:
        previous = asset.classification
        asset.classification = classification.value
        sync_linked_devices(asset, classification=classification.value)
        _audit_policy_asset_change(
            db,
            asset=asset,
            action="asset.policy_classification_changed",
            old=previous,
            new=classification.value,
            explanation=classification,
            context=context,
        )
        changed["classification"] = {"before": previous, "after": classification.value}
    disposition = result.actions["disposition"]
    if disposition.source == "policy" and disposition.value != asset.disposition:
        previous = asset.disposition
        asset.disposition = disposition.value
        _audit_policy_asset_change(
            db,
            asset=asset,
            action="asset.policy_disposition_changed",
            old=previous,
            new=disposition.value,
            explanation=disposition,
            context=context,
        )
        changed["disposition"] = {"before": previous, "after": disposition.value}
        from app.events import emit_asset_disposition_changed

        emit_asset_disposition_changed(
            db,
            asset,
            previous=previous,
            new=disposition.value,
            source="policy",
            policy_rule_id=disposition.rule_id,
            policy_revision=disposition.revision,
            network_id=context.network_id,
        )
    if changed:
        asset.updated_at = utcnow()
    return changed


def apply_asset_handling_for_observation(
    db: Session,
    asset: Asset,
    observation_context: dict[str, Any],
    *,
    report: Any | None = None,
) -> dict[str, Any]:
    hostname = getattr(report, "hostname", None) if report is not None else observation_context.get("hostname")
    raw_ports = getattr(report, "ports", None) if report is not None else observation_context.get("ports")
    ports: list[int] = []
    for item in raw_ports or []:
        if isinstance(item, dict):
            raw = item.get("port")
        else:
            raw = item
        try:
            ports.append(int(raw))
        except (TypeError, ValueError):
            continue
    inference = None
    if report is not None:
        inference = getattr(report, "classification", None) or infer_class(hostname or "", ports)
    elif observation_context.get("classification"):
        inference = observation_context.get("classification")
    elif hostname or ports:
        inference = infer_class(hostname or "", ports)
    override = {
        "site_id": observation_context.get("site_id"),
        "network_id": observation_context.get("network_id"),
    }
    if hostname:
        override["hostname"] = hostname
    if ports:
        override["observed_ports"] = frozenset(ports)
    if inference:
        override["inference_classification"] = inference
    return apply_asset_handling(db, asset, observation_override=override)


def reconcile_asset_handling(db: Session, *, batch_size: int = RECONCILE_BATCH_SIZE, after_id: int = 0) -> int:
    resolver = PolicyResolver(db)
    changed = 0
    last_id = after_id
    while True:
        assets = (
            db.query(Asset)
            .filter(Asset.merged_into_asset_id.is_(None), Asset.id > last_id)
            .order_by(Asset.id.asc())
            .limit(batch_size)
            .all()
        )
        if not assets:
            break
        contexts = contexts_for_assets(db, assets)
        for asset in assets:
            result = apply_asset_handling(db, asset, resolver=resolver, context=contexts[asset.id])
            if result:
                changed += 1
        last_id = assets[-1].id
        db.flush()
    return changed


def reconcile_asset_handling_job() -> int:
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        changed = reconcile_asset_handling(db)
        db.commit()
        return changed
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def resolution_details(explanation: ActionExplanation) -> dict[str, Any]:
    details = {
        "reason": "consecutive_clean_scans",
        "threshold": explanation.value,
        "threshold_source": explanation.source,
    }
    if explanation.source == "policy":
        details.update(
            {
                "policy_rule_id": explanation.rule_id,
                "policy_revision": explanation.revision,
                "policy_scope": explanation.scope_type,
                "policy_priority": explanation.priority,
                "policy_name": explanation.rule_name,
            }
        )
    return details


def create_policy(db: Session, *, actor: User, payload: dict[str, Any]) -> PolicyRule:
    if payload["scope_type"] == POLICY_SCOPE_GLOBAL and actor.role != "admin":
        raise PolicyError("Only an Admin may create a Global policy", status_code=403)
    cleaned = normalize_rule_payload(db, **payload)
    now = utcnow()
    row = PolicyRule(
        **cleaned,
        enabled=True,
        revision=1,
        created_by_user_id=actor.id,
        updated_by_user_id=actor.id,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.flush()
    _audit_policy_change(db, actor=actor, action="policy.created", row=row, before=None)
    from app.events import emit_policy_changed

    emit_policy_changed(db, row)
    return row


def update_policy(db: Session, *, actor: User, row: PolicyRule, changes: dict[str, Any]) -> PolicyRule:
    _require_write(actor, row.scope_type)
    if row.archived_at is not None:
        raise PolicyError("Archived policies cannot be updated")
    payload = {
        "name": changes.get("name", row.name),
        "description": changes.get("description", row.description),
        "category": changes.get("category", row.category),
        "scope_type": changes.get("scope_type", row.scope_type),
        "tenant_id": changes.get("tenant_id", row.tenant_id),
        "site_id": changes.get("site_id", row.site_id),
        "network_id": changes.get("network_id", row.network_id),
        "priority": changes.get("priority", row.priority),
        "conditions": changes.get("conditions", row.conditions),
        "actions": changes.get("actions", row.actions),
    }
    _require_write(actor, payload["scope_type"])
    cleaned = normalize_rule_payload(db, **payload)
    _require_write(actor, cleaned["scope_type"])
    before = _policy_snapshot(row)
    for key, value in cleaned.items():
        setattr(row, key, value)
    if "enabled" in changes and changes["enabled"] is not None:
        row.enabled = bool(changes["enabled"])
    row.revision = int(row.revision or 1) + 1
    row.updated_by_user_id = actor.id
    row.updated_at = utcnow()
    db.flush()
    _audit_policy_change(db, actor=actor, action="policy.changed", row=row, before=before)
    from app.events import emit_policy_changed

    emit_policy_changed(db, row)
    return row


def set_policy_enabled(db: Session, *, actor: User, row: PolicyRule, enabled: bool) -> PolicyRule:
    _require_write(actor, row.scope_type)
    if row.archived_at is not None:
        raise PolicyError("Archived policies cannot be enabled or disabled")
    if row.enabled is enabled:
        return row
    before = _policy_snapshot(row)
    row.enabled = enabled
    row.revision = int(row.revision or 1) + 1
    row.updated_by_user_id = actor.id
    row.updated_at = utcnow()
    db.flush()
    _audit_policy_change(
        db,
        actor=actor,
        action="policy.enabled" if enabled else "policy.disabled",
        row=row,
        before=before,
    )
    from app.events import emit_policy_changed

    emit_policy_changed(db, row)
    return row


def archive_policy(db: Session, *, actor: User, row: PolicyRule, reason: str = "") -> PolicyRule:
    _require_write(actor, row.scope_type)
    if row.archived_at is not None:
        return row
    before = _policy_snapshot(row)
    row.archived_at = utcnow()
    row.archived_by_user_id = actor.id
    row.archive_reason = reason or None
    row.enabled = False
    row.revision = int(row.revision or 1) + 1
    row.updated_by_user_id = actor.id
    row.updated_at = row.archived_at
    db.flush()
    _audit_policy_change(db, actor=actor, action="policy.archived", row=row, before=before, reason=reason)
    from app.events import emit_policy_changed

    emit_policy_changed(db, row)
    return row


def _require_write(actor: User, scope_type: str) -> None:
    if actor.role == "viewer":
        raise PolicyError("Viewer cannot change policies", status_code=403)
    if scope_type == POLICY_SCOPE_GLOBAL and actor.role != "admin":
        raise PolicyError("Only an Admin may change a Global policy", status_code=403)


def _policy_snapshot(row: PolicyRule) -> dict[str, Any]:
    return {
        "name": row.name,
        "description": row.description,
        "category": row.category,
        "scope_type": row.scope_type,
        "tenant_id": row.tenant_id,
        "site_id": row.site_id,
        "network_id": row.network_id,
        "priority": row.priority,
        "enabled": row.enabled,
        "conditions": row.conditions,
        "actions": row.actions,
        "revision": row.revision,
        "archived_at": row.archived_at.isoformat() if row.archived_at else None,
    }


def _audit_policy_change(
    db: Session,
    *,
    actor: User,
    action: str,
    row: PolicyRule,
    before: dict[str, Any] | None,
    reason: str = "",
) -> None:
    details = {
        "policy_id": row.id,
        "category": row.category,
        "scope_type": row.scope_type,
        "tenant_id": row.tenant_id,
        "site_id": row.site_id,
        "network_id": row.network_id,
        "priority": row.priority,
        "revision": row.revision,
        "after": _policy_snapshot(row),
    }
    if before is not None:
        details["before"] = before
    if reason:
        details["reason"] = reason
    record_audit(
        db,
        actor=actor,
        action=action,
        object_type="policy",
        object_id=row.id,
        tenant_id=row.tenant_id,
        site_id=row.site_id,
        details=details,
    )


def get_policy(db: Session, policy_id: int, *, include_archived: bool = True) -> PolicyRule:
    row = (
        db.query(PolicyRule)
        .options(
            selectinload(PolicyRule.tenant),
            selectinload(PolicyRule.site),
            selectinload(PolicyRule.network),
        )
        .filter(PolicyRule.id == policy_id)
        .first()
    )
    if row is None or (row.archived_at is not None and not include_archived):
        raise PolicyError("Policy not found", status_code=404)
    return row


def list_policies(
    db: Session,
    *,
    category: str | None = None,
    scope_type: str | None = None,
    tenant_id: int | None = None,
    site_id: int | None = None,
    network_id: int | None = None,
    enabled: bool | None = None,
    include_archived: bool = False,
) -> list[PolicyRule]:
    query = db.query(PolicyRule).options(
        selectinload(PolicyRule.tenant),
        selectinload(PolicyRule.site),
        selectinload(PolicyRule.network),
    )
    if category:
        query = query.filter(PolicyRule.category == category)
    if scope_type:
        query = query.filter(PolicyRule.scope_type == scope_type)
    if tenant_id is not None:
        query = query.filter(PolicyRule.tenant_id == tenant_id)
    if site_id is not None:
        query = query.filter(PolicyRule.site_id == site_id)
    if network_id is not None:
        query = query.filter(PolicyRule.network_id == network_id)
    if enabled is not None:
        query = query.filter(PolicyRule.enabled.is_(enabled))
    if not include_archived:
        query = query.filter(PolicyRule.archived_at.is_(None))
    return query.order_by(PolicyRule.scope_type.asc(), PolicyRule.priority.desc(), PolicyRule.id.asc()).all()


def evaluate_draft(
    db: Session,
    *,
    draft: dict[str, Any],
    context: PolicyEvaluationContext,
) -> PolicyEvaluationResult:
    cleaned = normalize_rule_payload(db, **{k: draft[k] for k in (
        "name",
        "description",
        "category",
        "scope_type",
        "tenant_id",
        "site_id",
        "network_id",
        "priority",
        "conditions",
        "actions",
    )})
    resolver = PolicyResolver(db)
    existing = resolver.load_rules(cleaned["category"])
    ephemeral = PolicyRule(
        id=0,
        name=cleaned["name"],
        description=cleaned["description"],
        category=cleaned["category"],
        scope_type=cleaned["scope_type"],
        tenant_id=cleaned["tenant_id"],
        site_id=cleaned["site_id"],
        network_id=cleaned["network_id"],
        priority=cleaned["priority"],
        enabled=True,
        conditions=cleaned["conditions"],
        actions=cleaned["actions"],
        revision=0,
    )
    resolver._rules[cleaned["category"]] = list(existing) + [ephemeral]
    return resolver.evaluate(context, cleaned["category"])
