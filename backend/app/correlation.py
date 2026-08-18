"""Deterministic multi-signal Asset correlation.

Asset correlation is authoritative. Device compatibility must not decide
identity. IP alone can never reach the automatic-match threshold.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session, selectinload

from app.assets import is_placeholder_hostname, normalize_identifier, observation_key_from_snapshot, report_snapshot
from app.classify import normalize_hostname
from app.models import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CORRELATION_ALGORITHM_VERSION,
    DECISION_AMBIGUOUS,
    DECISION_CREATED_NEW,
    DECISION_LINKED_EXISTING,
    IDENTIFIER_DEVICE_ID,
    IDENTIFIER_DNS_NAME,
    IDENTIFIER_FQDN,
    IDENTIFIER_HOSTNAME,
    IDENTIFIER_MAC,
    IDENTIFIER_SERIAL,
    IDENTIFIER_TLS_NAME,
    IDENTIFIER_VALIDITY_ACTIVE,
    Asset,
    AssetAddress,
    AssetCorrelationDecision,
    AssetIdentifier,
    AssetService,
)
from app.schemas import DeviceReport

ALGORITHM_VERSION = CORRELATION_ALGORITHM_VERSION

WEIGHT_MAC = 70
WEIGHT_SERIAL = 70
WEIGHT_DEVICE_ID = 70
WEIGHT_FQDN = 35
WEIGHT_TLS_NAME = 20
WEIGHT_DNS_NAME = 15
WEIGHT_HOSTNAME = 25
WEIGHT_SAME_SITE = 10
WEIGHT_SAME_ADDRESS = 15
WEIGHT_SERVICE_FINGERPRINT = 8
BONUS_UNIQUE_HOSTNAME = 30
PENALTY_HOSTNAME_CONFLICT = 25

AUTO_MATCH_THRESHOLD = 50
REVIEW_THRESHOLD = 40
AMBIGUOUS_GAP = 15
MAX_CANDIDATES_PER_LOOKUP = 20
MAX_CANDIDATES_SCORED = 50
MAX_CANDIDATES_STORED = 8

STRONG_IDENTIFIER_TYPES = frozenset({IDENTIFIER_MAC, IDENTIFIER_SERIAL, IDENTIFIER_DEVICE_ID})
NAME_IDENTIFIER_TYPES = frozenset(
    {IDENTIFIER_HOSTNAME, IDENTIFIER_FQDN, IDENTIFIER_DNS_NAME, IDENTIFIER_TLS_NAME}
)
STRONG_EVIDENCE_LABELS = frozenset(
    {"exact unique MAC", "exact serial", "exact device identifier"}
)
NAME_EVIDENCE_LABELS = frozenset({"exact normalized hostname", "exact normalized FQDN"})
CORROBORATING_EVIDENCE_LABELS = frozenset(
    {
        "same recently observed address",
        "compatible service fingerprint",
        "TLS certificate name",
        "DNS name",
    }
)


@dataclass(frozen=True)
class CorrelationSignal:
    identifier_type: str
    value: str
    normalized: str


@dataclass
class CorrelationSignals:
    tenant_id: int
    site_id: int | None
    scope: str
    ip: str
    hostname: str
    title: str = ""
    tech: str = ""
    ports: list = field(default_factory=list)
    identifiers: list[CorrelationSignal] = field(default_factory=list)

    @property
    def hostname_normalized(self) -> str:
        if not self.hostname or is_placeholder_hostname(self.hostname, self.ip):
            return ""
        return normalize_identifier(IDENTIFIER_HOSTNAME, self.hostname)

    def values_for(self, identifier_type: str) -> set[str]:
        return {row.normalized for row in self.identifiers if row.identifier_type == identifier_type}

    def has_strong_identity(self) -> bool:
        return any(row.identifier_type in STRONG_IDENTIFIER_TYPES for row in self.identifiers)


@dataclass
class EvidenceItem:
    label: str
    contribution: int
    polarity: str = "plus"

    def as_dict(self) -> dict[str, Any]:
        return {"label": self.label, "contribution": self.contribution, "polarity": self.polarity}


@dataclass
class ScoredCandidate:
    asset_id: int
    display_name: str
    score: int
    evidence: list[EvidenceItem]
    blocked: bool = False
    block_reason: str = ""
    matched_strong: bool = False
    matched_name: bool = False
    matched_corroboration: bool = False

    def as_summary(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "display_name": self.display_name,
            "score": self.score,
            "confidence": confidence_for_score(self.score),
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "evidence": [item.as_dict() for item in self.evidence],
        }


@dataclass
class CorrelationResult:
    decision: str
    confidence: str
    score: int
    selected_asset_id: int | None
    evidence: list[EvidenceItem]
    candidates: list[ScoredCandidate]
    algorithm_version: str = ALGORITHM_VERSION
    retry: bool = False

    def evidence_payload(self) -> list[dict[str, Any]]:
        return [item.as_dict() for item in self.evidence]

    def candidate_payload(self) -> list[dict[str, Any]]:
        ranked = sorted(self.candidates, key=lambda row: (-row.score, row.asset_id))
        return [row.as_summary() for row in ranked[:MAX_CANDIDATES_STORED]]


def confidence_for_score(score: int) -> str:
    if score >= 70:
        return CONFIDENCE_HIGH
    if score >= REVIEW_THRESHOLD:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def signals_from_report(tenant_id: int, report: DeviceReport, context: dict) -> CorrelationSignals:
    hostname = (report.hostname or "").strip()
    ip = (report.ip or "").strip()
    signals: list[CorrelationSignal] = []

    def add(identifier_type: str, raw: str) -> None:
        value = (raw or "").strip()
        if not value:
            return
        if identifier_type == IDENTIFIER_HOSTNAME and is_placeholder_hostname(value, ip):
            return
        normalized = normalize_identifier(identifier_type, value)
        if not normalized:
            return
        signals.append(CorrelationSignal(identifier_type, value, normalized))

    if hostname and not is_placeholder_hostname(hostname, ip):
        add(IDENTIFIER_HOSTNAME, hostname)
        if "." in normalize_hostname(hostname):
            add(IDENTIFIER_FQDN, hostname)
    add(IDENTIFIER_MAC, report.mac or "")
    add(IDENTIFIER_SERIAL, report.serial or "")
    add(IDENTIFIER_DEVICE_ID, report.device_identifier or "")
    add(IDENTIFIER_FQDN, report.fqdn or "")
    add(IDENTIFIER_TLS_NAME, report.tls_name or "")
    add(IDENTIFIER_DNS_NAME, report.dns_name or "")

    return CorrelationSignals(
        tenant_id=tenant_id,
        site_id=context.get("site_id"),
        scope=(context.get("scope") or report.scope or "").strip().lower(),
        ip=ip,
        hostname=hostname,
        title=report.title or "",
        tech=report.tech or "",
        ports=list(report.ports or []),
        identifiers=signals,
    )


def canonical_asset_id(db: Session, asset_id: int, *, _seen: set[int] | None = None) -> int:
    seen = _seen if _seen is not None else set()
    current = asset_id
    while current and current not in seen:
        seen.add(current)
        asset = db.get(Asset, current)
        if asset is None or not asset.merged_into_asset_id:
            return current
        current = asset.merged_into_asset_id
    return current


def generate_candidate_ids(db: Session, signals: CorrelationSignals) -> list[int]:
    """Indexed lookups only. Never scan every Asset in the tenant."""
    found: list[int] = []

    def add(asset_id: int) -> None:
        canonical = canonical_asset_id(db, asset_id)
        if canonical not in found:
            found.append(canonical)
        if len(found) >= MAX_CANDIDATES_SCORED:
            return

    for signal in signals.identifiers:
        rows = (
            db.query(AssetIdentifier.asset_id)
            .filter(
                AssetIdentifier.tenant_id == signals.tenant_id,
                AssetIdentifier.identifier_type == signal.identifier_type,
                AssetIdentifier.normalized_value == signal.normalized,
                AssetIdentifier.validity == IDENTIFIER_VALIDITY_ACTIVE,
            )
            .limit(MAX_CANDIDATES_PER_LOOKUP)
            .all()
        )
        for (asset_id,) in rows:
            add(asset_id)
            if len(found) >= MAX_CANDIDATES_SCORED:
                return found

    if signals.ip:
        addr_q = db.query(AssetAddress.asset_id).filter(
            AssetAddress.tenant_id == signals.tenant_id,
            AssetAddress.ip == signals.ip,
        )
        if signals.scope == "lan" and signals.site_id is not None:
            addr_q = addr_q.filter(AssetAddress.site_id == signals.site_id)
        elif signals.scope == "wan":
            addr_q = addr_q.filter(AssetAddress.site_id.is_(None))
        for (asset_id,) in addr_q.limit(MAX_CANDIDATES_PER_LOOKUP).all():
            add(asset_id)
            if len(found) >= MAX_CANDIDATES_SCORED:
                return found

    return found


def _active_values(asset: Asset, identifier_type: str) -> set[str]:
    return {
        row.normalized_value
        for row in asset.identifiers
        if row.identifier_type == identifier_type and row.validity == IDENTIFIER_VALIDITY_ACTIVE
    }


def _strong_identifier_match(asset: Asset, signals: CorrelationSignals) -> bool:
    for identifier_type in STRONG_IDENTIFIER_TYPES:
        observed = signals.values_for(identifier_type)
        if observed and observed & _active_values(asset, identifier_type):
            return True
    return False


def _eligible(asset: Asset, signals: CorrelationSignals) -> bool:
    if asset.tenant_id != signals.tenant_id:
        return False
    if asset.merged_into_asset_id:
        return False
    strong = _strong_identifier_match(asset, signals)
    lan = signals.scope == "lan"
    wan = signals.scope == "wan"
    if lan and signals.site_id is not None and asset.site_id is not None and asset.site_id != signals.site_id:
        return strong
    if lan and asset.site_id is None:
        return strong
    if wan and asset.site_id is not None:
        return strong
    return True


def _service_tokens(title: str, tech: str, ports: list) -> set[str]:
    tokens: set[str] = set()
    for part in (tech or "").split(","):
        token = part.strip().lower()
        if token:
            tokens.add(token)
    title_token = (title or "").strip().lower()
    if title_token:
        tokens.add(title_token)
    for item in ports or []:
        if isinstance(item, dict):
            product = str(item.get("product") or item.get("service") or "").strip().lower()
            if product:
                tokens.add(product)
    return tokens


def _asset_service_tokens(asset: Asset) -> set[str]:
    tokens: set[str] = set()
    for row in asset.services:
        tokens |= _service_tokens(row.web_title, row.tech, [{"product": row.product}])
    return tokens


def score_candidate(asset: Asset, signals: CorrelationSignals, *, unique_hostname: bool) -> ScoredCandidate:
    evidence: list[EvidenceItem] = []
    blocked = False
    block_reason = ""

    matched_strong = False
    matched_name = False
    matched_corroboration = False
    for identifier_type, weight, label in (
        (IDENTIFIER_MAC, WEIGHT_MAC, "exact unique MAC"),
        (IDENTIFIER_SERIAL, WEIGHT_SERIAL, "exact serial"),
        (IDENTIFIER_DEVICE_ID, WEIGHT_DEVICE_ID, "exact device identifier"),
    ):
        observed = signals.values_for(identifier_type)
        existing = _active_values(asset, identifier_type)
        if observed and existing:
            if observed & existing:
                evidence.append(EvidenceItem(label, weight))
                matched_strong = True
            else:
                blocked = True
                block_reason = "conflicting strong identifiers"
                evidence.append(EvidenceItem(f"conflicting {identifier_type}", -weight, "minus"))

    hostname = signals.hostname_normalized
    asset_hostnames = _active_values(asset, IDENTIFIER_HOSTNAME)
    asset_fqdns = _active_values(asset, IDENTIFIER_FQDN)
    if hostname:
        if hostname in asset_hostnames or hostname in asset_fqdns:
            evidence.append(EvidenceItem("exact normalized hostname", WEIGHT_HOSTNAME))
            matched_name = True
            if unique_hostname:
                evidence.append(EvidenceItem("unique hostname in locality", BONUS_UNIQUE_HOSTNAME))
        elif asset_hostnames and not matched_strong:
            evidence.append(EvidenceItem("conflicting hostname", -PENALTY_HOSTNAME_CONFLICT, "minus"))

    fqdn_values = signals.values_for(IDENTIFIER_FQDN)
    if fqdn_values and fqdn_values & (asset_fqdns | asset_hostnames):
        if not any(item.label == "exact normalized hostname" for item in evidence):
            evidence.append(EvidenceItem("exact normalized FQDN", WEIGHT_FQDN))
        matched_name = True

    tls_values = signals.values_for(IDENTIFIER_TLS_NAME)
    if tls_values and tls_values & _active_values(asset, IDENTIFIER_TLS_NAME):
        evidence.append(EvidenceItem("TLS certificate name", WEIGHT_TLS_NAME))
        matched_corroboration = True

    dns_values = signals.values_for(IDENTIFIER_DNS_NAME)
    if dns_values and dns_values & _active_values(asset, IDENTIFIER_DNS_NAME):
        evidence.append(EvidenceItem("DNS name", WEIGHT_DNS_NAME))
        matched_corroboration = True

    if signals.scope == "lan" and signals.site_id is not None and asset.site_id == signals.site_id:
        evidence.append(EvidenceItem("same Site", WEIGHT_SAME_SITE))

    if signals.ip:
        matching_addresses = [
            row
            for row in asset.addresses
            if row.ip == signals.ip
            and (
                signals.scope != "lan"
                or signals.site_id is None
                or row.site_id == signals.site_id
            )
        ]
        if matching_addresses:
            evidence.append(EvidenceItem("same recently observed address", WEIGHT_SAME_ADDRESS))
            matched_corroboration = True

    observed_tokens = _service_tokens(signals.title, signals.tech, signals.ports)
    if observed_tokens and observed_tokens & _asset_service_tokens(asset):
        evidence.append(EvidenceItem("compatible service fingerprint", WEIGHT_SERVICE_FINGERPRINT))
        matched_corroboration = True

    score = sum(item.contribution for item in evidence)
    return ScoredCandidate(
        asset_id=asset.id,
        display_name=asset.display_name,
        score=score,
        evidence=evidence,
        blocked=blocked,
        block_reason=block_reason,
        matched_strong=matched_strong,
        matched_name=matched_name,
        matched_corroboration=matched_corroboration,
    )


def qualifies_for_auto_match(candidate: ScoredCandidate) -> bool:
    """Structural eligibility only. Score threshold is applied in decide()."""
    if candidate.blocked:
        return False
    if candidate.matched_strong:
        return True
    return candidate.matched_name and candidate.matched_corroboration


def _competitor_blocks_auto(best: ScoredCandidate, competitor: ScoredCandidate) -> bool:
    if (best.score - competitor.score) >= AMBIGUOUS_GAP:
        return False
    return (
        competitor.score >= REVIEW_THRESHOLD
        or (best.matched_name and competitor.matched_name)
        or (best.matched_strong and competitor.matched_strong)
    )


def _ambiguous(best: ScoredCandidate, scored: list[ScoredCandidate]) -> CorrelationResult:
    return CorrelationResult(
        decision=DECISION_AMBIGUOUS,
        confidence=confidence_for_score(best.score),
        score=best.score,
        selected_asset_id=None,
        evidence=best.evidence,
        candidates=scored,
    )


def decide(scored: list[ScoredCandidate]) -> CorrelationResult:
    viable = [row for row in scored if not row.blocked]
    viable.sort(key=lambda row: (-row.score, row.asset_id))
    eligible_auto = [
        row
        for row in viable
        if qualifies_for_auto_match(row) and row.score >= AUTO_MATCH_THRESHOLD
    ]
    if not eligible_auto:
        best = viable[0] if viable else None
        second = viable[1] if len(viable) > 1 else None
        if best and second and _competitor_blocks_auto(best, second):
            return _ambiguous(best, scored)
        return CorrelationResult(
            decision=DECISION_CREATED_NEW,
            confidence=confidence_for_score(best.score) if best else CONFIDENCE_LOW,
            score=best.score if best else 0,
            selected_asset_id=None,
            evidence=best.evidence if best else [],
            candidates=scored,
        )
    best = eligible_auto[0]
    competitor = next((row for row in viable if row.asset_id != best.asset_id), None)
    if competitor is not None and _competitor_blocks_auto(best, competitor):
        return _ambiguous(best, scored)
    confidence = confidence_for_score(best.score)
    if best.score < AUTO_MATCH_THRESHOLD or confidence == CONFIDENCE_LOW:
        return CorrelationResult(
            decision=DECISION_CREATED_NEW,
            confidence=confidence,
            score=best.score,
            selected_asset_id=None,
            evidence=best.evidence,
            candidates=scored,
        )
    return CorrelationResult(
        decision=DECISION_LINKED_EXISTING,
        confidence=confidence,
        score=best.score,
        selected_asset_id=best.asset_id,
        evidence=best.evidence,
        candidates=scored,
    )


def correlate(db: Session, signals: CorrelationSignals) -> CorrelationResult:
    candidate_ids = generate_candidate_ids(db, signals)
    if not candidate_ids:
        return CorrelationResult(
            decision=DECISION_CREATED_NEW,
            confidence=CONFIDENCE_LOW,
            score=0,
            selected_asset_id=None,
            evidence=[],
            candidates=[],
        )
    assets = (
        db.query(Asset)
        .options(
            selectinload(Asset.identifiers),
            selectinload(Asset.addresses),
            selectinload(Asset.services),
        )
        .filter(Asset.id.in_(candidate_ids), Asset.tenant_id == signals.tenant_id)
        .all()
    )
    eligible = [asset for asset in assets if _eligible(asset, signals)]
    hostname = signals.hostname_normalized
    hostname_matches = [
        asset
        for asset in eligible
        if hostname and (hostname in _active_values(asset, IDENTIFIER_HOSTNAME) or hostname in _active_values(asset, IDENTIFIER_FQDN))
    ]
    unique_hostname = bool(hostname) and len(hostname_matches) == 1
    scored = [score_candidate(asset, signals, unique_hostname=unique_hostname) for asset in eligible]
    return decide(scored)


def find_correlation_decision(
    db: Session,
    *,
    scan_job_id: int | None,
    observation_key: str,
) -> AssetCorrelationDecision | None:
    query = db.query(AssetCorrelationDecision).filter(
        AssetCorrelationDecision.observation_key == observation_key
    )
    if scan_job_id is None:
        query = query.filter(AssetCorrelationDecision.scan_job_id.is_(None))
    else:
        query = query.filter(AssetCorrelationDecision.scan_job_id == scan_job_id)
    return query.first()


def persist_correlation_decision(
    db: Session,
    *,
    tenant_id: int,
    site_id: int | None,
    scan_job_id: int | None,
    observation_key: str,
    source_device_id: int | None,
    result: CorrelationResult,
) -> AssetCorrelationDecision:
    existing = find_correlation_decision(db, scan_job_id=scan_job_id, observation_key=observation_key)
    if existing is not None:
        result.retry = True
        return existing
    row = AssetCorrelationDecision(
        tenant_id=tenant_id,
        site_id=site_id,
        scan_job_id=scan_job_id,
        observation_key=observation_key,
        source_device_id=source_device_id,
        selected_asset_id=result.selected_asset_id,
        decision=result.decision,
        confidence=result.confidence,
        score=result.score,
        algorithm_version=result.algorithm_version,
        evidence=result.evidence_payload(),
        candidates=result.candidate_payload(),
    )
    db.add(row)
    db.flush()
    return row


def observation_key_for_report(report: DeviceReport, scope: str) -> str:
    return observation_key_from_snapshot(report_snapshot(report, scope))


def post_correlation_asset_policy_hook(
    db: Session,
    asset: Asset,
    result: CorrelationResult,
    context: dict,
) -> None:
    """Apply Asset handling policy after correlation identity is resolved.

    Policy never changes the selected Asset, score, or confidence.
    """
    from app.policy import apply_asset_handling_for_observation

    apply_asset_handling_for_observation(db, asset, context)


__all__ = [
    "ALGORITHM_VERSION",
    "AMBIGUOUS_GAP",
    "AUTO_MATCH_THRESHOLD",
    "CORROBORATING_EVIDENCE_LABELS",
    "CorrelationResult",
    "CorrelationSignals",
    "NAME_EVIDENCE_LABELS",
    "REVIEW_THRESHOLD",
    "STRONG_EVIDENCE_LABELS",
    "WEIGHT_HOSTNAME",
    "WEIGHT_MAC",
    "WEIGHT_SAME_ADDRESS",
    "WEIGHT_SAME_SITE",
    "canonical_asset_id",
    "correlate",
    "decide",
    "find_correlation_decision",
    "generate_candidate_ids",
    "observation_key_for_report",
    "persist_correlation_decision",
    "post_correlation_asset_policy_hook",
    "qualifies_for_auto_match",
    "score_candidate",
    "signals_from_report",
]
