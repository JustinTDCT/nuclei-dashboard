"""Per-run write-through index for Finding/coverage ingest (Scale S2C).

Lifecycle meaning stays in ``finding_lifecycle``. This object builds one
run-resolution index per batch so ingest and finalize do not reload the
current-run population or scan historical ``raw_json`` once per finding.
No schema change.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import tuple_
from sqlalchemy.orm import Session

from app.models import (
    HOST_COVERAGE_KINDS,
    Asset,
    AssetFinding,
    AssetFindingRunEvaluation,
    AssetObservation,
    Device,
    Finding,
    ScanJob,
    ScanRunDetectorCoverage,
    Vulnerability,
    VulnerabilityDetectorMapping,
)

if TYPE_CHECKING:
    from app.finding_lifecycle import DetectorIdentity


class FindingRunIndex:
    def __init__(self, db: Session, job: ScanJob, *, detector_pairs: set[tuple[str, str]] | None = None):
        self.db = db
        self.job = job
        self._assets: dict[int, Asset] = {}
        self._canonical: dict[int, int] = {}
        self._observations: list[AssetObservation] = []
        self._observation_tokens: dict[int, set[str]] = {}
        self._observed_asset_ids: set[int] = set()
        self._devices: list[Device] = []
        self._device_tokens: dict[int, set[str]] = {}
        self._coverage: dict[tuple[str, str], ScanRunDetectorCoverage] = {}
        self._coverage_by_detector: dict[str, list[ScanRunDetectorCoverage]] = {}
        self._evidence_keys: set[str] = set()
        self._findings_by_key: dict[str, Finding] = {}
        self._cves: dict[tuple[str, str], set[str]] = {}
        self._mappings: dict[tuple[str, str], VulnerabilityDetectorMapping] = {}
        self._vulnerabilities: dict[str, Vulnerability] = {}
        self._asset_findings: dict[tuple[int, int], AssetFinding] = {}
        self._evaluations: dict[tuple[int, int], AssetFindingRunEvaluation] = {}
        self._supporting: dict[int, list[Finding]] = {}
        self._prefetch(detector_pairs or set())

    @classmethod
    def for_job(
        cls,
        db: Session,
        job: ScanJob,
        *,
        detector_pairs: set[tuple[str, str]] | None = None,
    ) -> FindingRunIndex:
        return cls(db, job, detector_pairs=detector_pairs)

    def _prefetch(self, detector_pairs: set[tuple[str, str]]) -> None:
        from app.finding_lifecycle import _observation_identity_tokens, cve_union

        self._observations = (
            self.db.query(AssetObservation)
            .filter(
                AssetObservation.scan_job_id == self.job.id,
                AssetObservation.tenant_id == self.job.tenant_id,
            )
            .all()
        )
        for observation in self._observations:
            tokens = _observation_identity_tokens(observation)
            self._observation_tokens[observation.id] = tokens
            self._observed_asset_ids.add(observation.asset_id)
        self._devices = (
            self.db.query(Device)
            .filter(Device.last_scan_job_id == self.job.id, Device.tenant_id == self.job.tenant_id)
            .all()
        )
        from app.classify import normalize_hostname

        for device in self._devices:
            self._device_tokens[device.id] = {
                part for part in (device.ip or "", normalize_hostname(device.hostname or "")) if part
            }
        coverage_rows = (
            self.db.query(ScanRunDetectorCoverage)
            .filter(ScanRunDetectorCoverage.scan_job_id == self.job.id)
            .all()
        )
        for row in coverage_rows:
            self.remember_coverage(row)
        findings = (
            self.db.query(Finding)
            .filter(Finding.scan_job_id == self.job.id, Finding.tenant_id == self.job.tenant_id)
            .all()
        )
        for row in findings:
            self.remember_finding(row)
        if detector_pairs:
            historical = (
                self.db.query(Finding.detector_type, Finding.detector_key, Finding.raw_json)
                .filter(tuple_(Finding.detector_type, Finding.detector_key).in_(sorted(detector_pairs)))
                .all()
            )
            grouped: dict[tuple[str, str], list[dict]] = {pair: [] for pair in detector_pairs}
            for detector_type, detector_key, raw in historical:
                grouped.setdefault((detector_type, detector_key), []).append(
                    raw if isinstance(raw, dict) else {}
                )
            for pair, raws in grouped.items():
                self._cves[pair] = cve_union(raws)
            mappings = (
                self.db.query(VulnerabilityDetectorMapping)
                .filter(tuple_(VulnerabilityDetectorMapping.detector_type, VulnerabilityDetectorMapping.detector_key).in_(sorted(detector_pairs)))
                .all()
            )
            for mapping in mappings:
                self._mappings[(mapping.detector_type, mapping.detector_key)] = mapping
        evaluations = (
            self.db.query(AssetFindingRunEvaluation)
            .filter(AssetFindingRunEvaluation.scan_job_id == self.job.id)
            .all()
        )
        for row in evaluations:
            self._evaluations[(row.asset_finding_id, row.scan_job_id)] = row

    def remember_coverage(self, row: ScanRunDetectorCoverage) -> None:
        self._coverage[(row.detector_type, row.target)] = row
        self._coverage_by_detector.setdefault(row.detector_type, []).append(row)

    def coverage_exists(self, detector_type: str, target: str) -> bool:
        return (detector_type, target) in self._coverage

    def remember_finding(self, row: Finding) -> None:
        self._evidence_keys.add(row.evidence_key)
        self._findings_by_key[row.evidence_key] = row
        if row.asset_finding_id is not None and row.asset_finding_id in self._supporting:
            self._supporting[row.asset_finding_id].append(row)
        if row.detector_type and row.detector_key:
            from app.finding_lifecycle import explicit_cves

            pair = (row.detector_type, row.detector_key)
            self._cves.setdefault(pair, set()).update(explicit_cves(row.raw_json if isinstance(row.raw_json, dict) else {}))

    def evidence_exists(self, evidence_key: str) -> bool:
        return evidence_key in self._evidence_keys

    def finding_for_key(self, evidence_key: str) -> Finding | None:
        return self._findings_by_key.get(evidence_key)

    def known_cves(self, detector_type: str, detector_key: str) -> set[str]:
        return set(self._cves.get((detector_type, detector_key), set()))

    def add_identity_cves(self, identity: DetectorIdentity) -> None:
        from app.finding_lifecycle import explicit_cves

        pair = (identity.detector_type, identity.detector_key)
        self._cves.setdefault(pair, set()).update(explicit_cves(identity.raw if isinstance(identity.raw, dict) else {}))

    def get_asset(self, asset_id: int) -> Asset | None:
        cached = self._assets.get(asset_id)
        if cached is not None:
            return cached
        asset = self.db.get(Asset, asset_id)
        if asset is not None:
            self._assets[asset.id] = asset
        return asset

    def canonical_asset_id(self, asset_id: int) -> int:
        cached = self._canonical.get(asset_id)
        if cached is not None:
            return cached
        from app.correlation import canonical_asset_id

        resolved = canonical_asset_id(self.db, asset_id)
        self._canonical[asset_id] = resolved
        return resolved

    def resolve_device(self, identity: DetectorIdentity) -> Device | None:
        from app.finding_lifecycle import _identity_tokens

        tokens = _identity_tokens(identity)
        if not tokens:
            return None
        matches: list[Device] = []
        for device in self._devices:
            if tokens.intersection(self._device_tokens.get(device.id, set())):
                matches.append(device)
        if len({row.id for row in matches}) != 1:
            return None
        return matches[0]

    def resolve_asset(self, identity: DetectorIdentity) -> Asset | None:
        from app.finding_lifecycle import _identity_tokens

        tokens = _identity_tokens(identity)
        if not tokens or not self._observations:
            return None
        asset_ids: set[int] = set()
        for observation in self._observations:
            if observation.tenant_id != self.job.tenant_id:
                continue
            if tokens.intersection(self._observation_tokens.get(observation.id, set())):
                asset_ids.add(observation.asset_id)
        if len(asset_ids) != 1:
            return None
        asset = self.get_asset(next(iter(asset_ids)))
        if asset is None or asset.tenant_id != self.job.tenant_id:
            return None
        canonical_id = self.canonical_asset_id(asset.id)
        if canonical_id != asset.id:
            asset = self.get_asset(canonical_id)
            if asset is None or asset.tenant_id != self.job.tenant_id:
                return None
        return asset

    def latest_observation(self, asset_id: int) -> AssetObservation | None:
        rows = [row for row in self._observations if row.asset_id == asset_id]
        rows.sort(key=lambda row: (row.observed_at is None, row.observed_at, row.id), reverse=True)
        return rows[0] if rows else None

    def asset_observed(self, asset_id: int) -> bool:
        return asset_id in self._observed_asset_ids

    def asset_covered(self, asset_id: int, detector_type: str) -> bool:
        coverage = self._coverage_by_detector.get(detector_type) or []
        if not coverage:
            return False
        tokens: set[str] = set()
        for observation in self._observations:
            if observation.asset_id == asset_id and observation.tenant_id == self.job.tenant_id:
                tokens.update(self._observation_tokens.get(observation.id, set()))
        if not tokens:
            return False
        for row in coverage:
            if row.target_kind not in HOST_COVERAGE_KINDS:
                continue
            host = (row.normalized_host or "").strip()
            if host and host in tokens:
                return True
        return False

    def mapping_for(self, detector_type: str, detector_key: str) -> VulnerabilityDetectorMapping | None:
        cached = self._mappings.get((detector_type, detector_key))
        if cached is not None:
            return cached
        row = (
            self.db.query(VulnerabilityDetectorMapping)
            .filter(
                VulnerabilityDetectorMapping.detector_type == detector_type,
                VulnerabilityDetectorMapping.detector_key == detector_key,
            )
            .first()
        )
        if row is not None:
            self._mappings[(detector_type, detector_key)] = row
        return row

    def remember_mapping(self, row: VulnerabilityDetectorMapping) -> None:
        self._mappings[(row.detector_type, row.detector_key)] = row

    def vulnerability_for(self, canonical_key: str) -> Vulnerability | None:
        cached = self._vulnerabilities.get(canonical_key)
        if cached is not None:
            return cached
        row = self.db.query(Vulnerability).filter(Vulnerability.canonical_key == canonical_key).first()
        if row is not None:
            self._vulnerabilities[canonical_key] = row
        return row

    def remember_vulnerability(self, row: Vulnerability) -> None:
        if row.canonical_key:
            self._vulnerabilities[row.canonical_key] = row

    def asset_finding_for(self, asset_id: int, vulnerability_id: int) -> AssetFinding | None:
        cached = self._asset_findings.get((asset_id, vulnerability_id))
        if cached is not None:
            return cached
        row = (
            self.db.query(AssetFinding)
            .filter(AssetFinding.asset_id == asset_id, AssetFinding.vulnerability_id == vulnerability_id)
            .first()
        )
        if row is not None:
            self._asset_findings[(asset_id, vulnerability_id)] = row
        return row

    def remember_asset_finding(self, row: AssetFinding) -> None:
        self._asset_findings[(row.asset_id, row.vulnerability_id)] = row

    def evaluation_for(self, asset_finding_id: int) -> AssetFindingRunEvaluation | None:
        return self._evaluations.get((asset_finding_id, self.job.id))

    def remember_evaluation(self, row: AssetFindingRunEvaluation) -> None:
        self._evaluations[(row.asset_finding_id, row.scan_job_id)] = row

    def supporting_findings(self, asset_finding_id: int) -> list[Finding]:
        cached = self._supporting.get(asset_finding_id)
        if cached is not None:
            return cached
        rows = (
            self.db.query(Finding)
            .filter(
                Finding.asset_finding_id == asset_finding_id,
                Finding.detector_type != "",
                Finding.detector_key != "",
            )
            .all()
        )
        self._supporting[asset_finding_id] = rows
        return rows

    def latest_supporting(self, asset_finding_id: int, detector_type: str, detector_key: str) -> Finding | None:
        rows = [
            row
            for row in self.supporting_findings(asset_finding_id)
            if row.detector_type == detector_type and row.detector_key == detector_key
        ]
        rows.sort(key=lambda row: (row.found_at is None, row.found_at, row.id), reverse=True)
        return rows[0] if rows else None


__all__ = ["FindingRunIndex"]
