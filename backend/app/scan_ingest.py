"""Per-scan-job write-through cache for Device/Asset ingest (Scale S2B).

Correlate-then-apply stays per report. This object collapses repeated
indexed lookups inside one ``upsert_devices()`` batch. No schema change
and no correlation-algorithm change.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import TYPE_CHECKING

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Session, selectinload

from app.models import (
    IDENTIFIER_VALIDITY_ACTIVE,
    SOURCE_SCANNER,
    Asset,
    AssetAddress,
    AssetCorrelationDecision,
    AssetIdentifier,
    AssetObservation,
    AssetService,
    Device,
    Network,
    Scan,
    ScanJob,
)

if TYPE_CHECKING:
    from app.correlation import CorrelationSignals

# Keep in lockstep with app.correlation
_MAX_CANDIDATES_PER_LOOKUP = 20
_MAX_CANDIDATES_SCORED = 50


class ScanIngestContext:
    def __init__(self, db: Session, tenant_id: int, job_id: int):
        self.db = db
        self.tenant_id = tenant_id
        self.job_id = job_id
        self._job: ScanJob | None = None
        self._execution: dict | None = None
        self._legacy_scope: str | None = None
        self._legacy_site_id: int | None = None
        self._legacy_agent_id: int | None = None
        self._networks: list[Network] | None = None
        self._assets: dict[int, Asset] = {}
        self._canonical: dict[int, int] = {}
        self._identifiers: dict[tuple[int, str, str], AssetIdentifier] = {}
        self._id_index: dict[tuple[str, str], list[int]] = {}
        self._addresses: dict[tuple[int, str], AssetAddress] = {}
        self._addr_index: list[AssetAddress] = []
        self._services: dict[tuple[int, str, int, str], AssetService] = {}
        self._services_loaded: set[int] = set()
        self._observations: dict[tuple[int, int | None, str], AssetObservation] = {}
        self._decisions: dict[tuple[int | None, str], AssetCorrelationDecision] = {}
        self._devices: list[Device] | None = None
        self._prefetch()

    @classmethod
    def for_job(cls, db: Session, tenant_id: int, job_id: int) -> ScanIngestContext:
        return cls(db, tenant_id, job_id)

    def _prefetch(self) -> None:
        self._job = (
            self.db.query(ScanJob)
            .options(selectinload(ScanJob.scan).selectinload(Scan.agent))
            .filter(ScanJob.id == self.job_id)
            .first()
        )
        if self._job and self._job.execution_snapshot:
            from app.scan_execution import execution_context

            self._execution = execution_context(self.db, self._job)
        elif self._job:
            scan = self._job.scan
            agent = scan.agent if scan else None
            self._legacy_scope = (scan.scope if scan else None)
            if self._legacy_scope == "lan" and agent is not None:
                self._legacy_site_id = agent.site_id
                self._legacy_agent_id = agent.id
        identifiers = (
            self.db.query(AssetIdentifier)
            .filter(AssetIdentifier.tenant_id == self.tenant_id)
            .all()
        )
        for row in identifiers:
            self.remember_identifier(row, index_only=False)
        addresses = (
            self.db.query(AssetAddress)
            .filter(AssetAddress.tenant_id == self.tenant_id)
            .all()
        )
        for row in addresses:
            self.remember_address(row)
        decisions = (
            self.db.query(AssetCorrelationDecision)
            .filter(AssetCorrelationDecision.scan_job_id == self.job_id)
            .all()
        )
        for row in decisions:
            self.remember_decision(row)
        observations = (
            self.db.query(AssetObservation)
            .filter(AssetObservation.scan_job_id == self.job_id)
            .all()
        )
        for row in observations:
            self.remember_observation(row)
        self._devices = (
            self.db.query(Device).filter(Device.tenant_id == self.tenant_id).all()
        )

    def observation_context(self, ip: str, report_scope: str) -> dict:
        job = self._job
        if job and job.execution_snapshot:
            from app.scan_execution import resolve_snapshot_network

            context = self._execution or {}
            network_id = resolve_snapshot_network(self.db, job, ip)
            return {
                "site_id": context.get("site_id") if context.get("scope") == "lan" else None,
                "network_id": network_id,
                "agent_id": context.get("claimed_agent_id") if context.get("scope") == "lan" else None,
                "scope": context.get("scope"),
                "scan_job_id": self.job_id,
                "source": SOURCE_SCANNER,
            }
        scope = (self._legacy_scope or report_scope) or report_scope
        site_id = self._legacy_site_id if scope == "lan" else None
        agent_id = self._legacy_agent_id if scope == "lan" else None
        network = self._network_for_ip(site_id, ip) if site_id else None
        return {
            "site_id": site_id,
            "network_id": network.id if network else None,
            "agent_id": agent_id,
            "scope": scope,
            "scan_job_id": self.job_id,
            "source": SOURCE_SCANNER,
        }

    def _network_for_ip(self, site_id: int | None, ip: str) -> Network | None:
        if not site_id or not (ip or "").strip():
            return None
        try:
            parsed = ip_address(ip.strip())
        except ValueError:
            return None
        if self._networks is None:
            self._networks = (
                self.db.query(Network)
                .filter(Network.site_id == site_id, Network.archived_at.is_(None))
                .all()
            )
        matches: list[Network] = []
        for network in self._networks:
            try:
                if parsed in ip_network(network.cidr, strict=False):
                    matches.append(network)
            except ValueError:
                continue
        if len(matches) == 1:
            return matches[0]
        return None

    def get_asset(self, asset_id: int) -> Asset | None:
        cached = self._assets.get(asset_id)
        if cached is not None:
            return cached
        asset = self.db.get(Asset, asset_id)
        if asset is not None:
            self._assets[asset.id] = asset
        return asset

    def remember_asset(self, asset: Asset) -> None:
        self._assets[asset.id] = asset
        self.mark_asset_facts_empty(asset.id)

    def mark_asset_facts_empty(self, asset_id: int) -> None:
        self._services_loaded.add(asset_id)

    def canonical_asset_id(self, asset_id: int) -> int:
        cached = self._canonical.get(asset_id)
        if cached is not None:
            return cached
        seen: set[int] = set()
        current = asset_id
        while current and current not in seen:
            seen.add(current)
            known = self._canonical.get(current)
            if known is not None:
                current = known
                break
            asset = self.get_asset(current)
            if asset is None or not asset.merged_into_asset_id:
                break
            current = asset.merged_into_asset_id
        for item in seen:
            self._canonical[item] = current
        return current

    def remember_identifier(self, row: AssetIdentifier, *, index_only: bool = False) -> None:
        if not index_only:
            self._identifiers[(row.asset_id, row.identifier_type, row.normalized_value)] = row
            self._attach(row.asset_id, "identifiers", row)
        if row.validity != IDENTIFIER_VALIDITY_ACTIVE:
            return
        key = (row.identifier_type, row.normalized_value)
        bucket = self._id_index.setdefault(key, [])
        if row.asset_id not in bucket:
            bucket.append(row.asset_id)

    def find_identifier(
        self, asset_id: int, identifier_type: str, normalized: str
    ) -> AssetIdentifier | None:
        return self._identifiers.get((asset_id, identifier_type, normalized))

    def remember_address(self, row: AssetAddress) -> None:
        self._addresses[(row.asset_id, row.ip)] = row
        if row not in self._addr_index:
            self._addr_index.append(row)
        self._attach(row.asset_id, "addresses", row)

    def find_address(self, asset_id: int, ip: str) -> AssetAddress | None:
        return self._addresses.get((asset_id, ip))

    def _load_services(self, asset_id: int) -> None:
        if asset_id in self._services_loaded:
            return
        rows = self.db.query(AssetService).filter(AssetService.asset_id == asset_id).all()
        for row in rows:
            self.remember_service(row)
        self._services_loaded.add(asset_id)

    def remember_service(self, row: AssetService) -> None:
        self._services[(row.asset_id, row.ip or "", row.port, row.protocol)] = row
        self._services_loaded.add(row.asset_id)
        self._attach(row.asset_id, "services", row)

    def _attach(self, asset_id: int, collection: str, row) -> None:
        asset = self._assets.get(asset_id)
        if asset is None:
            return
        if collection in sa_inspect(asset).unloaded:
            return
        items = getattr(asset, collection)
        if row not in items:
            items.append(row)

    def find_service(
        self, asset_id: int, ip: str, port: int, protocol: str
    ) -> AssetService | None:
        self._load_services(asset_id)
        return self._services.get((asset_id, ip or "", port, protocol))

    def remember_observation(self, row: AssetObservation) -> None:
        self._observations[(row.asset_id, row.scan_job_id, row.observation_key)] = row

    def find_observation(
        self, asset_id: int, scan_job_id: int | None, observation_key: str
    ) -> AssetObservation | None:
        return self._observations.get((asset_id, scan_job_id, observation_key))

    def remember_decision(self, row: AssetCorrelationDecision) -> None:
        self._decisions[(row.scan_job_id, row.observation_key)] = row

    def find_decision(
        self, scan_job_id: int | None, observation_key: str
    ) -> AssetCorrelationDecision | None:
        return self._decisions.get((scan_job_id, observation_key))

    def candidate_asset_ids(self, signals: CorrelationSignals) -> list[int]:
        found: list[int] = []

        def add(asset_id: int) -> None:
            canonical = self.canonical_asset_id(asset_id)
            if canonical not in found:
                found.append(canonical)

        for signal in signals.identifiers:
            rows = self._id_index.get((signal.identifier_type, signal.normalized), [])
            for asset_id in rows[:_MAX_CANDIDATES_PER_LOOKUP]:
                add(asset_id)
                if len(found) >= _MAX_CANDIDATES_SCORED:
                    return found
        if signals.ip:
            matched = 0
            for row in self._addr_index:
                if row.tenant_id != signals.tenant_id or row.ip != signals.ip:
                    continue
                if signals.scope == "lan" and signals.site_id is not None and row.site_id != signals.site_id:
                    continue
                if signals.scope == "wan" and row.site_id is not None:
                    continue
                add(row.asset_id)
                matched += 1
                if matched >= _MAX_CANDIDATES_PER_LOOKUP or len(found) >= _MAX_CANDIDATES_SCORED:
                    return found
        return found

    def load_candidates(self, candidate_ids: list[int], tenant_id: int) -> list[Asset]:
        missing = [asset_id for asset_id in candidate_ids if asset_id not in self._assets]
        if missing:
            rows = (
                self.db.query(Asset)
                .options(
                    selectinload(Asset.identifiers),
                    selectinload(Asset.addresses),
                    selectinload(Asset.services),
                )
                .filter(Asset.id.in_(missing), Asset.tenant_id == tenant_id)
                .all()
            )
            for asset in rows:
                self._assets[asset.id] = asset
        return [self._assets[asset_id] for asset_id in candidate_ids if asset_id in self._assets]

    def devices(self) -> list[Device]:
        if self._devices is None:
            self._devices = (
                self.db.query(Device).filter(Device.tenant_id == self.tenant_id).all()
            )
        return self._devices

    def remember_device(self, device: Device) -> None:
        rows = self.devices()
        if device not in rows:
            rows.append(device)

    def forget_device(self, device: Device) -> None:
        rows = self.devices()
        if device in rows:
            rows.remove(device)

    def find_devices_for_asset(self, asset_id: int, scope: str) -> list[Device]:
        rows = [
            row
            for row in self.devices()
            if row.asset_id == asset_id and row.scope == scope
        ]
        rows.sort(key=lambda row: (row.last_seen is None, row.last_seen), reverse=True)
        return rows

    def find_by_hostname(
        self,
        scope: str,
        hostname: str,
        *,
        site_id: int | None,
        asset_id: int | None,
    ) -> Device | None:
        if not hostname:
            return None
        matches: list[Device] = []
        for row in self.devices():
            if row.hostname != hostname or row.scope != scope:
                continue
            if site_id is None:
                if row.site_id is not None:
                    continue
            elif row.site_id != site_id:
                continue
            if asset_id is not None and row.asset_id != asset_id:
                continue
            matches.append(row)
        matches.sort(key=lambda row: (row.last_seen is None, row.last_seen), reverse=True)
        return matches[0] if matches else None

    def find_placeholder_by_ip(
        self,
        scope: str,
        ip: str,
        *,
        site_id: int | None,
        asset_id: int | None,
        is_placeholder,
    ) -> Device | None:
        if not ip:
            return None
        matches: list[Device] = []
        for row in self.devices():
            if row.ip != ip or row.scope != scope:
                continue
            if site_id is None:
                if row.site_id is not None:
                    continue
            elif row.site_id != site_id:
                continue
            if asset_id is not None and row.asset_id != asset_id:
                continue
            matches.append(row)
        matches.sort(key=lambda row: (row.last_seen is None, row.last_seen), reverse=True)
        for row in matches:
            if is_placeholder(row):
                return row
        return None

    def find_by_ip(
        self,
        scope: str,
        ip: str,
        *,
        site_id: int | None,
        asset_id: int | None,
    ) -> Device | None:
        if not ip:
            return None
        matches: list[Device] = []
        for row in self.devices():
            if row.ip != ip or row.scope != scope:
                continue
            if site_id is None:
                if row.site_id is not None:
                    continue
            elif row.site_id != site_id:
                continue
            if asset_id is not None and row.asset_id != asset_id:
                continue
            matches.append(row)
        matches.sort(key=lambda row: (row.last_seen is None, row.last_seen), reverse=True)
        return matches[0] if matches else None


__all__ = ["ScanIngestContext"]
