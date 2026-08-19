"""Deterministic Device/Finding/coverage workloads for S2A."""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas import DeviceReport, FindingReport
from tests.scale_s2.constants import PORT_POOL, WorkloadSpec


@dataclass(frozen=True)
class IngestWorkload:
    spec: WorkloadSpec
    devices: list[DeviceReport]
    findings: list[FindingReport]
    coverage_targets: list[str]
    historical: list[dict]


def _ports(index: int, count: int) -> list[int]:
    return [PORT_POOL[(index + offset) % len(PORT_POOL)] for offset in range(count)]


def _ip(index: int) -> str:
    return f"10.200.{(index // 254) + 1}.{(index % 254) + 1}"


def _hostname(index: int) -> str:
    return f"host-{index:05d}.lab.local"


def _mac(index: int) -> str:
    return f"aa:bb:cc:{index // 65536:02x}:{(index // 256) % 256:02x}:{index % 256:02x}"


def _detector(index: int, distinct: int) -> tuple[str, str | None]:
    template = f"s2a-template-{(index % max(distinct, 1)):03d}"
    if index % 7 == 0:
        return template, f"CVE-2025-{(1000 + (index % 40)):04d}"
    if index % 11 == 0:
        return template, None
    return template, f"CVE-2024-{(2000 + (index % distinct)):04d}" if index % 5 == 0 else None


def build_workload(spec: WorkloadSpec) -> IngestWorkload:
    devices: list[DeviceReport] = []
    for index in range(spec.devices):
        hostname = _hostname(index)
        ip = _ip(index)
        report = DeviceReport(
            ip=ip,
            scope="wan",
            hostname=hostname,
            ports=_ports(index, spec.ports_per_device),
            title=f"Service {index:05d}" if index % 2 == 0 else "",
            tech="nginx" if index % 3 == 0 else "",
            mac=_mac(index) if index % 3 == 0 else "",
            fqdn=hostname if index % 4 == 0 else "",
            tls_name=f"tls-{index:05d}.lab.local" if index % 5 == 0 else "",
            dns_name=hostname if index % 6 == 0 else "",
            serial=f"SER-{index:05d}" if index % 8 == 0 else "",
            device_identifier=f"dev-{index:05d}" if index % 9 == 0 else "",
        )
        devices.append(report)

    findings: list[FindingReport] = []
    for index in range(spec.findings):
        device_index = index % spec.devices
        hostname = _hostname(device_index)
        ip = _ip(device_index)
        template, cve = _detector(index, spec.distinct_detectors)
        host = f"https://{ip}" if index % 2 == 0 else hostname
        matched = f"{host}/"
        info: dict = {"name": f"Detector {template}", "severity": "high", "tags": ["s2a"]}
        if cve:
            info["classification"] = {"cve-id": [cve]}
        findings.append(
            FindingReport(
                template_id=template,
                name=f"Detector {template}",
                severity="high",
                host=host,
                matched_at=matched,
                tags="s2a",
                raw={"template-id": template, "host": host, "matched-at": matched, "info": info},
            )
        )

    coverage = []
    for index in range(spec.devices):
        coverage.append(_ip(index))
        coverage.append(_hostname(index))

    historical = []
    for index in range(spec.historical_findings):
        template, cve = _detector(index, spec.distinct_detectors)
        raw = {"template-id": template, "info": {"name": template, "severity": "medium"}}
        if cve:
            raw["info"]["classification"] = {"cve-id": [cve]}
        historical.append(
            {
                "evidence_key": f"s2a-hist:{index:05d}:{template}",
                "detector_type": "nuclei",
                "detector_key": template,
                "template_id": template,
                "name": template,
                "severity": "medium",
                "host": f"hist-{index}.example.test",
                "matched_at": f"hist-{index}.example.test/",
                "raw_json": raw,
            }
        )
    return IngestWorkload(
        spec=spec,
        devices=devices,
        findings=findings,
        coverage_targets=coverage,
        historical=historical,
    )
