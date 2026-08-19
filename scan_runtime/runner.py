from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

from artifact_io import (
    artifact_meta,
    parse_jsonl_file,
    run_command_to_file,
    stream_gzip,
)
from classify import clean_tech, identity_name, infer_class, infer_label, is_ip, is_placeholder_name, normalize_hostname
from commands import (
    PORT_MODE_NONE,
    build_httpx_command,
    build_naabu_command,
    build_naabu_host_discovery_command,
    build_nuclei_command,
    job_intensity,
    job_stages,
    job_targets,
)
from enrich import enrich_identities, usable_hostname

LogFn = Callable[[str], None]


class PipelineError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        artifacts: list[dict[str, Any]] | None = None,
        staging_dir: str | Path | None = None,
        devices: list[dict[str, Any]] | None = None,
        findings: list[dict[str, Any]] | None = None,
        provenance: dict[str, Any] | None = None,
        detector_coverage: list[dict[str, Any]] | None = None,
    ):
        super().__init__(message)
        self.artifacts = artifacts or []
        self.staging_dir = str(staging_dir) if staging_dir else None
        self.devices = devices or []
        self.findings = findings or []
        self.provenance = provenance or {}
        self.detector_coverage = detector_coverage or []

    def as_result(self) -> dict[str, Any]:
        return {
            "devices": self.devices,
            "findings": self.findings,
            "provenance": self.provenance,
            "detector_coverage": self.detector_coverage,
            "artifacts": self.artifacts,
            "staging_dir": self.staging_dir,
            "pipeline_error": str(self),
        }


def _log(message: str, log: LogFn | None) -> None:
    if log:
        log(message)
    else:
        print(message, flush=True)


def _which(name: str) -> str | None:
    return shutil.which(name)


def _run(cmd: list[str], log: LogFn | None = None) -> str:
    with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
        path = Path(handle.name)
    try:
        run_command_to_file(cmd, path, log)
        return path.read_text(encoding="utf-8", errors="replace")
    finally:
        path.unlink(missing_ok=True)


def _parse_jsonl(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _execute_stage(
    cmd: list[str],
    staging_dir: Path,
    *,
    artifact_key: str,
    stage: str,
    tool: str,
    log: LogFn | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw_path = staging_dir / f"{artifact_key}.jsonl"
    gz_path = staging_dir / f"{artifact_key}.jsonl.gz"
    run_command_to_file(cmd, raw_path, log)
    rows = parse_jsonl_file(raw_path)
    stream_gzip(raw_path, gz_path)
    raw_path.unlink(missing_ok=True)
    return rows, artifact_meta(artifact_key=artifact_key, stage=stage, tool=tool, gz_path=gz_path)


def dry_run(cidrs: list[str], scope: str, profile: str) -> dict[str, Any]:
    sample_ip = "203.0.113.10" if scope == "wan" else "192.168.1.10"
    devices = [
        {
            "ip": sample_ip,
            "scope": scope,
            "ports": [80, 443],
            "hostname": "sample-host.local",
            "classification": "Server",
            "title": f"Sample host in {','.join(cidrs) or 'n/a'}",
            "tech": "nginx",
            "auto_label": "web-server",
        }
    ]
    findings = []
    if profile == "discovery_nuclei":
        findings.append(
            {
                "template_id": "sample-exposed-panel",
                "name": "Sample exposure (dry run)",
                "severity": "medium",
                "host": f"https://{sample_ip}",
                "matched_at": f"https://{sample_ip}/",
                "tags": "sample,dry-run",
                "raw": {"dry_run": True, "cidrs": cidrs},
            }
        )
    return {
        "devices": devices,
        "findings": findings,
        "artifacts": [],
        "staging_dir": None,
        "provenance": {},
        "detector_coverage": [],
        "dry_run": True,
    }


def _unpack_stage(result: Any) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if isinstance(result, tuple) and len(result) == 2:
        return result[0], result[1]
    return result or [], None


def run_pipeline(job: dict[str, Any], log: LogFn | None = None) -> dict[str, Any]:
    stages = job_stages(job)
    intensity = job_intensity(job)
    targets = resolve_execution_targets(job, log=log)
    scope = job.get("scope") or "lan"
    profile = "discovery_nuclei" if stages.get("vulnerability") else "discovery"
    cidrs = [row["value"] for row in targets if row["type"] in {"ip", "cidr"}]
    if job.get("dry_run") or os.environ.get("SCAN_DRY_RUN") == "1":
        _log("dry-run — emitting sample results without scanner artifacts", log)
        return dry_run(cidrs or [row["value"] for row in targets], scope, profile)
    if not targets:
        raise RuntimeError("No targets configured for this scan")

    staging_dir = Path(tempfile.mkdtemp(prefix="nd-raw-"))
    artifacts: list[dict[str, Any]] = []
    hosts: list[dict[str, Any]] = []
    http_info: list[dict[str, Any]] = []
    devices: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    nuclei_targets: list[str] = []
    try:
        port_mode = stages.get("port_mode") or PORT_MODE_NONE
        if port_mode != PORT_MODE_NONE:
            hosts, artifact = _unpack_stage(
                run_naabu(
                    [row["value"] for row in targets],
                    port_mode=port_mode,
                    custom_ports=stages.get("custom_ports") or [],
                    intensity=intensity,
                    exclude_hosts=_exclusion_hosts(job),
                    log=log,
                    staging_dir=staging_dir,
                )
            )
            if artifact:
                artifacts.append(artifact)
        elif stages.get("discovery"):
            hosts, artifact = _unpack_stage(
                run_host_discovery(
                    targets,
                    intensity=intensity,
                    exclude_hosts=_exclusion_hosts(job),
                    log=log,
                    staging_dir=staging_dir,
                )
            )
            if artifact:
                artifacts.append(artifact)
        if stages.get("fingerprint", True):
            probe_hosts = hosts or [
                {"ip": row["value"]} for row in targets if row["type"] in {"ip", "fqdn", "cidr"}
            ]
            http_info, artifact = _unpack_stage(
                run_httpx(probe_hosts, intensity=intensity, log=log, staging_dir=staging_dir)
            )
            if artifact:
                artifacts.append(artifact)
        devices = merge_devices(hosts, http_info, scope)
        attach_hostnames(devices, log=log)
        enrich_identities(devices, log=log)
        if stages.get("vulnerability"):
            nuclei_targets = [h["url"] for h in http_info if h.get("url")]
            if not nuclei_targets:
                nuclei_targets = [f"{h['ip']}:{h['port']}" for h in hosts if h.get("ip") and h.get("port")]
            if not nuclei_targets:
                nuclei_targets = [row["value"] for row in targets]
            findings, artifact = _unpack_stage(
                run_nuclei(
                    nuclei_targets,
                    severities=stages.get("nuclei_severities") or "critical,high,medium",
                    tags=stages.get("nuclei_tags") or "",
                    intensity=intensity,
                    log=log,
                    staging_dir=staging_dir,
                )
            )
            if artifact:
                artifacts.append(artifact)
            apply_nuclei_hostnames(devices, findings)
        finalize_devices(devices)
        named = sum(1 for d in devices if usable_hostname(d.get("hostname") or ""))
        _log(f"Hostnames resolved on agent: {named}/{len(devices)}", log)
        if stages.get("vulnerability"):
            coverage.append({"detector_type": "nuclei", "targets": nuclei_targets})
        provenance = collect_tool_versions(log=log)
        if not artifacts:
            shutil.rmtree(staging_dir, ignore_errors=True)
            staging_out = None
        else:
            staging_out = str(staging_dir)
        return {
            "devices": devices,
            "findings": findings,
            "provenance": provenance,
            "detector_coverage": coverage,
            "artifacts": artifacts,
            "staging_dir": staging_out,
        }
    except PipelineError:
        raise
    except Exception as exc:
        provenance = collect_tool_versions(log=log)
        if not artifacts:
            shutil.rmtree(staging_dir, ignore_errors=True)
            staging_out = None
        else:
            staging_out = staging_dir
        raise PipelineError(
            str(exc),
            artifacts=artifacts,
            staging_dir=staging_out,
            devices=devices,
            findings=findings,
            provenance=provenance,
            detector_coverage=coverage,
        ) from exc


def resolve_execution_targets(job: dict[str, Any], log: LogFn | None = None) -> list[dict[str, str]]:
    import ipaddress

    exclusions = []
    for row in job.get("exclusions") or []:
        kind = row.get("type") or row.get("exclusion_type")
        value = row.get("normalized") or row.get("normalized_value") or row.get("value")
        if not value:
            continue
        if kind == "ip":
            exclusions.append(ipaddress.ip_network(ipaddress.ip_address(value)))
        elif kind == "cidr":
            exclusions.append(ipaddress.ip_network(value, strict=False))
        elif kind == "range" and "-" in value:
            start, _, end = value.partition("-")
            exclusions.extend(ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end)))
    resolved: list[dict[str, str]] = []
    for row in job_targets(job):
        kind = row.get("type") or "cidr"
        value = row.get("value") or ""
        if kind == "fqdn":
            for ip in _pin_fqdn_ips(value, exclusions, log=log):
                resolved.append({"type": "ip", "value": ip, "source_fqdn": value})
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise RuntimeError(f"Invalid target {value}") from exc
        if any(network.overlaps(exc) for exc in exclusions):
            remaining = list(network.address_exclude(exc)) if False else [network]
            for exclusion in exclusions:
                nxt = []
                for current in remaining:
                    if current.overlaps(exclusion) and current.version == exclusion.version:
                        if exclusion.supernet_of(current) or exclusion == current:
                            continue
                        if current.supernet_of(exclusion):
                            nxt.extend(current.address_exclude(exclusion))
                        continue
                    nxt.append(current)
                remaining = nxt
            resolved.extend({"type": "cidr", "value": str(item)} for item in remaining)
        else:
            resolved.append({"type": kind, "value": value})
    if job_targets(job) and not resolved:
        raise RuntimeError("Exclusions remove all targets")
    return resolved


def _keep_fqdn(fqdn: str, exclusions: list, log: LogFn | None = None) -> bool:
    return bool(_pin_fqdn_ips(fqdn, exclusions, log=log))


def _pin_fqdn_ips(fqdn: str, exclusions: list, log: LogFn | None = None) -> list[str]:
    try:
        infos = socket.getaddrinfo(fqdn, None)
    except socket.gaierror:
        _log(f"FQDN {fqdn} did not resolve; excluding fail-closed", log)
        return []
    import ipaddress

    addresses = []
    for item in infos:
        if not item[4]:
            continue
        try:
            addresses.append(ipaddress.ip_address(str(item[4][0]).split("%", 1)[0]))
        except ValueError:
            continue
    if not addresses:
        _log(f"FQDN {fqdn} did not resolve; excluding fail-closed", log)
        return []
    for addr in addresses:
        if any(addr in network for network in exclusions):
            _log(f"FQDN {fqdn} resolved to excluded address {addr}; excluding fail-closed", log)
            return []
    return [str(addr) for addr in addresses]


def _exclusion_hosts(job: dict[str, Any]) -> list[str]:
    hosts = []
    for row in job.get("exclusions") or []:
        kind = row.get("type") or row.get("exclusion_type")
        value = row.get("normalized") or row.get("value")
        if kind == "ip" and value:
            hosts.append(value)
    return hosts


def collect_tool_versions(log: LogFn | None = None) -> dict[str, Any]:
    versions = {
        "runtime_version": os.environ.get("SCAN_RUNTIME_VERSION") or None,
        "naabu_version": _tool_version("naabu"),
        "httpx_version": _tool_version(_pd_httpx() or "httpx"),
        "nuclei_version": _tool_version("nuclei"),
        "nuclei_templates": _nuclei_template_version(),
    }
    return {key: value for key, value in versions.items() if value}


def _tool_version(name: str | None) -> str | None:
    if not name:
        return None
    binary = name if os.path.isabs(name) else _which(name)
    if not binary:
        return None
    proc = subprocess.run([binary, "-version"], capture_output=True, text=True)
    text = (proc.stdout or proc.stderr or "").strip()
    if not text:
        return None
    return text.splitlines()[0][:200]


def _nuclei_template_version() -> str | None:
    binary = _which("nuclei")
    if not binary:
        return None
    proc = subprocess.run([binary, "-tl", "-silent"], capture_output=True, text=True)
    # Do not invent a template commit. Only record a path hint when nuclei reports one.
    combined = f"{proc.stdout}\n{proc.stderr}"
    for line in combined.splitlines():
        if "templates" in line.lower() and any(token in line.lower() for token in ("version", "commit", "release")):
            return line.strip()[:200]
    return None


def run_naabu(
    targets: list[str],
    log: LogFn | None = None,
    *,
    port_mode: str = "common",
    custom_ports: list[str] | None = None,
    intensity: dict[str, Any] | None = None,
    exclude_hosts: list[str] | None = None,
    staging_dir: Path | None = None,
    artifact_key: str = "port_discovery.naabu",
    stage: str = "port_discovery",
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    binary = _which("naabu")
    if not binary:
        raise RuntimeError("naabu is not installed")
    cmd = build_naabu_command(
        binary,
        targets,
        port_mode=port_mode,
        custom_ports=custom_ports,
        intensity=intensity,
        exclude_hosts=exclude_hosts,
    )
    if cmd is None:
        return [], None
    if staging_dir is None:
        return _parse_jsonl(_run(cmd, log)), None
    return _execute_stage(cmd, staging_dir, artifact_key=artifact_key, stage=stage, tool="naabu", log=log)


def run_host_discovery(
    targets: list[dict[str, str]],
    log: LogFn | None = None,
    *,
    intensity: dict[str, Any] | None = None,
    exclude_hosts: list[str] | None = None,
    staging_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    values = [row["value"] for row in targets]
    binary = _which("naabu")
    if binary:
        cmd = build_naabu_host_discovery_command(
            binary,
            values,
            intensity=intensity,
            exclude_hosts=exclude_hosts,
        )
        if cmd:
            _log("Discovery enabled with port mode none; running Naabu host discovery (-sn)", log)
            if staging_dir is None:
                return _parse_jsonl(_run(cmd, log)), None
            return _execute_stage(
                cmd,
                staging_dir,
                artifact_key="discovery.naabu",
                stage="discovery",
                tool="naabu",
                log=log,
            )
    hosts: list[dict[str, Any]] = []
    for row in targets:
        kind = row.get("type") or "cidr"
        value = row.get("value") or ""
        if kind in {"ip", "fqdn"}:
            hosts.append({"ip": value, "host": value, "port": None, "discovery": True})
        elif kind == "cidr":
            raise RuntimeError("naabu is required for CIDR host discovery when port mode is none")
    if not hosts:
        raise RuntimeError("Host discovery produced no hosts")
    _log(f"Host discovery recorded {len(hosts)} explicit IP/FQDN target(s)", log)
    return hosts, None


def _pd_httpx() -> str | None:
    for name in ("pd-httpx", "httpx"):
        path = _which(name)
        if path and _is_pd_httpx(path):
            return path
    return None


def _is_pd_httpx(path: str) -> bool:
    proc = subprocess.run([path, "-version"], capture_output=True, text=True)
    text = f"{proc.stdout} {proc.stderr}".lower()
    return "projectdiscovery" in text or "current version" in text


def run_httpx(
    hosts: list[dict[str, Any]],
    log: LogFn | None = None,
    *,
    intensity: dict[str, Any] | None = None,
    staging_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if not hosts:
        return [], None
    binary = _pd_httpx()
    if not binary:
        _log("ProjectDiscovery httpx not found; skipping HTTP fingerprinting", log)
        return [], None
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        for row in hosts:
            ip = row.get("ip")
            port = row.get("port")
            if ip and port:
                handle.write(f"{ip}:{port}\n")
            elif ip:
                handle.write(f"{ip}\n")
        path = handle.name
    try:
        cmd = build_httpx_command(binary, path, intensity=intensity, tls_grab=True)
        try:
            if staging_dir is None:
                return _parse_jsonl(_run(cmd, log)), None
            return _execute_stage(
                cmd,
                staging_dir,
                artifact_key="fingerprint.httpx",
                stage="fingerprint",
                tool="httpx",
                log=log,
            )
        except RuntimeError as exc:
            _log(f"httpx tls-grab failed ({exc}); retrying without it", log)
            cmd = build_httpx_command(binary, path, intensity=intensity, tls_grab=False)
            if staging_dir is None:
                return _parse_jsonl(_run(cmd, log)), None
            return _execute_stage(
                cmd,
                staging_dir,
                artifact_key="fingerprint.httpx",
                stage="fingerprint",
                tool="httpx",
                log=log,
            )
    finally:
        Path(path).unlink(missing_ok=True)


def run_nuclei(
    targets: list[str],
    severities: str,
    tags: str,
    log: LogFn | None = None,
    *,
    intensity: dict[str, Any] | None = None,
    staging_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if not targets:
        return [], None
    binary = _which("nuclei")
    if not binary:
        raise RuntimeError("nuclei is not installed")
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write("\n".join(targets) + "\n")
        path = handle.name
    artifact = None
    try:
        cmd = build_nuclei_command(binary, path, severities=severities, tags=tags, intensity=intensity)
        if staging_dir is None:
            rows = _parse_jsonl(_run(cmd, log))
        else:
            rows, artifact = _execute_stage(
                cmd,
                staging_dir,
                artifact_key="vulnerability.nuclei",
                stage="vulnerability",
                tool="nuclei",
                log=log,
            )
    finally:
        Path(path).unlink(missing_ok=True)
    findings = []
    for raw in rows:
        info = raw.get("info") or {}
        findings.append(
            {
                "template_id": raw.get("template-id") or "",
                "name": info.get("name") or "",
                "severity": (info.get("severity") or "info").lower(),
                "host": raw.get("host") or "",
                "matched_at": raw.get("matched-at") or "",
                "tags": ",".join(info.get("tags") or []),
                "raw": raw,
            }
        )
    return findings, artifact


def merge_devices(hosts: list[dict[str, Any]], http_info: list[dict[str, Any]], scope: str) -> list[dict[str, Any]]:
    ports: dict[str, set[int]] = defaultdict(set)
    for row in hosts:
        ip = row.get("ip")
        if not ip:
            continue
        if row.get("port"):
            ports[ip].add(int(row["port"]))
        else:
            ports.setdefault(ip, set())
    meta: dict[str, dict[str, str]] = {}
    for row in http_info:
        host = row.get("host") or row.get("input") or ""
        ip = str(host).split("://")[-1].split(":")[0].split("/")[0]
        if not ip:
            continue
        title = (row.get("title") or "").strip()
        techs = row.get("tech") or []
        if isinstance(techs, str):
            tech = techs
        else:
            tech = ",".join(str(t) for t in techs if t)
        server = (row.get("webserver") or row.get("web-server") or "").strip()
        if server and server not in tech:
            tech = ",".join(part for part in (tech, server) if part)
        http_name = _http_hostname(row)
        prev = meta.get(ip, {"title": "", "tech": "", "hostname": ""})
        titles = [prev.get("title") or "", title]
        title = max(titles, key=len)
        tech_parts = []
        for part in f"{prev.get('tech', '')},{tech}".split(","):
            part = part.strip()
            if part and part not in tech_parts:
                tech_parts.append(part)
        meta[ip] = {
            "title": title,
            "tech": ",".join(tech_parts),
            "hostname": prev.get("hostname") or http_name,
        }
        if row.get("port"):
            try:
                ports[ip].add(int(row["port"]))
            except (TypeError, ValueError):
                pass
    devices = []
    for ip, portset in sorted(ports.items()):
        info = meta.get(ip, {})
        devices.append(
            {
                "ip": ip,
                "scope": scope,
                "ports": sorted(portset),
                "hostname": info.get("hostname", ""),
                "title": info.get("title", ""),
                "tech": info.get("tech", ""),
                "auto_label": "",
            }
        )
    return devices


def _http_hostname(row: dict[str, Any]) -> str:
    tls = row.get("tls") or row.get("tls-grab") or {}
    if isinstance(tls, dict):
        for key in ("subject_cn", "host"):
            name = usable_hostname(str(tls.get(key) or ""))
            if name:
                return name
        for san in tls.get("subject_an") or tls.get("subject_alt_names") or []:
            name = usable_hostname(str(san))
            if name:
                return name
    for key in ("cname", "host", "input", "url", "final_url"):
        raw = row.get(key)
        if isinstance(raw, list):
            raw = raw[0] if raw else ""
        value = str(raw or "").strip()
        if "://" in value:
            value = value.split("://", 1)[1]
        value = value.split("/")[0].split(":")[0].rstrip(".")
        name = usable_hostname(value)
        if name:
            return name
    return ""


def _reverse_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(1.5)
        name, aliases, _ = socket.gethostbyaddr(ip)
        for candidate in [name, *(aliases or [])]:
            candidate = (candidate or "").rstrip(".")
            if candidate and not is_ip(candidate):
                return candidate
    except Exception:
        return ""
    return ""


def attach_hostnames(devices: list[dict[str, Any]], log: LogFn | None = None) -> None:
    missing = [
        d["ip"]
        for d in devices
        if d.get("ip") and is_placeholder_name(d.get("hostname") or "", d.get("ip") or "")
    ]
    if not missing:
        return
    _log(f"Resolving hostnames for {len(missing)} addresses", log)
    found: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=20) as pool:
        for ip, name in zip(missing, pool.map(_reverse_dns, missing)):
            if name:
                found[ip] = normalize_hostname(name)
    for device in devices:
        if is_placeholder_name(device.get("hostname") or "", device.get("ip") or ""):
            device["hostname"] = found.get(device.get("ip"), device.get("hostname") or "")


def apply_nuclei_hostnames(devices: list[dict[str, Any]], findings: list[dict[str, Any]]) -> None:
    by_ip: dict[str, str] = {}
    for row in findings:
        raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
        name = _host_label(row.get("host") or row.get("matched_at") or raw.get("host") or "")
        ip = str(raw.get("ip") or "") or _host_ip(row.get("host") or row.get("matched_at") or "")
        if name and ip:
            by_ip[ip] = name
    for device in devices:
        if is_placeholder_name(device.get("hostname") or "", device.get("ip") or ""):
            name = by_ip.get(device.get("ip") or "")
            if name:
                device["hostname"] = name


def finalize_devices(devices: list[dict[str, Any]]) -> None:
    for device in devices:
        ip = device.get("ip") or ""
        device["hostname"] = identity_name(device.get("hostname") or "", ip)
        title = device.get("title") or ""
        tech = clean_tech(device.get("tech") or "")
        device["tech"] = tech
        ports = device.get("ports") or []
        guessed = infer_class(device.get("hostname") or "", ports, title, tech)
        device["classification"] = guessed if guessed not in ("", "Other") else "Unknown"
        device["auto_label"] = infer_label(device.get("hostname") or "", ports, title, tech)


def _host_label(value: str) -> str:
    raw = (value or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/")[0].split(":")[0].rstrip(".")
    name = normalize_hostname(raw)
    return name if name and not is_ip(name) else ""


def _host_ip(value: str) -> str:
    raw = (value or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/")[0].split(":")[0]
    return raw if is_ip(raw) else ""
