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

from classify import clean_tech, identity_name, infer_class, infer_label, is_ip, is_placeholder_name, normalize_hostname
from enrich import enrich_identities, usable_hostname

LogFn = Callable[[str], None]


def _log(message: str, log: LogFn | None) -> None:
    if log:
        log(message)
    else:
        print(message, flush=True)


def _which(name: str) -> str | None:
    return shutil.which(name)


def _run(cmd: list[str], log: LogFn | None = None) -> str:
    _log("$ " + " ".join(cmd), log)
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(proc.stderr.strip() or f"command failed: {cmd[0]}")
    if proc.stderr.strip():
        _log(proc.stderr.strip(), log)
    return proc.stdout


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
    return {"devices": devices, "findings": findings}


def run_pipeline(job: dict[str, Any], log: LogFn | None = None) -> dict[str, Any]:
    cidrs: list[str] = job.get("cidrs") or []
    scope = job.get("scope") or "lan"
    profile = job.get("profile") or "discovery"
    if os.environ.get("SCAN_DRY_RUN") == "1":
        _log("SCAN_DRY_RUN=1 — emitting sample results", log)
        return dry_run(cidrs, scope, profile)
    if not cidrs:
        raise RuntimeError("No CIDRs configured for this scan")

    hosts = run_naabu(cidrs, log=log)
    http_info = run_httpx(hosts, log=log)
    devices = merge_devices(hosts, http_info, scope)
    attach_hostnames(devices, log=log)
    enrich_identities(devices, log=log)
    findings: list[dict[str, Any]] = []
    if profile == "discovery_nuclei":
        targets = [h["url"] for h in http_info if h.get("url")]
        if not targets:
            targets = [f"{h['ip']}:{h['port']}" for h in hosts]
        findings = run_nuclei(
            targets,
            severities=job.get("nuclei_severities") or "critical,high,medium",
            tags=job.get("nuclei_tags") or "",
            log=log,
        )
        apply_nuclei_hostnames(devices, findings)
    finalize_devices(devices)
    named = sum(1 for d in devices if usable_hostname(d.get("hostname") or ""))
    _log(f"Hostnames resolved on agent: {named}/{len(devices)}", log)
    return {"devices": devices, "findings": findings}


def run_naabu(cidrs: list[str], log: LogFn | None = None) -> list[dict[str, Any]]:
    binary = _which("naabu")
    if not binary:
        raise RuntimeError("naabu is not installed")
    cmd = [binary, "-host", ",".join(cidrs), "-top-ports", "100", "-json", "-silent"]
    return _parse_jsonl(_run(cmd, log))


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


def run_httpx(hosts: list[dict[str, Any]], log: LogFn | None = None) -> list[dict[str, Any]]:
    if not hosts:
        return []
    binary = _pd_httpx()
    if not binary:
        _log("ProjectDiscovery httpx not found; skipping HTTP fingerprinting", log)
        return []
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
        cmd = [
            binary,
            "-l",
            path,
            "-json",
            "-silent",
            "-title",
            "-tech-detect",
            "-status-code",
            "-cname",
            "-web-server",
            "-tls-grab",
        ]
        try:
            return _parse_jsonl(_run(cmd, log))
        except RuntimeError as exc:
            _log(f"httpx tls-grab failed ({exc}); retrying without it", log)
            cmd = cmd[:-1]
            return _parse_jsonl(_run(cmd, log))
    finally:
        Path(path).unlink(missing_ok=True)


def run_nuclei(targets: list[str], severities: str, tags: str, log: LogFn | None = None) -> list[dict[str, Any]]:
    if not targets:
        return []
    binary = _which("nuclei")
    if not binary:
        raise RuntimeError("nuclei is not installed")
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write("\n".join(targets) + "\n")
        path = handle.name
    try:
        cmd = [binary, "-l", path, "-jsonl", "-silent", "-severity", severities]
        if tags:
            cmd.extend(["-tags", tags])
        rows = _parse_jsonl(_run(cmd, log))
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
    return findings


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
