"""Pure command builders for Naabu, httpx, and Nuclei.

Flags are limited to options actually supported by ProjectDiscovery CLIs:
- naabu: -host, -p, -top-ports, -json, -silent, -rate, -c, -timeout, -retries, -exclude-hosts
- httpx: -l, -json, -silent, -title, -tech-detect, -status-code, -cname, -web-server, -tls-grab,
         -sni, -H, -rl, -t, -timeout, -retries
  (v1.10.0 has no -no-classify; DIT download is avoided by seeding ~/.dit/model.json)
- nuclei: -l, -jsonl, -silent, -severity, -tags, -sni, -H, -rl, -c, -timeout, -retries, -duc
"""

from __future__ import annotations

from typing import Any

PORT_MODE_NONE = "none"
PORT_MODE_COMMON = "common"
PORT_MODE_DEEP = "deep"
PORT_MODE_CUSTOM = "custom"
COMMON_TOP_PORTS = "100"
DEEP_TOP_PORTS = "1000"


def build_naabu_command(
    binary: str,
    targets: list[str],
    *,
    port_mode: str,
    custom_ports: list[str] | None = None,
    intensity: dict[str, Any] | None = None,
    exclude_hosts: list[str] | None = None,
) -> list[str] | None:
    if port_mode == PORT_MODE_NONE or not targets:
        return None
    cmd = [binary, "-host", ",".join(targets), "-json", "-silent"]
    if port_mode == PORT_MODE_COMMON:
        cmd.extend(["-top-ports", COMMON_TOP_PORTS])
    elif port_mode == PORT_MODE_DEEP:
        cmd.extend(["-top-ports", DEEP_TOP_PORTS])
    elif port_mode == PORT_MODE_CUSTOM:
        ports = [str(item) for item in (custom_ports or []) if str(item).strip()]
        if not ports:
            raise ValueError("Custom port mode requires ports")
        cmd.extend(["-p", ",".join(ports)])
    else:
        raise ValueError(f"Unsupported port mode: {port_mode}")
    intensity = intensity or {}
    if intensity.get("naabu_rate") is not None:
        cmd.extend(["-rate", str(int(intensity["naabu_rate"]))])
    if intensity.get("naabu_concurrency") is not None:
        cmd.extend(["-c", str(int(intensity["naabu_concurrency"]))])
    if intensity.get("naabu_timeout_ms") is not None:
        cmd.extend(["-timeout", str(int(intensity["naabu_timeout_ms"]))])
    if intensity.get("naabu_retries") is not None:
        cmd.extend(["-retries", str(int(intensity["naabu_retries"]))])
    if exclude_hosts:
        cmd.extend(["-exclude-hosts", ",".join(exclude_hosts)])
    return cmd


def build_naabu_host_discovery_command(
    binary: str,
    targets: list[str],
    *,
    intensity: dict[str, Any] | None = None,
    exclude_hosts: list[str] | None = None,
) -> list[str] | None:
    """Host discovery only. Uses documented Naabu -sn / -host-discovery, not a port scan."""
    if not targets:
        return None
    cmd = [binary, "-host", ",".join(targets), "-json", "-silent", "-sn"]
    intensity = intensity or {}
    if intensity.get("naabu_rate") is not None:
        cmd.extend(["-rate", str(int(intensity["naabu_rate"]))])
    if intensity.get("naabu_concurrency") is not None:
        cmd.extend(["-c", str(int(intensity["naabu_concurrency"]))])
    if intensity.get("naabu_timeout_ms") is not None:
        cmd.extend(["-timeout", str(int(intensity["naabu_timeout_ms"]))])
    if intensity.get("naabu_retries") is not None:
        cmd.extend(["-retries", str(int(intensity["naabu_retries"]))])
    if exclude_hosts:
        cmd.extend(["-exclude-hosts", ",".join(exclude_hosts)])
    return cmd


def build_httpx_command(
    binary: str,
    list_path: str,
    *,
    intensity: dict[str, Any] | None = None,
    tls_grab: bool = True,
    sni: str | None = None,
) -> list[str]:
    cmd = [
        binary,
        "-l",
        list_path,
        "-json",
        "-silent",
        "-title",
        "-tech-detect",
        "-status-code",
        "-cname",
        "-web-server",
    ]
    if tls_grab:
        cmd.append("-tls-grab")
    if sni:
        cmd.extend(["-sni", sni, "-H", f"Host: {sni}"])
    intensity = intensity or {}
    if intensity.get("httpx_rate") is not None:
        cmd.extend(["-rl", str(int(intensity["httpx_rate"]))])
    if intensity.get("httpx_threads") is not None:
        cmd.extend(["-t", str(int(intensity["httpx_threads"]))])
    if intensity.get("httpx_timeout") is not None:
        cmd.extend(["-timeout", str(int(intensity["httpx_timeout"]))])
    if intensity.get("httpx_retries") is not None:
        cmd.extend(["-retries", str(int(intensity["httpx_retries"]))])
    return cmd


def build_nuclei_command(
    binary: str,
    list_path: str,
    *,
    severities: str,
    tags: str = "",
    intensity: dict[str, Any] | None = None,
    sni: str | None = None,
) -> list[str]:
    cmd = [binary, "-l", list_path, "-jsonl", "-silent", "-severity", severities, "-duc"]
    if tags:
        cmd.extend(["-tags", tags])
    if sni:
        cmd.extend(["-sni", sni, "-H", f"Host: {sni}"])
    intensity = intensity or {}
    if intensity.get("nuclei_rate") is not None:
        cmd.extend(["-rl", str(int(intensity["nuclei_rate"]))])
    if intensity.get("nuclei_concurrency") is not None:
        cmd.extend(["-c", str(int(intensity["nuclei_concurrency"]))])
    if intensity.get("nuclei_timeout") is not None:
        cmd.extend(["-timeout", str(int(intensity["nuclei_timeout"]))])
    if intensity.get("nuclei_retries") is not None:
        cmd.extend(["-retries", str(int(intensity["nuclei_retries"]))])
    return cmd


def job_stages(job: dict[str, Any]) -> dict[str, Any]:
    stages = job.get("stages")
    if stages:
        return stages
    profile = job.get("profile") or "discovery"
    return {
        "discovery": True,
        "port_mode": PORT_MODE_COMMON,
        "custom_ports": [],
        "fingerprint": True,
        "vulnerability": profile == "discovery_nuclei",
        "nuclei_severities": job.get("nuclei_severities") or "critical,high,medium",
        "nuclei_tags": job.get("nuclei_tags") or "",
    }


def job_targets(job: dict[str, Any]) -> list[dict[str, str]]:
    if job.get("targets"):
        return list(job["targets"])
    return [{"type": "cidr", "value": cidr} for cidr in (job.get("cidrs") or [])]


def job_intensity(job: dict[str, Any]) -> dict[str, Any]:
    intensity = job.get("intensity")
    if isinstance(intensity, dict):
        return intensity.get("resolved") or intensity
    return {}
