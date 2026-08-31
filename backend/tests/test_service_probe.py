from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

BACKEND_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = BACKEND_ROOT.parent / "scan_runtime"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))


def test_expand_probe_ips_keeps_slash24_and_skips_huge_cidrs():
    from service_probe import expand_probe_ips

    ips = expand_probe_ips([{"type": "cidr", "value": "10.1.0.0/24"}])
    assert "10.1.0.1" in ips
    assert "10.1.0.254" in ips
    assert len(ips) == 254
    assert expand_probe_ips([{"type": "cidr", "value": "10.0.0.0/16"}]) == []
    assert expand_probe_ips([{"type": "ip", "value": "10.1.0.9"}]) == ["10.1.0.9"]


def test_expand_probe_ips_skips_ipv6_and_caps_without_materializing_hosts():
    from service_probe import expand_probe_ips

    assert expand_probe_ips([{"type": "cidr", "value": "2001:db8::/64"}]) == []
    assert expand_probe_ips([{"type": "cidr", "value": "2001:db8::/112"}]) == []
    capped = expand_probe_ips([{"type": "cidr", "value": "10.1.0.0/20"}], limit=16)
    assert capped == [f"10.1.{i // 256}.{i % 256}" for i in range(1, 17)]
    assert len(capped) == 16


def test_probe_tcp_services_reads_ssh_smb_rdp_banners():
    from service_probe import probe_tcp_services

    def fake_banner(ip, port, timeout=0.8):
        return "SSH-2.0-OpenSSH_9.2"

    with (
        patch("service_probe._tcp_banner", side_effect=fake_banner),
        patch("service_probe._smb_reply", return_value=True),
        patch("service_probe._rdp_reply", return_value=True),
    ):
        rows = probe_tcp_services("10.1.0.9", {22, 445, 3389})
    kinds = {row["tech"] for row in rows}
    assert kinds == {"ssh", "smb", "rdp"}
    assert any("OpenSSH" in row["title"] for row in rows)


def test_pipeline_keeps_udp_hosts_and_non_http_fingerprint():
    from unittest.mock import patch

    import runner as runtime_runner

    with (
        patch.object(runtime_runner, "discover_liveness", return_value=[]),
        patch.object(runtime_runner, "read_neighbor_table", return_value={}),
        patch.object(runtime_runner, "run_host_discovery", return_value=([{"ip": "10.1.0.8"}], None)),
        patch.object(runtime_runner, "run_naabu", return_value=([{"ip": "10.1.0.8", "port": 22}], None)),
        patch.object(runtime_runner, "run_httpx", return_value=([], None)),
        patch.object(
            runtime_runner,
            "discover_udp",
            return_value=[{"ip": "10.1.0.9", "port": 53, "tech": "dns", "title": "DNS"}],
        ),
        patch.object(
            runtime_runner,
            "fingerprint_non_http",
            return_value=[{"ip": "10.1.0.8", "port": 22, "tech": "ssh", "title": "OpenSSH_9.2"}],
        ),
        patch.object(runtime_runner, "collect_run_provenance", return_value={"runtime_version": "t"}),
    ):
        result = runtime_runner.run_pipeline(
            {
                "scope": "lan",
                "targets": [{"type": "cidr", "value": "10.1.0.0/24"}],
                "stages": {
                    "discovery": True,
                    "port_mode": "common",
                    "port_scope": "detected",
                    "fingerprint": True,
                    "vulnerability": False,
                },
                "intensity": {},
                "exclusions": [],
            }
        )
    by_ip = {row["ip"]: row for row in result["devices"]}
    assert 53 in by_ip["10.1.0.9"]["ports"]
    assert "ssh" in by_ip["10.1.0.8"]["tech"]
    assert "SSH" in by_ip["10.1.0.8"]["auto_label"]
