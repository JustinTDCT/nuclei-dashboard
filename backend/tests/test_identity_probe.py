from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

BACKEND_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = BACKEND_ROOT.parent / "scan_runtime"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))


def test_mac_normalize_and_oui_vendor():
    from oui import normalize_mac, vendor_for_mac

    assert normalize_mac("00000C123456") == "00:00:0c:12:34:56"
    assert vendor_for_mac("00:00:0c:12:34:56") == "Cisco"
    assert vendor_for_mac("00-50-56-aa-bb-cc") == "VMware"
    assert vendor_for_mac("ff:ff:ff:ff:ff:ff") == ""
    assert normalize_mac("short") == ""


def test_arp_table_keeps_complete_entries_only():
    from identity_probe import read_neighbor_table

    text = (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "10.1.0.1         0x1         0x2         00:00:0c:aa:bb:cc     *        eth0\n"
        "10.1.0.2         0x1         0x0         00:00:00:00:00:00     *        eth0\n"
        "10.1.0.3         0x1         0x2         00:50:56:11:22:33     *        eth0\n"
    )
    neighbors = read_neighbor_table(text)
    assert neighbors == {
        "10.1.0.1": "00:00:0c:aa:bb:cc",
        "10.1.0.3": "00:50:56:11:22:33",
    }


def test_snmp_sysdescr_reads_octet_string():
    from service_probe import _snmp_sysdescr

    descr = b"Cisco IOS Software, C2960"
    payload = b"\x30\x20\x04" + bytes([len(descr)]) + descr + b"\x04\x06public"
    assert "Cisco IOS" in _snmp_sysdescr(payload)


def test_icmp_checksum_is_ones_complement():
    from identity_probe import _echo_request, _icmp_checksum

    packet = _echo_request(0x1234, 1)
    assert packet[0] == 8
    assert _icmp_checksum(packet) == 0


def test_classify_uses_snmp_sysdescr():
    from classify import infer_class

    assert infer_class(title="Cisco IOS Software, C2960", tech="snmp") == "Switch"
    assert infer_class(title="HP LaserJet 400", tech="Hewlett Packard") == "Print Server (non server)"


def test_pipeline_attaches_mac_without_credentials():
    import runner as runtime_runner

    with (
        patch.object(
            runtime_runner,
            "discover_liveness",
            return_value=[{"ip": "10.1.0.8", "mac": "00:00:0c:aa:bb:cc", "vendor": "Cisco", "title": "Cisco"}],
        ),
        patch.object(runtime_runner, "read_neighbor_table", return_value={}),
        patch.object(runtime_runner, "run_host_discovery", return_value=([{"ip": "10.1.0.8"}], None)),
        patch.object(runtime_runner, "run_naabu", return_value=([{"ip": "10.1.0.8", "port": 22}], None)),
        patch.object(runtime_runner, "run_httpx", return_value=([], None)),
        patch.object(runtime_runner, "discover_udp", return_value=[]),
        patch.object(runtime_runner, "fingerprint_non_http", return_value=[]),
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
    device = result["devices"][0]
    assert device["mac"] == "00:00:0c:aa:bb:cc"
    assert "cisco" in device["tech"].lower()
    assert "password" not in str(result).lower()
    assert "credential" not in str(result).lower()
