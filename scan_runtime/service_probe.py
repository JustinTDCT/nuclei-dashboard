"""Unprivileged LAN service discovery: UDP apps and non-HTTP TCP banners.

These probes use ordinary sockets. They do not need root or stored credentials.
SNMP uses the well-known community ``public`` as a probe, not a saved secret.
Naabu -sn is not used.
"""

from __future__ import annotations

import ipaddress
import itertools
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from enrich import netbios_name

LogFn = Callable[[str], None]

UDP_TIMEOUT = 0.45
TCP_TIMEOUT = 0.8
MAX_UDP_HOSTS = 4096
UDP_WORKERS = 80
TCP_WORKERS = 32

# SNMPv1 GET public sysDescr.0
_SNMP_GET = bytes.fromhex(
    "302602010004067075626c6963a01902041a2b3c4d0201000201003011300f06052b060102010500"
)
_DNS_QUERY = bytes.fromhex("1200010000010000000000000000010001")
_RDP_X224 = bytes.fromhex("030000130ee000000000000100080003000000")
_SMB_NEGOTIATE = (
    b"\x00\x00\x00\x45"
    b"\xffSMB"
    b"\x72\x00\x00\x00\x00\x18\x01\x48\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x02NT LM 0.12\x00"
)


def expand_probe_ips(targets: list[dict[str, str]], *, limit: int = MAX_UDP_HOSTS) -> list[str]:
    ips: list[str] = []
    seen: set[str] = set()
    for row in targets:
        kind = row.get("type") or "cidr"
        value = str(row.get("value") or "").strip()
        if not value:
            continue
        if kind == "fqdn":
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if network.version != 4 or network.prefixlen < 20:
            continue
        remaining = limit - len(ips)
        if remaining <= 0:
            return ips
        stream = (
            [network.network_address]
            if network.num_addresses == 1
            else itertools.islice(network.hosts(), remaining)
        )
        for item in stream:
            ip = str(item)
            if ip in seen:
                continue
            seen.add(ip)
            ips.append(ip)
            if len(ips) >= limit:
                return ips
    return ips


def discover_udp(targets: list[dict[str, str]], log: LogFn | None = None) -> list[dict[str, Any]]:
    ips = expand_probe_ips(targets)
    if not ips:
        return []
    if log:
        log(f"UDP discovery on {len(ips)} address(es) (DNS/SNMP/NetBIOS/mDNS)")
    found: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=UDP_WORKERS) as pool:
        for rows in pool.map(probe_udp_host, ips):
            found.extend(rows)
    if log:
        hosts = {row["ip"] for row in found}
        log(f"UDP discovery found {len(hosts)} host(s), {len(found)} service(s)")
    return found


def fingerprint_non_http(hosts: list[tuple[str, set[int] | list[int]]], log: LogFn | None = None) -> list[dict[str, Any]]:
    work = [(ip, set(int(p) for p in ports if str(p).isdigit() or isinstance(p, int))) for ip, ports in hosts if ip]
    if not work:
        return []
    if log:
        log(f"Fingerprinting non-HTTP services on {len(work)} host(s)")
    found: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as pool:
        for rows in pool.map(lambda item: probe_tcp_services(item[0], item[1]), work):
            found.extend(rows)
    return found


def probe_udp_host(ip: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if _udp_exchange(ip, 53, _DNS_QUERY):
        rows.append({"ip": ip, "port": 53, "tech": "dns", "title": "DNS"})
    snmp = _snmp_identity(ip)
    if snmp:
        rows.append(snmp)
    nb_name = netbios_name(ip, timeout=UDP_TIMEOUT)
    if nb_name or _udp_exchange(ip, 137, _netbios_stat()):
        row = {"ip": ip, "port": 137, "tech": "netbios", "title": "NetBIOS-NS"}
        if nb_name:
            row["hostname"] = nb_name
        rows.append(row)
    if _udp_exchange(ip, 5353, _DNS_QUERY):
        rows.append({"ip": ip, "port": 5353, "tech": "mdns", "title": "mDNS"})
    return rows


def probe_tcp_services(ip: str, ports: set[int]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if 22 in ports:
        banner = _tcp_banner(ip, 22)
        if banner.startswith("SSH-"):
            product = banner.split()[0].replace("SSH-2.0-", "").replace("SSH-1.99-", "")
            rows.append({"ip": ip, "port": 22, "tech": "ssh", "title": product or "SSH"})
    if ports & {139, 445}:
        port = 445 if 445 in ports else 139
        if _smb_reply(ip, port):
            rows.append({"ip": ip, "port": port, "tech": "smb", "title": "SMB"})
    if 3389 in ports and _rdp_reply(ip):
        rows.append({"ip": ip, "port": 3389, "tech": "rdp", "title": "RDP"})
    return rows


def _netbios_stat() -> bytes:
    return bytes.fromhex(
        "12840000000100000000000020434b41414141414141414141414141414141"
        "4141414141414141414141414141410000210001"
    )


def _snmp_identity(ip: str) -> dict[str, Any] | None:
    """SNMPv1 GET sysDescr with community public. Not a stored credential."""
    data = _udp_payload(ip, 161, _SNMP_GET)
    if not data:
        return None
    descr = _snmp_sysdescr(data)
    row: dict[str, Any] = {"ip": ip, "port": 161, "tech": "snmp", "title": descr or "SNMP"}
    return row


def _snmp_sysdescr(data: bytes) -> str:
    """Pull the first printable OCTET STRING from an SNMPv1 response."""
    i = 0
    best = ""
    while i < len(data) - 2:
        if data[i] == 0x04:
            length = data[i + 1]
            if length < 0x80 and i + 2 + length <= len(data):
                raw = data[i + 2 : i + 2 + length]
                if raw and all(32 <= byte < 127 or byte in {9, 10, 13} for byte in raw):
                    text = raw.decode("ascii", "ignore").strip()
                    if len(text) >= 4 and len(text) > len(best):
                        best = text
                i += 2 + length
                continue
        i += 1
    return best[:200]


def _udp_payload(ip: str, port: int, payload: bytes, timeout: float = UDP_TIMEOUT) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(payload, (ip, port))
        data, _ = sock.recvfrom(4096)
        return data or b""
    except OSError:
        return b""
    finally:
        sock.close()


def _udp_exchange(ip: str, port: int, payload: bytes, timeout: float = UDP_TIMEOUT) -> bool:
    return bool(_udp_payload(ip, port, payload, timeout=timeout))


def _tcp_banner(ip: str, port: int, timeout: float = TCP_TIMEOUT) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(128)
    except OSError:
        return ""
    return data.decode("ascii", "ignore").strip()


def _smb_reply(ip: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_SMB_NEGOTIATE)
            data = sock.recv(64)
    except OSError:
        return False
    return data[4:8] in {b"\xffSMB", b"\xfeSMB"} if len(data) >= 8 else False


def _rdp_reply(ip: str, timeout: float = TCP_TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, 3389), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_RDP_X224)
            data = sock.recv(32)
    except OSError:
        return False
    return data.startswith(b"\x03\x00")
