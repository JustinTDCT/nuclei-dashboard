"""Unauthenticated host identity: ICMP, ARP/MAC, OUI vendor.

No client credentials are used or stored. SNMP community ``public`` is a
well-known default probe (same as RapidFire's LAN Scan default), not a
stored secret. WMI, WinRM, SSH login, and SNMPv3 stay out of this path.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import time
from typing import Any, Callable

from oui import normalize_mac, vendor_for_mac
from service_probe import expand_probe_ips

LogFn = Callable[[str], None]

ICMP_TIMEOUT = 0.55
ARP_PATH = "/proc/net/arp"
ZERO_MAC = "00:00:00:00:00:00"


def discover_liveness(targets: list[dict[str, str]], log: LogFn | None = None) -> list[dict[str, Any]]:
    """Find live hosts and attach MAC/vendor without logging in."""
    ips = expand_probe_ips(targets)
    if not ips:
        return []
    if log:
        log(f"Identity sweep on {len(ips)} address(es) (ICMP + ARP/MAC, no credentials)")
    alive = icmp_sweep(ips)
    neighbors = read_neighbor_table()
    found: dict[str, dict[str, Any]] = {}
    for ip in alive:
        found[ip] = _identity_row(ip, mac=neighbors.get(ip, ""), via="icmp")
    for ip, mac in neighbors.items():
        if ip not in found and ip in set(ips):
            found[ip] = _identity_row(ip, mac=mac, via="arp")
        elif ip in found and mac:
            found[ip]["mac"] = mac
            vendor = vendor_for_mac(mac)
            if vendor:
                found[ip]["vendor"] = vendor
                found[ip]["title"] = found[ip].get("title") or vendor
    rows = list(found.values())
    if log:
        named = sum(1 for row in rows if row.get("mac"))
        log(f"Identity sweep found {len(rows)} live host(s), {named} with MAC")
    return rows


def icmp_sweep(ips: list[str], timeout: float = ICMP_TIMEOUT) -> set[str]:
    if not ips:
        return set()
    sock = _open_icmp_socket()
    if sock is None:
        return set()
    ident = os.getpid() & 0xFFFF
    allowed = {_canonical_ip(ip) for ip in ips}
    sent_seqs: set[int] = set()
    alive: set[str] = set()
    try:
        sock.settimeout(0.05)
        for seq, ip in enumerate(ips):
            seq &= 0xFFFF
            packet = _echo_request(ident, seq)
            try:
                sock.sendto(packet, (ip, 0))
            except OSError:
                continue
            sent_seqs.add(seq)
        deadline = time.monotonic() + timeout + min(0.4, 0.001 * len(ips))
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            host = _canonical_ip(addr[0]) if addr else ""
            if host not in allowed:
                continue
            if _is_our_echo_reply(data, ident, sent_seqs):
                alive.add(host)
    finally:
        sock.close()
    return alive


def read_neighbor_table(text: str | None = None) -> dict[str, str]:
    """Parse kernel ARP / neighbor entries. Incomplete rows are dropped."""
    if text is None:
        try:
            text = open(ARP_PATH, encoding="utf-8").read()
        except OSError:
            return {}
    neighbors: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        ip, _hw, flags, mac = parts[0], parts[1], parts[2], parts[3]
        try:
            flag_value = int(flags, 0)
        except ValueError:
            flag_value = 0
        if flag_value & 0x02 == 0:
            continue
        normalized = normalize_mac(mac)
        if not normalized or normalized == ZERO_MAC:
            continue
        neighbors[ip] = normalized
    return neighbors


def _identity_row(ip: str, *, mac: str, via: str) -> dict[str, Any]:
    mac = normalize_mac(mac)
    vendor = vendor_for_mac(mac) if mac else ""
    row: dict[str, Any] = {
        "ip": ip,
        "tech": vendor,
        "title": vendor,
        "mac": mac,
        "vendor": vendor,
        "discovery": True,
        "via": via,
    }
    return row


def _open_icmp_socket() -> socket.socket | None:
    """Prefer unprivileged ICMP datagrams; fall back to NET_RAW."""
    for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
        try:
            sock = socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
        except OSError:
            continue
        return sock
    return None


def _echo_request(ident: int, seq: int) -> bytes:
    header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    checksum = _icmp_checksum(header)
    return struct.pack("!BBHHH", 8, 0, checksum, ident, seq)


def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _canonical_ip(host: str) -> str:
    text = str(host or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text.split("%", 1)[0]))
    except ValueError:
        return text


def _icmp_header_offset(data: bytes) -> int | None:
    if len(data) < 8:
        return None
    # Linux raw sockets prepend the IPv4 header; SOCK_DGRAM does not.
    if len(data) >= 20 and (data[0] >> 4) == 4:
        offset = (data[0] & 0x0F) * 4
        if offset + 8 > len(data):
            return None
        return offset
    return 0


def _is_our_echo_reply(data: bytes, ident: int, sent_seqs: set[int]) -> bool:
    offset = _icmp_header_offset(data)
    if offset is None or data[offset] != 0:
        return False
    reply_ident, reply_seq = struct.unpack_from("!HH", data, offset + 4)
    return reply_ident == ident and reply_seq in sent_seqs
