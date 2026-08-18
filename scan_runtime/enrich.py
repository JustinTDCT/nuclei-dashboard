from __future__ import annotations

import socket
import ssl
import struct
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address
from typing import Callable

from classify import is_ip, is_weak_hostname, normalize_hostname
from cryptography import x509
from cryptography.hazmat.backends import default_backend

LogFn = Callable[[str], None]

TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443, 4443, 10443, 8834, 4343}
SKIP_NAMES = {"localhost", "localhost.localdomain", "local", "invalid", "example.com"}


def usable_hostname(value: str) -> str:
    raw = (value or "").strip().rstrip(".").lower()
    if raw.startswith("*.") or raw == "*":
        return ""
    name = normalize_hostname(value)
    if not name or is_ip(name) or name in SKIP_NAMES or " " in name or is_weak_hostname(name):
        return ""
    if name.endswith(".invalid") or name.endswith(".example"):
        return ""
    return name


def enrich_identities(devices: list[dict], log: LogFn | None = None) -> None:
    missing = [d for d in devices if d.get("ip") and not usable_hostname(d.get("hostname") or "")]
    if not missing:
        return
    if log:
        log(f"Enriching names for {len(missing)} hosts (NetBIOS, mDNS, TLS)")

    def resolve(device: dict) -> tuple[str, str]:
        ip = device.get("ip") or ""
        name = (
            netbios_name(ip)
            or mdns_name(ip)
            or llmnr_name(ip)
            or tls_hostname(ip, device.get("ports") or [])
        )
        return ip, name

    found: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=16) as pool:
        for ip, name in pool.map(resolve, missing):
            if name:
                found[ip] = name
    for device in devices:
        if usable_hostname(device.get("hostname") or ""):
            continue
        device["hostname"] = found.get(device.get("ip") or "", device.get("hostname") or "")


def netbios_name(ip: str, timeout: float = 1.2) -> str:
    packet = bytes.fromhex(
        "12840000000100000000000020434b41414141414141414141414141414141"
        "4141414141414141414141414141410000210001"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return ""
    finally:
        sock.close()
    if len(data) < 58:
        return ""
    count = data[56]
    offset = 57
    for _ in range(count):
        if offset + 18 > len(data):
            break
        raw = data[offset : offset + 15].decode("ascii", "ignore").strip(" \x00")
        suffix = data[offset + 15]
        flags = int.from_bytes(data[offset + 16 : offset + 18], "big")
        offset += 18
        if suffix == 0x00 and not flags & 0x8000:
            name = usable_hostname(raw)
            if name:
                return name
    return ""


def mdns_name(ip: str, timeout: float = 1.0) -> str:
    try:
        ptr = ip_address(ip).reverse_pointer.encode()
    except ValueError:
        return ""
    query = _dns_ptr_query(ptr)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.sendto(query, ("224.0.0.251", 5353))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return ""
    finally:
        sock.close()
    return _dns_ptr_answer(data)


def llmnr_name(ip: str, timeout: float = 1.0) -> str:
    try:
        ptr = ip_address(ip).reverse_pointer.encode()
    except ValueError:
        return ""
    query = _dns_ptr_query(ptr)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(query, ("224.0.0.252", 5355))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return ""
    finally:
        sock.close()
    return _dns_ptr_answer(data)


def tls_hostname(ip: str, ports: list) -> str:
    candidates = []
    for port in ports:
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            continue
        if port_i in TLS_PORTS or port_i in {443, 8443}:
            candidates.append(port_i)
    for port in candidates[:4]:
        name = _tls_name(ip, port)
        if name:
            return name
    return ""


def _tls_name(ip: str, port: int, timeout: float = 2.0) -> str:
    ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except OSError:
        return ""
    if not der:
        return ""
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except ValueError:
        return ""
    names: list[str] = []
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        names.extend(attr.value for attr in cn if isinstance(attr.value, str))
    except Exception:
        pass
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names.extend(ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        pass
    for raw in names:
        name = usable_hostname(str(raw))
        if name:
            return name
    return ""


def _dns_ptr_query(qname: bytes) -> bytes:
    header = struct.pack("!HHHHHH", 0x1200, 0x0100, 1, 0, 0, 0)
    parts = b""
    for label in qname.split(b"."):
        parts += bytes([len(label)]) + label
    parts += b"\x00\x00\x0c\x00\x01"
    return header + parts


def _dns_ptr_answer(data: bytes) -> str:
    if len(data) < 12:
        return ""
    answers = int.from_bytes(data[6:8], "big")
    offset = 12
    try:
        offset = _skip_name(data, offset) + 4
        for _ in range(answers):
            offset = _skip_name(data, offset)
            if offset + 10 > len(data):
                return ""
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            rdata = data[offset : offset + rdlen]
            offset += rdlen
            if rtype == 12:
                name = _decode_name(data, offset - rdlen)
                return usable_hostname(name)
    except Exception:
        return ""
    return ""


def _skip_name(data: bytes, offset: int) -> int:
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def _decode_name(data: bytes, offset: int) -> str:
    labels = []
    jumped = False
    seen = 0
    while offset < len(data) and seen < 20:
        length = data[offset]
        if length == 0:
            break
        if length & 0xC0:
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                jumped = True
            seen += 1
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", "ignore"))
        offset += length
        seen += 1
    return ".".join(labels)
