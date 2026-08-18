from __future__ import annotations

from ipaddress import ip_address


def is_ip(value: str) -> bool:
    try:
        ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def normalize_hostname(value: str) -> str:
    name = (value or "").strip().rstrip(".").lower()
    if name.startswith("*."):
        name = name[2:]
    return name


WEAK_HOSTNAMES = {
    "ui",
    "www",
    "ftp",
    "ssh",
    "vpn",
    "nas",
    "ap",
    "gw",
    "sw",
    "fw",
    "pc",
    "vm",
    "host",
    "device",
    "localhost",
    "local",
    "unifi",
    "router",
    "gateway",
    "switch",
}


def is_weak_hostname(hostname: str) -> bool:
    name = normalize_hostname(hostname)
    if not name or is_ip(name) or name in WEAK_HOSTNAMES:
        return True
    if name.startswith("*.") or name == "*":
        return True
    if "." not in name and len(name) <= 3:
        return True
    return False


def identity_name(hostname: str, ip: str) -> str:
    name = normalize_hostname(hostname)
    if name and not is_ip(name) and not is_weak_hostname(name):
        return name
    return (ip or "").strip() or generic_name(ip)


def is_placeholder_name(hostname: str, ip: str = "") -> bool:
    name = normalize_hostname(hostname)
    return not name or is_ip(name) or name.startswith("dev-") or (ip and name == ip.strip())


def generic_name(seed: str) -> str:
    token = "".join(ch for ch in (seed or "x") if ch.isalnum())[-6:] or "x"
    return f"dev-{token.lower()}"


def _portset(ports: list | None) -> set[int]:
    values = set()
    for port in ports or []:
        try:
            values.add(int(port))
        except (TypeError, ValueError):
            continue
    return values


def infer_class(hostname: str = "", ports: list | None = None, title: str = "", tech: str = "") -> str:
    blob = f"{hostname} {title} {tech}".lower()
    portset = _portset(ports)

    rules = [
        ("Server Management", ("idrac", "ilo", "irmc", "ipmi", "bmc", "xclarity", "imm2", "openbmc", "idrac/")),
        ("UPS", (" ups", "ups-", "apc ", "eaton", "cyberpower", "powerware", "tripplite", "network management card")),
        ("Print Server (non server)", ("printer", "print-server", "jetdirect", "cups", "laserjet", "officejet", "printers")),
        ("Access Point", ("access point", "access-point", "aironet", "unifi-ap", "aruba-ap", "wap-", "-ap-", "wap.")),
        ("Router / Firewall", ("firewall", "fortigate", "forti", "pfsense", "opnsense", "palo alto", "sophos", "asa-", "srx")),
        ("Router / Firewall", ("router", "gateway", "mikrotik", "edgeos", "edgerouter", "ubiquiti", "unifi security")),
        ("Switch", ("switch", "catalyst", "procurve", "netgear gs", "-sw-", "sw0")),
        ("Laptop", ("laptop", "notebook", "macbook", "thinkpad")),
        ("Desktop", ("desktop-", "desktop ", "workstation", "imac", "optiplex")),
        ("Virtual Host", ("esxi", "vmware esx", "hyper-v", "proxmox", "xenserver", "virtual host")),
        ("Virtual Server", ("vhost", "vm-", "-vm.", "virtual server")),
        ("IoT Device", ("camera", "cam-", "nvr", "tuya", "hue", "thermostat", "roku", "chromecast", "smartplug")),
        ("Server", ("server", "srv-", "-srv", "dc01", "ad01", "sql", "mbox", "domain controller")),
    ]
    for label, needles in rules:
        if any(n in blob for n in needles):
            return label

    windows = bool(portset & {135, 139, 445, 3389, 5985, 5986})
    directory = bool(portset & {88, 389, 636})
    mail = bool(portset & {25, 110, 143, 465, 587, 993, 995})
    name_service = 53 in portset

    if 623 in portset:
        return "Server Management"
    if 8006 in portset or (902 in portset and 443 in portset):
        return "Virtual Host"
    if 9100 in portset or 515 in portset or 631 in portset:
        return "Print Server (non server)"
    if portset & {554, 8554, 37777, 34567}:
        return "IoT Device"
    if portset & {8291, 8728, 8729}:
        return "Router / Firewall"
    if 161 in portset and 23 in portset:
        return "Switch"
    if directory or mail or name_service:
        return "Server"
    if windows and 3389 in portset and not (directory or mail or name_service):
        return "Desktop"
    if windows:
        return "Server"
    if 22 in portset and portset & {80, 443, 8000, 8080, 8443}:
        return "Server"
    if 22 in portset and len(portset) >= 3:
        return "Server"
    return "Unknown"


_JUNK_TITLE = (
    "redirecting",
    "moved permanently",
    "found",
    "403",
    "404",
    "401",
    "500",
    "just a moment",
    "attention required",
    "welcome to",
    "ui toolkit",
    "sign in",
    "log in",
    "login",
    "it works",
    "index of",
    "apache2",
    "default page",
)
_NOISE_TECH = {
    "bootstrap",
    "nprogress",
    "jquery",
    "font awesome",
    "fontawesome",
    "python",
    "uvicorn",
    "php",
}
_PRODUCTS = (
    ("Synology", ("synology", "diskstation", "dsm", "web station")),
    ("Fluidd", ("fluidd", "klipper", "mainsail")),
    ("UniFi", ("unifi", "ubiquiti")),
    ("iDRAC", ("idrac",)),
    ("iLO", ("ilo",)),
    ("Proxmox", ("proxmox",)),
    ("ESXi", ("esxi", "vmware esx")),
    ("pfSense", ("pfsense",)),
    ("OPNsense", ("opnsense",)),
)


def clean_title(title: str) -> str:
    text = " ".join((title or "").split())
    if not text:
        return ""
    low = text.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return ""
    if any(needle in low for needle in _JUNK_TITLE):
        return ""
    if len(text) > 32 or text.count(" ") > 3:
        return ""
    return text


def clean_tech(tech: str) -> str:
    seen: set[str] = set()
    kept: list[str] = []
    for part in (tech or "").split(","):
        raw = part.strip()
        if not raw:
            continue
        key = raw.split(":")[0].split("/")[0].strip().lower()
        if not key or key in _NOISE_TECH or key in seen:
            continue
        seen.add(key)
        kept.append(key)
        if len(kept) == 2:
            break
    return ", ".join(kept)


def product_hint(hostname: str = "", title: str = "", tech: str = "") -> str:
    blob = f"{hostname} {title} {tech}".lower()
    for label, needles in _PRODUCTS:
        if any(needle in blob for needle in needles):
            return label
    short = clean_title(title)
    if short and " " not in short:
        return short
    return ""


def infer_label(hostname: str = "", ports: list | None = None, title: str = "", tech: str = "") -> str:
    product = product_hint(hostname, title, tech)
    role_text = ", ".join(_service_roles(_portset(ports)))
    if product and role_text:
        return f"{product} · {role_text}"[:80]
    return (product or role_text)[:80]


def _service_roles(portset: set[int]) -> list[str]:
    roles: list[str] = []
    checks = [
        ("RDP", {3389}),
        ("SMB", {139, 445}),
        ("WinRPC", {135}),
        ("SSH", {22}),
        ("DNS", {53}),
        ("HTTP", {80, 8000, 8080, 8888}),
        ("HTTPS", {443, 8443, 9443}),
        ("Mail", {25, 110, 143, 465, 587, 993, 995}),
        ("LDAP", {389, 636}),
        ("Kerberos", {88}),
        ("SQL", {1433, 3306, 5432}),
        ("SNMP", {161}),
        ("IPMI", {623}),
        ("Printer", {515, 631, 9100}),
        ("NFS", {111, 2049}),
        ("VNC", {5900}),
        ("WinRM", {5985, 5986}),
    ]
    for name, needed in checks:
        if portset & needed:
            roles.append(name)
    return roles
