"""
KHMatrix - Asset & Service Discovery Engine

Wraps nmap using argument arrays only (never shell=True, never string-built commands).
Performs non-destructive discovery: host sweep + version detection (-sV).
No exploitation scripts (--script vuln/exploit categories are explicitly excluded).
"""
import shutil
import subprocess
import xml.etree.ElementTree as ET
from .utils import CancellationToken

NMAP_BIN = shutil.which("nmap")

# Default, conservative port set. Kept intentionally scoped rather than -p-.
DEFAULT_PORTS = (
    "21,22,23,25,53,80,81,110,111,135,139,143,161,179,389,443,445,465,554,587,631,"
    "993,995,1723,3306,3389,5000,5432,5900,5985,6379,7547,8000,8008,8080,8081,8443,"
    "8888,9000,9100,9200,10000,27017"
)


def nmap_available():
    return NMAP_BIN is not None


def run_host_discovery(ip: str, cancel: CancellationToken, timeout=15):
    """Ping-style host discovery for a single IP. Returns True if host appears up."""
    if cancel.is_cancelled() or not NMAP_BIN:
        return False
    try:
        proc = subprocess.run(
            [NMAP_BIN, "-sn", "-n", "-T4", "--max-retries", "1", "-oX", "-", ip],
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            return False
        root = ET.fromstring(proc.stdout)
        host = root.find("host")
        if host is None:
            return False
        status = host.find("status")
        return status is not None and status.get("state") == "up"
    except (subprocess.TimeoutExpired, ET.ParseError, FileNotFoundError):
        return False


def run_service_scan(ip: str, cancel: CancellationToken, ports: str = DEFAULT_PORTS, timeout=180):
    """
    Run an authorized, non-destructive service/version scan against a single host.
    Returns a dict: {ip, mac, hostname, vendor, os_indicator, ports: [ {port, protocol, state,
    service, product, version, banner} ]}
    """
    result = {"ip": ip, "mac": None, "hostname": None, "vendor": None, "os_indicator": None, "ports": []}
    if cancel.is_cancelled():
        return result
    if not NMAP_BIN:
        result["os_indicator"] = "UNKNOWN (nmap not installed on this host)"
        return result

    cmd = [
        NMAP_BIN, "-sV", "--version-light", "-T4", "-Pn", "-n",
        "--max-retries", "1", "--host-timeout", "120s",
        "-p", ports, "-oX", "-", ip,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        result["os_indicator"] = "SCAN TIMEOUT"
        return result

    if cancel.is_cancelled():
        return result

    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError:
        return result

    host_el = root.find("host")
    if host_el is None:
        return result

    for addr in host_el.findall("address"):
        addrtype = addr.get("addrtype")
        if addrtype == "mac":
            result["mac"] = addr.get("addr")
            result["vendor"] = addr.get("vendor")
        elif addrtype in ("ipv4", "ipv6"):
            result["ip"] = addr.get("addr") or result["ip"]

    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        hn = hostnames_el.find("hostname")
        if hn is not None:
            result["hostname"] = hn.get("name")

    os_el = host_el.find("os")
    if os_el is not None:
        match = os_el.find("osmatch")
        if match is not None:
            result["os_indicator"] = f"{match.get('name')} (accuracy {match.get('accuracy')}%)"

    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            if cancel.is_cancelled():
                break
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"
            if state != "open":
                continue
            service_el = port_el.find("service")
            service = product = version = banner = None
            if service_el is not None:
                service = service_el.get("name")
                product = service_el.get("product")
                version = service_el.get("version")
                extrainfo = service_el.get("extrainfo")
                banner = " ".join([p for p in [product, version, extrainfo] if p]) or None
            result["ports"].append({
                "port": int(port_el.get("portid")),
                "protocol": port_el.get("protocol"),
                "state": state,
                "service": service,
                "product": product,
                "version": version,
                "banner": banner,
            })

    return result
