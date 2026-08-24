"""
KHMatrix - Shared utilities: target validation, cancellation, safe subprocess helpers.
"""
import ipaddress
import re
import socket
import threading
from urllib.parse import urlparse

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class CancellationToken:
    """Thread-safe cancellation flag checked periodically by scan workers."""

    def __init__(self):
        self._event = threading.Event()

    def cancel(self):
        self._event.set()

    def is_cancelled(self):
        return self._event.is_set()


def classify_target_type(target: str) -> str:
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        return "url"
    try:
        ipaddress.ip_network(target, strict=False)
        if "/" in target:
            return "cidr"
        return "ip"
    except ValueError:
        pass
    if HOSTNAME_RE.match(target):
        return "hostname"
    return "unknown"


def expand_target_hosts(target: str, target_type: str, max_hosts: int = 1024):
    """Return a list of individual IP strings for a target. Caps CIDR expansion for safety."""
    if target_type == "ip":
        return [target]
    if target_type == "cidr":
        net = ipaddress.ip_network(target, strict=False)
        hosts = [str(h) for h in net.hosts()]
        if len(hosts) > max_hosts:
            raise ValueError(
                f"CIDR range too large ({len(hosts)} hosts). Limit is {max_hosts} for a single scan job."
            )
        return hosts if hosts else [str(net.network_address)]
    if target_type == "hostname":
        try:
            resolved = socket.gethostbyname(target)
            return [resolved]
        except socket.gaierror as e:
            raise ValueError(f"DNS resolution failed for {target}: {e}")
    if target_type == "url":
        parsed = urlparse(target)
        return [parsed.hostname] if parsed.hostname else []
    raise ValueError(f"Unsupported target type: {target_type}")


def is_authorized_scope(target: str, target_type: str, authorized_assets: list) -> bool:
    """
    Verify the requested target falls within an explicitly authorized asset entry.
    Only exact-match or containment (CIDR) against stored, operator-confirmed assets is allowed.
    """
    for asset in authorized_assets:
        if not asset.get("authorized"):
            continue
        stored = asset["target"].strip()
        if stored == target:
            return True
        try:
            if asset["target_type"] == "cidr" and target_type in ("ip", "hostname"):
                net = ipaddress.ip_network(stored, strict=False)
                ip_to_check = target
                if target_type == "hostname":
                    try:
                        ip_to_check = socket.gethostbyname(target)
                    except socket.gaierror:
                        continue
                if ipaddress.ip_address(ip_to_check) in net:
                    return True
        except ValueError:
            continue
        if asset["target_type"] == "url" and target_type == "url":
            if urlparse(stored).netloc == urlparse(target).netloc:
                return True
    return False


def safe_join_evidence(*parts):
    return " | ".join([p for p in parts if p])
