"""
KHMatrix - Device Classification Engine

Classifies a discovered host using observable, non-invasive signals only:
open ports, service/product banners, and MAC vendor OUI text. Never invents
information; if signals are ambiguous, reports UNKNOWN with LOW confidence.
"""

# (device_type, required-signal weight rules)
RULES = [
    ("CAMERA", {"ports": [554, 8554], "services": ["rtsp"], "products": ["camera", "hikvision", "dahua", "ipcam", "axis"]}),
    ("PRINTER", {"ports": [9100, 631, 515], "services": ["ipp", "printer", "jetdirect"], "products": ["printer", "jetdirect", "cups"]}),
    ("NAS", {"ports": [139, 445, 2049, 5000, 5001], "services": ["smb", "nfs", "microsoft-ds"], "products": ["synology", "qnap", "netgear readynas", "truenas"]}),
    ("ROUTER", {"ports": [23, 80, 443, 7547, 179], "services": ["tr069", "http", "telnet"], "products": ["router", "mikrotik", "ubiquiti", "openwrt", "dd-wrt", "cisco ios", "asus"]}),
    ("SWITCH", {"ports": [22, 23, 161, 80], "services": ["snmp", "telnet", "ssh"], "products": ["catalyst", "procurve", "juniper", "netgear switch"]}),
    ("WEB_SERVER", {"ports": [80, 443, 8080, 8443], "services": ["http", "https", "http-proxy"], "products": ["apache", "nginx", "iis", "caddy", "lighttpd"]}),
    ("SERVER", {"ports": [22, 3389, 445, 5985, 111], "services": ["ssh", "rdp", "ms-wbt-server", "smb", "rpcbind"], "products": ["windows server", "ubuntu", "centos", "debian", "red hat"]}),
    ("MOBILE_OR_IOT", {"ports": [], "services": ["mdns", "upnp"], "products": ["android", "ios", "espressif", "iot"]}),
    ("PC", {"ports": [135, 139, 445, 3389], "services": ["netbios-ssn", "microsoft-ds", "ms-wbt-server"], "products": ["windows"]}),
]


def classify_host(host: dict) -> dict:
    """
    host: {ip, mac, hostname, vendor, os_indicator, ports:[{port, service, product, banner}]}
    Returns {device_type, confidence, signals: [...]}.
    """
    open_ports = {p["port"] for p in host.get("ports", [])}
    services = {(p.get("service") or "").lower() for p in host.get("ports", [])}
    products_text = " ".join(
        f"{p.get('product') or ''} {p.get('banner') or ''}".lower() for p in host.get("ports", [])
    )
    vendor_text = (host.get("vendor") or "").lower()
    os_text = (host.get("os_indicator") or "").lower()

    scores = {}
    signals = {}
    for device_type, sig in RULES:
        score = 0
        matched = []
        for port in sig["ports"]:
            if port in open_ports:
                score += 1
                matched.append(f"port {port} open")
        for svc in sig["services"]:
            if svc in services:
                score += 2
                matched.append(f"service '{svc}' detected")
        for prod in sig["products"]:
            if prod in products_text or prod in vendor_text or prod in os_text:
                score += 3
                matched.append(f"product/vendor string matched '{prod}'")
        if score > 0:
            scores[device_type] = score
            signals[device_type] = matched

    if not scores:
        return {"device_type": "UNKNOWN", "confidence": "LOW", "signals": []}

    best = max(scores, key=scores.get)
    best_score = scores[best]

    # Confidence banding - deliberately conservative.
    if best_score >= 5:
        confidence = "HIGH"
    elif best_score >= 3:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # If top two candidates are tied, drop confidence and flag ambiguity.
    sorted_scores = sorted(scores.values(), reverse=True)
    if len(sorted_scores) > 1 and sorted_scores[0] == sorted_scores[1]:
        confidence = "LOW"

    return {"device_type": best, "confidence": confidence, "signals": signals[best]}
