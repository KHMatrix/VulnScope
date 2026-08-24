"""
KHMatrix - Vulnerability Correlation Engine

Two correlation paths, each explicitly labeled with a confidence level:

1. CONFIGURATION FINDINGS (confidence: CONFIRMED BY SAFE CHECK)
   Derived directly from observed, non-destructive scan data (e.g. Telnet is open,
   a security header is absent, a TLS certificate is expired). These require no
   external database and are as reliable as the scan data itself.

2. CVE CORRELATION (confidence: VERSION MATCH / POTENTIAL / MANUAL VERIFICATION REQUIRED)
   Queries the public NVD REST API live for the detected product/version. KHMatrix does
   NOT ship a hard-coded CVE database, because a hard-coded list would silently go stale
   and risks misattributing CVE IDs. If NVD is unreachable, every affected finding is
   explicitly marked MANUAL VERIFICATION REQUIRED rather than guessed.
"""
import time
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_last_nvd_call = [0.0]
_MIN_INTERVAL = 6.5  # public NVD rate limit is ~5 req / 30s without an API key


def _rate_limit():
    elapsed = time.time() - _last_nvd_call[0]
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_nvd_call[0] = time.time()


def query_nvd(product: str, version: str, timeout=10, max_results=5):
    """
    Live keyword search against NVD for a product+version string.
    Returns a list of {cve_id, description, cvss, severity, references, confidence}.
    Never fabricates CVE IDs; returns [] plus an 'unavailable' flag on any failure.
    """
    if not product:
        return {"results": [], "unavailable": False}
    keyword = f"{product} {version}".strip()
    try:
        _rate_limit()
        resp = requests.get(
            NVD_API,
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            timeout=timeout,
            headers={"User-Agent": "KHMatrix-Auditor/1.0"},
        )
        if resp.status_code != 200:
            return {"results": [], "unavailable": True}
        data = resp.json()
    except (requests.RequestException, ValueError):
        return {"results": [], "unavailable": True}

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        cvss = None
        severity = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0]["cvssData"]
                cvss = cvss_data.get("baseScore")
                severity = metrics[key][0].get("baseSeverity") or cvss_data.get("baseSeverity")
                break
        refs = [r.get("url") for r in cve.get("references", [])][:3]

        # Version string textually present in the CVE description -> higher confidence.
        confidence = "VERSION MATCH" if version and version.lower() in desc.lower() else "POTENTIAL"

        results.append({
            "cve_id": cve_id,
            "description": desc[:500],
            "cvss": cvss,
            "severity": severity,
            "references": refs,
            "confidence": confidence,
        })
    return {"results": results, "unavailable": False}


def severity_from_cvss(cvss):
    if cvss is None:
        return "INFO"
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    if cvss > 0:
        return "LOW"
    return "INFO"


# ---------------- Configuration-based findings (no external lookup needed) ----------------

INSECURE_SERVICES = {
    "telnet": ("Telnet service exposed", "HIGH",
               "Telnet transmits credentials and session data in cleartext.",
               "Credential Exposure Risk / Information Disclosure",
               "CWE-319"),
    "ftp": ("FTP service exposed", "MEDIUM",
            "Legacy FTP transmits credentials and data in cleartext unless FTPS is enforced.",
            "Credential Exposure Risk",
            "CWE-319"),
    "rsh": ("Legacy remote shell service exposed", "HIGH",
            "rsh/rlogin-family services use weak, spoofable trust-based authentication.",
            "Unauthorized Access Risk",
            "CWE-287"),
    "snmp": ("SNMP service exposed", "MEDIUM",
             "SNMP v1/v2c uses cleartext community strings and is often left at default values.",
             "Information Disclosure / Configuration Exposure",
             "CWE-287"),
    "vnc": ("VNC remote-access service exposed", "HIGH",
            "VNC is frequently deployed with weak or no authentication and exposes a full desktop session.",
            "Unauthorized Access Risk",
            "CWE-306"),
}


def config_findings_for_host(host: dict):
    """Findings derivable purely from observed open ports/services - CONFIRMED BY SAFE CHECK."""
    findings = []
    for svc in host.get("ports", []):
        name = (svc.get("service") or "").lower()
        for key, (title, severity, desc, impact, cwe) in INSECURE_SERVICES.items():
            if key in name:
                findings.append({
                    "title": title,
                    "severity": severity,
                    "confidence": "CONFIRMED BY SAFE CHECK",
                    "port": svc.get("port"),
                    "protocol": svc.get("protocol"),
                    "service": svc.get("service"),
                    "product": svc.get("product"),
                    "version": svc.get("version"),
                    "description": desc,
                    "evidence": f"Port {svc.get('port')}/{svc.get('protocol')} identified as '{name}' "
                                f"({svc.get('banner') or 'no banner captured'})",
                    "security_impact": impact,
                    "cwe": cwe,
                    "cve": None,
                    "cvss": None,
                    "remediation_immediate": f"Restrict network access to the {name} service via firewall rules "
                                              "to only explicitly trusted management hosts.",
                    "remediation_permanent": f"Disable {name} and replace it with an encrypted, modern equivalent "
                                              "(e.g. SSH instead of Telnet, SFTP/FTPS instead of FTP, SNMPv3 instead of v1/v2c).",
                    "verification": f"Re-scan the host and confirm port {svc.get('port')} is closed or no longer "
                                     f"reports the {name} service; confirm the replacement service enforces encryption.",
                })
    return findings


def web_findings_for_site(site: dict):
    """Findings derivable purely from observed HTTP response data - CONFIRMED BY SAFE CHECK."""
    findings = []
    headers_data = site.get("_headers_result") or {}
    missing = headers_data.get("missing_security_headers", [])
    if missing:
        findings.append({
            "title": "Missing security headers",
            "severity": "LOW" if len(missing) <= 2 else "MEDIUM",
            "confidence": "CONFIRMED BY SAFE CHECK",
            "url": site.get("url"),
            "description": f"The response does not set the following recommended security headers: {', '.join(missing)}.",
            "evidence": f"Observed response headers: {list((headers_data.get('headers') or {}).keys())}",
            "security_impact": "Configuration Exposure / weakened browser-side defenses (clickjacking, MIME sniffing, XSS blast radius)",
            "cwe": "CWE-693",
            "remediation_immediate": "Add the missing headers at the reverse proxy / load balancer layer if an application change is not immediately possible.",
            "remediation_permanent": "Configure the application or web server to set: " + ", ".join(missing) + " with appropriate policy values.",
            "verification": "Re-request the page and confirm each header is present with an appropriately restrictive value.",
        })

    for cookie in headers_data.get("cookies", []):
        issues = []
        if not cookie.get("secure"):
            issues.append("missing Secure flag")
        if not cookie.get("httponly"):
            issues.append("missing HttpOnly flag")
        if not cookie.get("samesite"):
            issues.append("missing/weak SameSite attribute")
        if issues:
            findings.append({
                "title": f"Cookie '{cookie['name']}' has weak attributes",
                "severity": "MEDIUM",
                "confidence": "CONFIRMED BY SAFE CHECK",
                "url": site.get("url"),
                "description": f"Cookie '{cookie['name']}' is {', '.join(issues)}.",
                "evidence": f"Observed cookie attributes: {cookie}",
                "security_impact": "Credential Exposure Risk / Session hijacking exposure over insecure channels or via script access",
                "cwe": "CWE-614" if "missing Secure flag" in issues else "CWE-1004",
                "remediation_immediate": "Set Secure, HttpOnly, and SameSite=Strict/Lax on session and auth cookies.",
                "remediation_permanent": "Update the application's cookie/session configuration to enforce these attributes by default.",
                "verification": "Inspect Set-Cookie headers in a fresh response and confirm all three attributes are present.",
            })

    tls = site.get("_tls_result")
    if tls and not tls.get("error"):
        days_left = tls.get("days_until_expiry")
        if days_left is not None and days_left < 30:
            findings.append({
                "title": "TLS certificate nearing expiration" if days_left > 0 else "TLS certificate expired",
                "severity": "HIGH" if days_left <= 0 else "MEDIUM",
                "confidence": "CONFIRMED BY SAFE CHECK",
                "url": site.get("url"),
                "description": f"Certificate expires in {days_left} day(s) (not_after={tls.get('not_after')}).",
                "evidence": f"Issuer: {tls.get('issuer')}, Subject: {tls.get('subject')}",
                "security_impact": "Availability Risk / user trust and TLS validation failures",
                "cwe": "CWE-295",
                "remediation_immediate": "Renew the certificate immediately if already expired.",
                "remediation_permanent": "Automate certificate renewal (e.g. ACME/Let's Encrypt or enterprise PKI auto-renewal).",
                "verification": "Re-check the certificate expiry date after renewal.",
            })
    elif tls and tls.get("error"):
        findings.append({
            "title": "TLS connection could not be fully validated",
            "severity": "INFO",
            "confidence": "MANUAL VERIFICATION REQUIRED",
            "url": site.get("url"),
            "description": f"TLS handshake/inspection failed: {tls.get('error')}",
            "evidence": tls.get("error"),
            "security_impact": "Unknown - manual review recommended",
            "cwe": None,
            "remediation_immediate": "Manually verify TLS configuration with an authorized scanner (e.g. testssl.sh) from an approved host.",
            "remediation_permanent": "Ensure the service presents a valid, correctly chained certificate and supports modern TLS versions only.",
            "verification": "Re-run TLS analysis after remediation.",
        })

    for ep in site.get("endpoints", []):
        if ep.get("status") and ep["status"] < 400 and ep.get("relevance", "").startswith(("HIGH", "MEDIUM")):
            findings.append({
                "title": f"Potentially sensitive resource reachable: {ep['url']}",
                "severity": "HIGH" if ep["relevance"].startswith("HIGH") else "MEDIUM",
                "confidence": "CONFIRMED BY SAFE CHECK" if ep["status"] == 200 else "POTENTIAL",
                "url": ep["url"],
                "description": f"Resource returned HTTP {ep['status']} ({ep.get('content_type')}, {ep.get('size')} bytes). {ep['relevance']}",
                "evidence": f"GET {ep['url']} -> {ep['status']}",
                "security_impact": "Information Disclosure / Configuration Exposure",
                "cwe": "CWE-538",
                "remediation_immediate": "Restrict or remove public access to this path immediately (firewall/reverse-proxy rule).",
                "remediation_permanent": "Remove the exposed artifact from the public web root or move it behind authentication.",
                "verification": "Re-request the URL and confirm it now returns 401/403/404 or is no longer reachable.",
            })

    return findings
