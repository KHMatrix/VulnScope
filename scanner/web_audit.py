"""
KHMatrix - Web Application Assessment Engine

Non-destructive HTTP/HTTPS analysis: security headers, cookie attributes, TLS/certificate
inspection, and controlled discovery of common PUBLIC resource paths (GET requests only,
no authentication bypass, no payload injection, no fuzzing beyond a small static wordlist).
"""
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException

from .utils import CancellationToken

REQUEST_TIMEOUT = 8
USER_AGENT = "KHMatrix-Auditor/1.0 (+authorized-assessment)"

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Small, well-known, non-invasive resource list. No brute-force wordlists, no fuzzing.
COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/login", "/admin", "/administrator",
    "/api", "/docs", "/swagger", "/swagger.json", "/health", "/status",
    "/backup", "/.git/HEAD", "/.env", "/wp-admin", "/server-status",
]

SENSITIVE_RELEVANCE = {
    "/.git/HEAD": "HIGH - possible exposed source control directory",
    "/.env": "HIGH - possible exposed environment/config file",
    "/backup": "MEDIUM - possible exposed backup artifact",
    "/server-status": "MEDIUM - possible Apache mod_status information disclosure",
    "/admin": "MEDIUM - administrative interface surface",
    "/administrator": "MEDIUM - administrative interface surface",
    "/wp-admin": "MEDIUM - CMS administrative interface surface",
    "/swagger": "LOW - API documentation surface, review for sensitive exposure",
    "/swagger.json": "LOW - API documentation surface, review for sensitive exposure",
    "/login": "INFO - authentication surface",
    "/api": "INFO - API surface",
}


def _session():
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def analyze_tls(hostname: str, port: int = 443, timeout=REQUEST_TIMEOUT):
    """Non-destructive TLS/certificate inspection. No cipher-downgrade attacks performed."""
    info = {"hostname": hostname, "port": port, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info["tls_version"] = ssock.version()
                info["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
                info["subject"] = dict(x[0] for x in cert.get("subject", []))
                info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                info["not_before"] = cert.get("notBefore")
                info["not_after"] = cert.get("notAfter")
                info["san"] = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                if info["not_after"]:
                    try:
                        expiry = datetime.strptime(info["not_after"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                        info["days_until_expiry"] = days_left
                    except ValueError:
                        info["days_until_expiry"] = None
    except Exception as e:
        info["error"] = str(e)
    return info


def analyze_headers(url: str, cancel: CancellationToken):
    """Fetch a URL once and analyze security headers + cookies. GET only, no auth bypass."""
    if cancel.is_cancelled():
        return None
    session = _session()
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=True)
    except RequestException as e:
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False)
        except RequestException as e2:
            return {"url": url, "error": str(e2), "status_code": None}

    headers = dict(resp.headers)
    missing = [h for h in SECURITY_HEADERS if h not in headers]

    cookies_info = []
    for c in resp.cookies:
        cookies_info.append({
            "name": c.name,
            "secure": bool(c.secure),
            "httponly": bool(c.has_nonstandard_attr("HttpOnly") or "httponly" in str(c._rest).lower()),
            "samesite": c._rest.get("SameSite") if hasattr(c, "_rest") else None,
        })

    server_banner = headers.get("Server")
    powered_by = headers.get("X-Powered-By")
    technologies = [t for t in [server_banner, powered_by] if t]

    return {
        "url": resp.url,
        "status_code": resp.status_code,
        "headers": headers,
        "missing_security_headers": missing,
        "cookies": cookies_info,
        "technologies": technologies,
        "final_redirect": resp.url if resp.url != url else None,
    }


def discover_endpoints(base_url: str, cancel: CancellationToken):
    """Check a small, fixed list of well-known public resource paths. GET requests only."""
    session = _session()
    results = []
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    for path in COMMON_PATHS:
        if cancel.is_cancelled():
            break
        url = urljoin(root, path)
        start = time.time()
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False, verify=False)
            elapsed = time.time() - start
            auth_indicator = None
            if resp.status_code in (401, 403):
                auth_indicator = "AUTH_REQUIRED"
            elif "www-authenticate" in {k.lower() for k in resp.headers}:
                auth_indicator = "HTTP_BASIC_AUTH"

            results.append({
                "url": url,
                "status": resp.status_code,
                "content_type": resp.headers.get("Content-Type"),
                "size": len(resp.content or b""),
                "response_time": round(elapsed, 3),
                "redirect": resp.headers.get("Location"),
                "auth_indicator": auth_indicator,
                "relevance": SENSITIVE_RELEVANCE.get(path, "INFO"),
            })
        except RequestException:
            continue
    return results
