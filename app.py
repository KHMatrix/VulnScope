"""
KHMatrix Cyber-Security Auditor
Authorized multi-asset vulnerability assessment platform.

Run: python app.py
See README.md for installation and first-run setup.
"""
import os
import secrets
import functools
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, request, jsonify, session, render_template, Response, redirect, url_for
from flask_socketio import SocketIO, join_room
from werkzeug.security import generate_password_hash, check_password_hash

import database as db
from scanner.utils import CancellationToken, classify_target_type, expand_target_hosts, is_authorized_scope
from scanner import discovery, classifier, web_audit, correlation, findings as findings_mod, reporting

APP_SECRET = os.environ.get("KHMATRIX_SECRET_KEY") or secrets.token_hex(32)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=APP_SECRET,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("KHMATRIX_FORCE_SECURE_COOKIE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 4,  # 4 hours
)

socketio = SocketIO(app, async_mode="threading", cors_allowed_origins=[])

MAX_HOST_WORKERS = 8
MAX_SERVICE_WORKERS = 4
MAX_NVD_QUERIES_PER_SCAN = 20
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

# scan_id -> CancellationToken, for the abort mechanism (thread-safe, checked periodically by workers)
ACTIVE_SCANS = {}


# ---------------------------------------------------------------- auth ----
def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("login_page"))
        return view(*a, **kw)
    return wrapped


def csrf_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
            if not token or token != session.get("csrf_token"):
                return jsonify({"error": "invalid or missing CSRF token"}), 403
        return view(*a, **kw)
    return wrapped


@app.route("/login", methods=["GET"])
def login_page():
    needs_setup = not db.any_user_exists()
    return render_template("login.html", needs_setup=needs_setup)


@app.route("/api/setup", methods=["POST"])
def api_setup():
    if db.any_user_exists():
        return jsonify({"error": "setup already completed"}), 400
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if len(username) < 3 or len(password) < 10:
        return jsonify({"error": "username must be >=3 chars and password >=10 chars"}), 400
    db.create_user(username, generate_password_hash(password))
    return jsonify({"ok": True})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    user = db.get_user(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "invalid credentials"}), 401
    session.clear()
    session.permanent = True
    session["user"] = username
    session["csrf_token"] = secrets.token_hex(16)
    return jsonify({"ok": True, "csrf_token": session["csrf_token"]})


@app.route("/api/logout", methods=["POST"])
@login_required
def api_logout():
    session.clear()
    return jsonify({"ok": True})


# ------------------------------------------------------------ dashboard ----
@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", csrf_token=session.get("csrf_token"))


# --------------------------------------------------------------- assets ----
@app.route("/api/assets", methods=["GET"])
@login_required
def api_list_assets():
    return jsonify(db.list_assets())


@app.route("/api/assets", methods=["POST"])
@login_required
@csrf_required
def api_add_asset():
    data = request.get_json(force=True)
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    ttype = classify_target_type(target)
    if ttype == "unknown":
        return jsonify({"error": "target is not a recognizable IP, CIDR, hostname, or URL"}), 400
    asset_id = db.add_asset(
        name=data.get("name") or target,
        target=target,
        target_type=ttype,
        device_type_hint=data.get("device_type"),
        owner=data.get("owner"),
        environment=data.get("environment"),
        notes=data.get("notes"),
        authorized=bool(data.get("authorized")),
    )
    return jsonify(db.get_asset(asset_id))


@app.route("/api/assets/<int:asset_id>", methods=["DELETE"])
@login_required
@csrf_required
def api_delete_asset(asset_id):
    db.delete_asset(asset_id)
    return jsonify({"ok": True})


# ---------------------------------------------------------------- scans ----
@app.route("/api/scans", methods=["GET"])
@login_required
def api_list_scans():
    asset_id = request.args.get("asset_id", type=int)
    return jsonify(db.list_scans(asset_id))


@app.route("/api/scan/start", methods=["POST"])
@login_required
@csrf_required
def api_start_scan():
    data = request.get_json(force=True)
    asset_id = data.get("asset_id")
    asset = db.get_asset(asset_id)
    if not asset:
        return jsonify({"error": "unknown asset"}), 404
    if not asset["authorized"]:
        return jsonify({"error": "TARGET AUTHORIZATION: NOT VERIFIED. Mark this asset authorized before scanning."}), 403

    scan_type = data.get("scan_type", "single")
    scan_id = db.create_scan(asset_id, scan_type)
    cancel_token = CancellationToken()
    ACTIVE_SCANS[scan_id] = cancel_token

    socketio.start_background_task(run_scan_job, asset, scan_id, cancel_token)
    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<int:scan_id>/abort", methods=["POST"])
@login_required
@csrf_required
def api_abort_scan(scan_id):
    token = ACTIVE_SCANS.get(scan_id)
    if not token:
        return jsonify({"error": "scan is not active"}), 404
    token.cancel()
    return jsonify({"ok": True})


@app.route("/api/scan/<int:scan_id>", methods=["GET"])
@login_required
def api_scan_status(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    hosts = db.hosts_for_scan(scan_id)
    for h in hosts:
        cls = classifier.classify_host(h)
        h.setdefault("device_type", cls["device_type"])
    websites = db.websites_for_scan(scan_id)
    finds = db.findings_for_scan(scan_id)
    return jsonify({"scan": scan, "hosts": hosts, "websites": websites, "findings": finds})


@app.route("/api/scan/<int:scan_id>/report/<fmt>", methods=["GET"])
@login_required
def api_scan_report(scan_id, fmt):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    asset = db.get_asset(scan["asset_id"])
    hosts = db.hosts_for_scan(scan_id)
    websites = db.websites_for_scan(scan_id)
    finds = db.findings_for_scan(scan_id)
    changes = db.changes_for_asset(scan["asset_id"])
    ctx = reporting.build_report_context(asset, scan, hosts, websites, finds, changes)

    if fmt == "json":
        return Response(reporting.to_json(ctx), mimetype="application/json",
                         headers={"Content-Disposition": f"attachment; filename=khmatrix_scan_{scan_id}.json"})
    if fmt == "csv":
        return Response(reporting.to_csv(ctx), mimetype="text/csv",
                         headers={"Content-Disposition": f"attachment; filename=khmatrix_scan_{scan_id}.csv"})
    if fmt == "txt":
        return Response(reporting.to_txt(ctx), mimetype="text/plain",
                         headers={"Content-Disposition": f"attachment; filename=khmatrix_scan_{scan_id}.txt"})
    if fmt == "html":
        return Response(reporting.to_html(ctx), mimetype="text/html")
    return jsonify({"error": "unsupported format. use json, csv, txt, or html"}), 400


@app.route("/api/assets/<int:asset_id>/changes", methods=["GET"])
@login_required
def api_asset_changes(asset_id):
    return jsonify(db.changes_for_asset(asset_id))


@app.route("/api/system/check", methods=["GET"])
@login_required
def api_system_check():
    return jsonify({
        "nmap_installed": discovery.nmap_available(),
        "python_version": os.sys.version,
    })


# --------------------------------------------------------- socket.io ------
@socketio.on("subscribe_scan")
def on_subscribe(data):
    scan_id = data.get("scan_id")
    if scan_id:
        join_room(f"scan_{scan_id}")


def emit_telemetry(scan_id, event, message, level="info", extra=None):
    payload = {"event": event, "message": message, "level": level}
    if extra:
        payload["extra"] = extra
    socketio.emit("telemetry", payload, room=f"scan_{scan_id}")


# ------------------------------------------------------- scan pipeline ----
def run_scan_job(asset, scan_id, cancel_token: CancellationToken):
    asset_id = asset["id"]
    target = asset["target"]
    ttype = asset["target_type"]
    nvd_queries_used = [0]

    try:
        authorized_assets = db.list_assets()
        if not is_authorized_scope(target, ttype, authorized_assets):
            emit_telemetry(scan_id, "TARGET AUTHORIZATION VERIFIED", "DENIED - target outside authorized scope", "error")
            db.finish_scan(scan_id, "failed", {"error": "target outside authorized scope"})
            return

        emit_telemetry(scan_id, "TARGET AUTHORIZATION VERIFIED", f"Scope confirmed for {target}")
        emit_telemetry(scan_id, "DISCOVERY STARTED", f"Beginning authorized assessment of {target}")

        collected_hosts = []
        collected_sites = []
        collected_findings = []

        if ttype == "url":
            site = _assess_web_target(target, scan_id, asset_id, cancel_token)
            if site:
                collected_sites.append(site)
        else:
            try:
                ips = expand_target_hosts(target, ttype)
            except ValueError as e:
                emit_telemetry(scan_id, "DISCOVERY STARTED", f"ERROR: {e}", "error")
                db.finish_scan(scan_id, "failed", {"error": str(e)})
                return

            up_ips = []
            with ThreadPoolExecutor(max_workers=MAX_HOST_WORKERS) as pool:
                futs = {pool.submit(discovery.run_host_discovery, ip, cancel_token): ip for ip in ips}
                for fut in as_completed(futs):
                    if cancel_token.is_cancelled():
                        break
                    ip = futs[fut]
                    try:
                        if fut.result():
                            up_ips.append(ip)
                            emit_telemetry(scan_id, "HOST DISCOVERED", f"{ip} is up")
                    except Exception:
                        continue

            if not up_ips and not cancel_token.is_cancelled():
                emit_telemetry(scan_id, "HOST DISCOVERED", "No live hosts responded in the authorized range.")

            with ThreadPoolExecutor(max_workers=MAX_SERVICE_WORKERS) as pool:
                futs = {pool.submit(discovery.run_service_scan, ip, cancel_token): ip for ip in up_ips}
                for fut in as_completed(futs):
                    if cancel_token.is_cancelled():
                        break
                    try:
                        host_result = fut.result()
                    except Exception:
                        continue

                    cls = classifier.classify_host(host_result)
                    emit_telemetry(scan_id, "SERVICE DISCOVERED",
                                    f"{host_result['ip']} classified as {cls['device_type']} "
                                    f"(confidence {cls['confidence']})")

                    host_id = db.add_host(
                        scan_id, asset_id, host_result["ip"], host_result.get("mac"),
                        host_result.get("hostname"), host_result.get("vendor"),
                        cls["device_type"], cls["confidence"], host_result.get("os_indicator"),
                    )
                    host_record = dict(host_result)
                    host_record["id"] = host_id
                    host_record["device_type"] = cls["device_type"]
                    host_record["confidence"] = cls["confidence"]

                    for svc in host_result["ports"]:
                        db.add_service(host_id, svc["port"], svc["protocol"], svc["state"],
                                        svc.get("service"), svc.get("product"), svc.get("version"),
                                        svc.get("banner"))
                        emit_telemetry(scan_id, "VERSION DETECTED",
                                        f"{host_result['ip']}:{svc['port']} {svc.get('service')} "
                                        f"{svc.get('product') or ''} {svc.get('version') or ''}".strip())

                    collected_hosts.append(host_record)

                    # Configuration-derived findings (no external lookup required)
                    for f in correlation.config_findings_for_host(host_result):
                        norm = findings_mod.normalize_finding(f, scan_id, asset_id, host_result["ip"],
                                                                host_result.get("hostname"))
                        db.add_finding(norm)
                        collected_findings.append(norm)
                        emit_telemetry(scan_id, "FINDING CREATED", f"[{norm['severity']}] {norm['title']} on {host_result['ip']}")

                    # CVE correlation via live NVD lookup, bounded per scan
                    for svc in host_result["ports"]:
                        if cancel_token.is_cancelled() or nvd_queries_used[0] >= MAX_NVD_QUERIES_PER_SCAN:
                            break
                        if not svc.get("product"):
                            continue
                        nvd_queries_used[0] += 1
                        nvd = correlation.query_nvd(svc["product"], svc.get("version") or "")
                        emit_telemetry(scan_id, "VULNERABILITY CORRELATED",
                                        f"Queried NVD for {svc['product']} {svc.get('version') or ''}".strip())
                        if nvd.get("unavailable"):
                            continue
                        for cve in nvd["results"]:
                            raw = {
                                "title": f"Potential vulnerability in {svc['product']} {svc.get('version') or ''}".strip(),
                                "severity": correlation.severity_from_cvss(cve["cvss"]),
                                "confidence": cve["confidence"],
                                "port": svc["port"], "protocol": svc["protocol"], "service": svc.get("service"),
                                "product": svc.get("product"), "version": svc.get("version"),
                                "description": cve["description"],
                                "evidence": f"NVD keyword match for '{svc['product']} {svc.get('version') or ''}'",
                                "security_impact": "See CVE description. POTENTIAL VULNERABILITY — manual authorized verification required. No exploitation was performed.",
                                "cve": cve["cve_id"], "cwe": None, "cvss": cve["cvss"],
                                "affected_versions": svc.get("version"),
                                "remediation_immediate": "Restrict network exposure of this service until the version can be confirmed and patched.",
                                "remediation_permanent": f"Upgrade {svc['product']} to a version that resolves {cve['cve_id']} per vendor guidance.",
                                "verification": "Confirm the exact installed version through an authenticated/manual check, then re-scan to verify the fix.",
                                "references": cve["references"],
                            }
                            norm = findings_mod.normalize_finding(raw, scan_id, asset_id, host_result["ip"],
                                                                    host_result.get("hostname"))
                            db.add_finding(norm)
                            collected_findings.append(norm)
                            emit_telemetry(scan_id, "FINDING CREATED",
                                            f"[{norm['severity']}] {norm['title']} ({cve['cve_id']}) on {host_result['ip']}")

                    # If the host exposes a web port, also run the web assessment against it.
                    web_ports_open = {s["port"] for s in host_result["ports"]} & WEB_PORTS
                    for wp in web_ports_open:
                        if cancel_token.is_cancelled():
                            break
                        scheme = "https" if wp in (443, 8443) else "http"
                        site = _assess_web_target(f"{scheme}://{host_result['ip']}:{wp}", scan_id, asset_id, cancel_token)
                        if site:
                            collected_sites.append(site)

        # Web findings (headers/cookies/TLS/exposed-endpoint based) are derived once, here,
        # for every website assessed above regardless of whether it came from a direct URL
        # asset or from a web port discovered on a scanned host.
        for site in collected_sites:
            for f in correlation.web_findings_for_site(site):
                norm = findings_mod.normalize_finding(f, scan_id, asset_id, hostname=site.get("url"))
                db.add_finding(norm)
                emit_telemetry(scan_id, "FINDING CREATED", f"[{norm['severity']}] {norm['title']}")

        status = "aborted" if cancel_token.is_cancelled() else "completed"
        all_findings = db.findings_for_scan(scan_id)
        summary = findings_mod.summarize_counts(all_findings)
        summary["hosts_discovered"] = len(collected_hosts)
        summary["websites_assessed"] = len(collected_sites)
        db.finish_scan(scan_id, status, summary)

        _compute_monitoring_changes(asset_id, scan_id)

        emit_telemetry(scan_id, "SCAN COMPLETED" if status == "completed" else "SCAN COMPLETED",
                        f"Scan {status.upper()}. {summary}")
        emit_telemetry(scan_id, "REPORT GENERATED", "Reports available for download (HTML/JSON/CSV/TXT).")

    except Exception as e:
        db.finish_scan(scan_id, "failed", {"error": str(e)})
        emit_telemetry(scan_id, "SCAN COMPLETED", f"Scan FAILED: {e}", "error")
    finally:
        ACTIVE_SCANS.pop(scan_id, None)


def _assess_web_target(url, scan_id, asset_id, cancel_token):
    if cancel_token.is_cancelled():
        return None
    emit_telemetry(scan_id, "WEB ENDPOINT DISCOVERED", f"Assessing {url}")
    headers_result = web_audit.analyze_headers(url, cancel_token)
    if not headers_result or headers_result.get("error"):
        emit_telemetry(scan_id, "WEB ENDPOINT DISCOVERED", f"Could not reach {url}", "warn")
        return None

    from urllib.parse import urlparse
    parsed = urlparse(url)
    tls_result = None
    if parsed.scheme == "https":
        tls_result = web_audit.analyze_tls(parsed.hostname, parsed.port or 443)
        emit_telemetry(scan_id, "SECURITY CONTROL ANALYZED", f"TLS analyzed for {parsed.hostname}")

    endpoints = web_audit.discover_endpoints(url, cancel_token)
    for ep in endpoints:
        emit_telemetry(scan_id, "WEB ENDPOINT DISCOVERED", f"{ep['url']} -> {ep['status']}")

    website_id = db.add_website(
        scan_id, asset_id, headers_result["url"], headers_result["status_code"],
        headers_result["headers"], tls_result or {}, headers_result["cookies"],
        headers_result["technologies"],
    )
    for ep in endpoints:
        db.add_endpoint(website_id, ep["url"], ep["status"], ep["content_type"], ep["size"],
                         ep["response_time"], ep["redirect"], ep["auth_indicator"], ep["relevance"])

    emit_telemetry(scan_id, "SECURITY CONTROL ANALYZED",
                    f"{len(headers_result['missing_security_headers'])} missing security header(s) on {url}")

    site = {
        "id": website_id, "url": headers_result["url"], "_headers_result": headers_result,
        "_tls_result": tls_result, "endpoints": endpoints,
    }
    return site


def _compute_monitoring_changes(asset_id, scan_id):
    prev = db.previous_scan(asset_id, scan_id)
    if not prev:
        return
    prev_hosts = db.hosts_for_scan(prev["id"])
    curr_hosts = db.hosts_for_scan(scan_id)
    prev_ips = {h["ip"] for h in prev_hosts if h["ip"]}
    curr_ips = {h["ip"] for h in curr_hosts if h["ip"]}

    for ip in curr_ips - prev_ips:
        db.add_change(asset_id, scan_id, "NEW DEVICE", f"New device detected: {ip}")
    for ip in prev_ips - curr_ips:
        db.add_change(asset_id, scan_id, "DEVICE REMOVED", f"Device no longer responding: {ip}")

    prev_ports = {h["ip"]: {(s["port"], s["protocol"]) for s in h["services"]} for h in prev_hosts}
    curr_ports = {h["ip"]: {(s["port"], s["protocol"]) for s in h["services"]} for h in curr_hosts}
    for ip in curr_ips & prev_ips:
        new_p = curr_ports.get(ip, set()) - prev_ports.get(ip, set())
        closed_p = prev_ports.get(ip, set()) - curr_ports.get(ip, set())
        for p in new_p:
            db.add_change(asset_id, scan_id, "NEW PORT", f"{ip} opened port {p[0]}/{p[1]}")
        for p in closed_p:
            db.add_change(asset_id, scan_id, "CLOSED PORT", f"{ip} closed port {p[0]}/{p[1]}")

    prev_findings = {f["title"] + "|" + (f["host_ip"] or "") for f in db.findings_for_scan(prev["id"])}
    curr_findings_rows = db.findings_for_scan(scan_id)
    curr_findings = {f["title"] + "|" + (f["host_ip"] or "") for f in curr_findings_rows}
    for key in curr_findings - prev_findings:
        db.add_change(asset_id, scan_id, "NEW VULNERABILITY", key.replace("|", " on "))
    for key in prev_findings - curr_findings:
        db.add_change(asset_id, scan_id, "RESOLVED VULNERABILITY", key.replace("|", " on "))


if __name__ == "__main__":
    db.init_db()
    print("KHMatrix Cyber-Security Auditor")
    print(f"nmap available: {discovery.nmap_available()}")
    if not db.any_user_exists():
        print("No admin account exists yet. Visit /login to complete first-run setup.")
    port = int(os.environ.get("KHMATRIX_PORT", 5000))
    socketio.run(app, host=os.environ.get("KHMATRIX_HOST", "127.0.0.1"), port=port, debug=False, allow_unsafe_werkzeug=True)
