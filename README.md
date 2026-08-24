# KHMatrix Cyber-Security Auditor

Authorized multi-asset vulnerability assessment, discovery, and reporting platform for
**your own lab, your own devices, and infrastructure you have explicit written authorization
to test.**

KHMatrix is **not** an exploitation framework. It performs non-destructive discovery,
fingerprinting, configuration analysis, and CVE correlation, and clearly labels anything
that would require exploitation to fully confirm as:

```
POTENTIAL VULNERABILITY
Manual authorized verification required.
No exploitation was performed.
```

---

## 1. Requirements

- Python 3.10+
- `nmap` installed and on your `PATH` (used for host/service discovery — required for
  scanning IP/CIDR/hostname assets; not required for URL-only web assessments)
  - Debian/Ubuntu: `sudo apt-get install nmap`
  - macOS (Homebrew): `brew install nmap`
  - Windows: install from https://nmap.org/download.html and ensure `nmap.exe` is on PATH
- Internet access (optional) for live CVE correlation against the public NVD API. If
  unreachable, KHMatrix still runs — CVE-based findings are simply marked
  "MANUAL VERIFICATION REQUIRED" instead of being fabricated.

## 2. Install

```bash
cd khmatrix
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Run

```bash
python app.py
```

By default the app listens on `http://127.0.0.1:5000`. Open that URL in a browser.

On first run, no operator account exists yet — you'll be prompted to create one
(username + password, minimum 10-character password). All subsequent access requires
login. Sessions expire after 4 hours of inactivity.

### Optional environment variables

| Variable | Purpose | Default |
|---|---|---|
| `KHMATRIX_SECRET_KEY` | Flask session signing key. Set this explicitly in any persistent deployment. | random per-run |
| `KHMATRIX_HOST` | Bind address | `127.0.0.1` |
| `KHMATRIX_PORT` | Bind port | `5000` |
| `KHMATRIX_FORCE_SECURE_COOKIE` | Set to `1` to require HTTPS for the session cookie (do this if you put KHMatrix behind TLS) | `0` |

## 4. Using KHMatrix

1. **Add an authorized asset** — click "+ ADD ASSET" and enter an IP, CIDR range (e.g.
   `192.168.10.0/24`), hostname, or URL. Check the authorization confirmation box. Unchecked
   assets **cannot be scanned** — the API enforces this server-side, not just in the UI.
2. **Select the asset** in the target dropdown. The banner reads
   `TARGET AUTHORIZATION: VERIFIED` once you pick an authorized asset.
3. **Start Scan.** Live telemetry streams in over Socket.IO as hosts, services, and
   findings are discovered. You can **Abort Scan** at any time — partial results already
   collected are preserved and the scan is marked `ABORTED`.
4. **Review findings** in the Vulnerability Findings table, and **download reports**
   (HTML / JSON / CSV / TXT) from the links above that table once a scan completes.
5. **Archived Intel** at the bottom lists every past scan; opening a report never
   triggers a new scan.

## 5. What KHMatrix actually checks

- **Host/service discovery** via `nmap -sn` (host sweep) and `nmap -sV` (version
  detection) against a conservative, named port list (see `scanner/discovery.py`).
- **Device classification** from open ports/service banners/vendor OUI — heuristic,
  always labeled with a confidence level, never guessed silently.
- **Configuration findings** (Telnet/FTP/SNMP/VNC exposure, missing security headers,
  weak cookie flags, expiring/expired TLS certs, unauthenticated sensitive paths) —
  labeled `CONFIRMED BY SAFE CHECK` because they come directly from observed scan data.
- **CVE correlation** via a *live* query to the public NVD REST API for each detected
  product/version. KHMatrix does not ship a bundled, hard-coded CVE database — that
  would silently go stale. If NVD can't be reached, findings are marked
  `MANUAL VERIFICATION REQUIRED` rather than guessed.
- **Continuous monitoring**: each new scan of an asset is diffed against its most recent
  prior completed scan (new/removed devices, new/closed ports, new/resolved findings).

## 6. Security notes

- All SQL uses parameterized queries.
- All subprocess calls to `nmap` use argument arrays — no shell string concatenation.
- CSRF tokens are required on every state-changing API call.
- Session cookies are `HttpOnly` + `SameSite=Lax`.
- Passwords are hashed with Werkzeug's salted `pbkdf2:sha256` (via `generate_password_hash`).
- The built-in Flask/Werkzeug server is fine for local lab use. For anything reachable
  beyond localhost, put it behind a real WSGI server (gunicorn/uwsgi) and a reverse proxy
  with TLS, and set `KHMATRIX_FORCE_SECURE_COOKIE=1`.

## 7. Known simplifications (read before relying on this for anything important)

This is a working reference implementation, not a commercial-grade scanner. In particular:

- **CVE correlation is keyword-based**, not CPE-based. It's a reasonable starting point
  for triage, not a substitute for an authenticated vulnerability scanner (e.g. an
  authenticated OpenVAS/Nessus scan) before you treat something as fixed or not-fixed.
- **Device classification is heuristic**, based only on what's visible over the network.
  It will say `UNKNOWN` / `LOW confidence` rather than guess when signals are weak — trust
  that over a forced guess.
- The default port list in `scanner/discovery.py` is a curated common-services set, not a
  full 1–65535 sweep (you can widen `DEFAULT_PORTS` if your lab needs it — expect scans to
  take longer).
- NVD's public API is rate-limited (~5 requests/30s without a key); KHMatrix caps itself
  at 20 NVD queries per scan and paces requests accordingly, so scans against hosts with
  many distinct product/version combinations will take longer.

## 8. Uninstall / reset

All data lives in `instance/khmatrix.db` (SQLite). Delete that file to reset everything
(assets, scans, findings, users) — you'll be prompted to create a new operator account.
# VulnScope
# VulnScope
# VulnScope
# VulnScope
# VulnScope
# VulnScope
