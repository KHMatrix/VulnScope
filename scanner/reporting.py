"""
KHMatrix - Automatic Reporting Engine
Generates HTML, JSON, CSV, and TXT reports from a completed scan.
"""
import csv
import io
import json
from datetime import datetime
from .findings import risk_priority, sort_findings, summarize_counts


def build_report_context(asset, scan, hosts, websites, findings, changes):
    findings = sort_findings(findings)
    for f in findings:
        f["priority"] = risk_priority(f)
    counts = summarize_counts(findings)
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "asset": asset,
        "scan": scan,
        "hosts": hosts,
        "websites": websites,
        "findings": findings,
        "changes": changes,
        "counts": counts,
        "total_findings": len(findings),
    }


def to_json(ctx: dict) -> str:
    return json.dumps(ctx, indent=2, default=str)


def to_csv(ctx: dict) -> str:
    buf = io.StringIO()
    fieldnames = ["finding_ref", "title", "severity", "priority", "confidence", "host_ip", "hostname",
                  "port", "protocol", "service", "product", "version", "url", "cve", "cwe", "cvss",
                  "status", "first_seen", "last_seen"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for f in ctx["findings"]:
        writer.writerow(f)
    return buf.getvalue()


def to_txt(ctx: dict) -> str:
    lines = []
    a = ctx["asset"]
    lines.append("=" * 70)
    lines.append("KHMatrix Cyber-Security Auditor - Technical Report")
    lines.append("=" * 70)
    lines.append(f"Generated: {ctx['generated_at']}")
    lines.append(f"Asset: {a['name']} ({a['target']})  [Environment: {a.get('environment') or 'n/a'}]")
    lines.append(f"Scan ID: {ctx['scan']['id']}  Status: {ctx['scan']['status']}")
    lines.append("")
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 70)
    c = ctx["counts"]
    lines.append(f"Total findings: {ctx['total_findings']}  "
                  f"(CRITICAL={c['CRITICAL']} HIGH={c['HIGH']} MEDIUM={c['MEDIUM']} LOW={c['LOW']} INFO={c['INFO']})")
    lines.append("")
    lines.append("SCOPE")
    lines.append("-" * 70)
    lines.append(f"Target: {a['target']} ({a['target_type']})  Authorized: {'YES' if a['authorized'] else 'NO'}")
    lines.append("")
    lines.append("ASSETS DISCOVERED")
    lines.append("-" * 70)
    for h in ctx["hosts"]:
        lines.append(f"  {h.get('ip')}  [{h.get('device_type')} / confidence={h.get('confidence')}]"
                      f"  hostname={h.get('hostname') or 'n/a'}  os={h.get('os_indicator') or 'n/a'}")
        for s in h.get("services", []):
            lines.append(f"      {s['port']}/{s['protocol']}  {s.get('service') or 'unknown'}"
                          f"  {s.get('product') or ''} {s.get('version') or ''}".rstrip())
    lines.append("")
    lines.append("WEB ASSESSMENT")
    lines.append("-" * 70)
    for w in ctx["websites"]:
        lines.append(f"  {w.get('url')}  status={w.get('status_code')}")
        missing = (w.get("headers") or {}).get("missing_security_headers")
    lines.append("")
    lines.append("VULNERABILITY FINDINGS")
    lines.append("-" * 70)
    for f in ctx["findings"]:
        lines.append(f"[{f['severity']}] ({f['priority']}) {f['title']}  -- {f['finding_ref']}")
        lines.append(f"    Confidence: {f['confidence']}   CVE: {f.get('cve') or 'n/a'}   CWE: {f.get('cwe') or 'n/a'}   CVSS: {f.get('cvss') or 'n/a'}")
        lines.append(f"    Location: {f.get('host_ip') or f.get('url') or 'n/a'}"
                      f"{':' + str(f['port']) if f.get('port') else ''}")
        lines.append(f"    Description: {f.get('description')}")
        lines.append(f"    Evidence: {f.get('evidence')}")
        lines.append(f"    Security Impact: {f.get('security_impact')}")
        lines.append(f"    Potential Attacker Impact: {f.get('attacker_impact')}")
        lines.append(f"    Immediate Mitigation: {f.get('remediation_immediate')}")
        lines.append(f"    Permanent Fix: {f.get('remediation_permanent')}")
        lines.append(f"    Verification: {f.get('verification')}")
        lines.append("")
    lines.append("HISTORICAL CHANGES")
    lines.append("-" * 70)
    for ch in ctx["changes"]:
        lines.append(f"  [{ch['created_at']}] {ch['change_type']}: {ch['description']}")
    return "\n".join(lines)


def to_html(ctx: dict) -> str:
    a = ctx["asset"]
    c = ctx["counts"]

    def esc(x):
        return (str(x) if x is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    rows = []
    for f in ctx["findings"]:
        rows.append(f"""
        <tr class="sev-{esc(f['severity']).lower()}">
          <td>{esc(f['finding_ref'])}</td>
          <td>{esc(f['title'])}</td>
          <td><span class="badge badge-{esc(f['severity']).lower()}">{esc(f['severity'])}</span></td>
          <td>{esc(f['priority'])}</td>
          <td>{esc(f['confidence'])}</td>
          <td>{esc(f.get('host_ip') or f.get('url') or '')}</td>
          <td>{esc(f.get('cve') or '')}</td>
          <td>{esc(f.get('cvss') or '')}</td>
        </tr>
        <tr class="detail-row">
          <td colspan="8">
            <div class="detail">
              <p><b>Description:</b> {esc(f.get('description'))}</p>
              <p><b>Evidence:</b> {esc(f.get('evidence'))}</p>
              <p><b>Security Impact:</b> {esc(f.get('security_impact'))}</p>
              <p><b>Potential Attacker Impact:</b> {esc(f.get('attacker_impact'))}</p>
              <p><b>Immediate Mitigation:</b> {esc(f.get('remediation_immediate'))}</p>
              <p><b>Permanent Fix:</b> {esc(f.get('remediation_permanent'))}</p>
              <p><b>Verification:</b> {esc(f.get('verification'))}</p>
              <p><b>References:</b> {esc(f.get('refs'))}</p>
            </div>
          </td>
        </tr>""")

    def port_summary(h):
        parts = [f"{s['port']}/{s.get('service') or '?'}" for s in h.get("services", [])]
        return ", ".join(parts)

    host_rows = "".join(
        f"<tr><td>{esc(h.get('ip'))}</td><td>{esc(h.get('device_type'))}</td>"
        f"<td>{esc(h.get('confidence'))}</td><td>{esc(h.get('hostname'))}</td>"
        f"<td>{esc(h.get('os_indicator'))}</td>"
        f"<td>{esc(port_summary(h))}</td></tr>"
        for h in ctx["hosts"]
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>KHMatrix Report - {esc(a['name'])}</title>
<style>
  body {{ background:#050508; color:#d8f6ff; font-family: 'Courier New', monospace; margin:0; padding:24px; }}
  h1,h2 {{ color:#5fe1ff; text-shadow:0 0 8px #00d4ff88; }}
  .summary {{ display:flex; gap:16px; margin:16px 0; flex-wrap:wrap; }}
  .card {{ background:#0d0f16; border:1px solid #1c4a5f; border-radius:8px; padding:12px 18px; box-shadow:0 0 12px #00d4ff22;}}
  table {{ width:100%; border-collapse:collapse; margin:12px 0; }}
  th, td {{ border-bottom:1px solid #14313d; padding:6px 8px; text-align:left; font-size:13px; }}
  th {{ color:#5fe1ff; }}
  .badge {{ padding:2px 8px; border-radius:4px; font-weight:bold; font-size:11px; }}
  .badge-critical {{ background:#ff003c33; color:#ff4d6d; border:1px solid #ff4d6d;}}
  .badge-high {{ background:#ff8a0033; color:#ff8a00; border:1px solid #ff8a00;}}
  .badge-medium {{ background:#ffd60033; color:#ffd600; border:1px solid #ffd600;}}
  .badge-low {{ background:#00e0ff22; color:#00e0ff; border:1px solid #00e0ff;}}
  .badge-info {{ background:#8888aa22; color:#aaaacc; border:1px solid #aaaacc;}}
  .detail {{ background:#0a0c12; padding:10px 14px; border-left:2px solid #00d4ff55; font-size:12px; color:#b9e4f0;}}
  .detail p {{ margin:4px 0; }}
  .banner {{ border:1px solid #1c4a5f; padding:10px; margin-bottom:12px; color:#8ad; font-size:12px;}}
</style></head>
<body>
<h1>KHMatrix Cyber-Security Auditor &mdash; Assessment Report</h1>
<div class="banner">Generated {esc(ctx['generated_at'])} &middot; Authorized asset: {esc(a['target'])} &middot; Environment: {esc(a.get('environment') or 'n/a')}</div>

<h2>Executive Summary</h2>
<div class="summary">
  <div class="card">CRITICAL<br><b>{c['CRITICAL']}</b></div>
  <div class="card">HIGH<br><b>{c['HIGH']}</b></div>
  <div class="card">MEDIUM<br><b>{c['MEDIUM']}</b></div>
  <div class="card">LOW<br><b>{c['LOW']}</b></div>
  <div class="card">INFO<br><b>{c['INFO']}</b></div>
</div>

<h2>Asset Inventory</h2>
<table>
<tr><th>IP</th><th>Device Type</th><th>Confidence</th><th>Hostname</th><th>OS Indicator</th><th>Open Ports/Services</th></tr>
{host_rows}
</table>

<h2>Vulnerability Findings</h2>
<table>
<tr><th>ID</th><th>Title</th><th>Severity</th><th>Priority</th><th>Confidence</th><th>Location</th><th>CVE</th><th>CVSS</th></tr>
{''.join(rows)}
</table>

<h2>Notes</h2>
<div class="banner">
KHMatrix performs non-destructive assessment only. Findings marked "MANUAL VERIFICATION REQUIRED" or
"POTENTIAL" were not exploited or empirically confirmed and require authorized manual review before
being treated as confirmed vulnerabilities.
</div>
</body></html>"""
