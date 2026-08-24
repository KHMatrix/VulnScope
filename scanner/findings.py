"""
KHMatrix - Finding Model & Risk Prioritization
"""
import uuid
from datetime import datetime

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
CONFIDENCE_WEIGHT = {
    "CONFIRMED BY SAFE CHECK": 1.0,
    "VERSION MATCH": 0.85,
    "POTENTIAL": 0.6,
    "INFORMATIONAL": 0.4,
    "MANUAL VERIFICATION REQUIRED": 0.3,
}


def new_finding_id():
    return f"KHM-{uuid.uuid4().hex[:10].upper()}"


def normalize_finding(raw: dict, scan_id: int, asset_id: int, host_ip=None, hostname=None) -> dict:
    """Fill in every field from the required finding model, defaulting safely."""
    now_iso = datetime.utcnow().isoformat() + "Z"
    return {
        "finding_ref": raw.get("finding_ref") or new_finding_id(),
        "scan_id": scan_id,
        "asset_id": asset_id,
        "title": raw.get("title", "Untitled finding"),
        "severity": raw.get("severity", "INFO"),
        "confidence": raw.get("confidence", "INFORMATIONAL"),
        "host_ip": raw.get("host_ip", host_ip),
        "hostname": raw.get("hostname", hostname),
        "port": raw.get("port"),
        "protocol": raw.get("protocol"),
        "service": raw.get("service"),
        "product": raw.get("product"),
        "version": raw.get("version"),
        "url": raw.get("url"),
        "description": raw.get("description", ""),
        "evidence": raw.get("evidence", ""),
        "security_impact": raw.get("security_impact", ""),
        "attacker_impact": raw.get(
            "attacker_impact",
            "Manual authorized verification required. No exploitation was performed; the practical impact "
            "if this weakness were successfully abused has not been empirically confirmed.",
        ),
        "cve": raw.get("cve"),
        "cwe": raw.get("cwe"),
        "cvss": raw.get("cvss"),
        "affected_versions": raw.get("affected_versions"),
        "remediation_immediate": raw.get("remediation_immediate", ""),
        "remediation_permanent": raw.get("remediation_permanent", ""),
        "verification": raw.get("verification", "Re-scan after remediation to confirm the finding no longer reproduces."),
        "refs": ", ".join(raw.get("references", [])) if isinstance(raw.get("references"), list) else raw.get("refs", ""),
        "first_seen": now_iso,
        "last_seen": now_iso,
        "status": "open",
    }


def risk_priority(finding: dict) -> str:
    """FIX FIRST / FIX SOON / NORMAL MAINTENANCE / INFORMATIONAL"""
    sev = SEVERITY_ORDER.get(finding.get("severity", "INFO"), 0)
    conf = CONFIDENCE_WEIGHT.get(finding.get("confidence", "INFORMATIONAL"), 0.3)
    cvss = finding.get("cvss") or 0
    score = (sev * 2 + (cvss / 10) * 3) * conf

    if finding.get("severity") == "INFO":
        return "INFORMATIONAL"
    if score >= 5.5:
        return "FIX FIRST"
    if score >= 3:
        return "FIX SOON"
    return "NORMAL MAINTENANCE"


def sort_findings(findings: list) -> list:
    def key(f):
        return (
            -SEVERITY_ORDER.get(f.get("severity", "INFO"), 0),
            -(f.get("cvss") or 0),
            -CONFIDENCE_WEIGHT.get(f.get("confidence", "INFORMATIONAL"), 0),
        )
    return sorted(findings, key=key)


def summarize_counts(findings: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in counts:
            counts[sev] += 1
    return counts
