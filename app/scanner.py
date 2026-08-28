import json
import subprocess
from app.config import settings

SEVERITIES = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def scan_image(image: str) -> dict:
    cmd = [
        "trivy", "image", "--quiet", "--format", "json",
        "--scanners", "vuln", image
    ]
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=settings.trivy_timeout_seconds, check=False
        )
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "Trivy scan timed out"}

    if p.returncode not in (0, 1):
        return {"status": "error", "error": p.stderr[-2000:]}

    try:
        raw = json.loads(p.stdout or "{}")
    except json.JSONDecodeError:
        return {"status": "error", "error": "Invalid Trivy JSON output"}

    findings = []
    for target in raw.get("Results", []) or []:
        for v in target.get("Vulnerabilities", []) or []:
            findings.append({
                "target": target.get("Target"),
                "vulnerability_id": v.get("VulnerabilityID"),
                "package": v.get("PkgName"),
                "installed_version": v.get("InstalledVersion"),
                "fixed_version": v.get("FixedVersion"),
                "severity": v.get("Severity", "UNKNOWN"),
                "title": v.get("Title"),
            })

    threshold = settings.fail_on_severity.upper()
    threshold_value = SEVERITIES.get(threshold, 4)
    blocking = [x for x in findings if SEVERITIES.get(x["severity"], 0) >= threshold_value]
    return {
        "status": "completed",
        "image": image,
        "finding_count": len(findings),
        "blocking_count": len(blocking),
        "policy": {"fail_on_severity": threshold, "passed": not blocking},
        "vulnerabilities": findings,
    }
