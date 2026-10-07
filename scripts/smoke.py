"""Run the complete analyst workflow against a real loopback HTTP server.

Use a fresh isolated database, not a workspace containing personal data.
Example: .venv/bin/python scripts/smoke.py http://127.0.0.1:8765
"""
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone


BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8765"
if urllib.parse.urlsplit(BASE).hostname not in ("127.0.0.1", "localhost", "::1"):
    raise SystemExit("Smoke tests may run only on loopback")


def request(method, path, data=None, headers=None):
    payload = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(BASE + "/api" + path, data=payload, method=method,
                                 headers=headers or {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            body = response.read()
            return json.loads(body) if "application/json" in response.headers.get("Content-Type", "") else body
    except urllib.error.HTTPError as exc:
        raise AssertionError(f"{method} {path}: {exc.code}: {exc.read().decode()}") from exc


def upload(kind, value, filename, asset_id=None):
    raw = value.encode() if isinstance(value, str) else json.dumps(value).encode()
    boundary = "RiskScopeSmokeBoundary"
    body = bytearray()
    if asset_id is not None:
        body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="asset_id"\r\n\r\n{asset_id}\r\n'.encode())
    body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                'Content-Type: application/octet-stream\r\n\r\n'.encode())
    body.extend(raw)
    body.extend(f"\r\n--{boundary}--\r\n".encode())
    req = urllib.request.Request(
        BASE + "/api/imports/" + kind, data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        raise AssertionError(f"Import {kind}: {exc.code}: {exc.read().decode()}") from exc
    assert result["rejected"] == 0, result
    return result


def main():
    assert request("GET", "/health")["status"] == "ok"
    if request("GET", "/assets")["total"]:
        raise SystemExit("Smoke workflow requires a fresh database (will not overwrite user records)")
    jobs = []
    jobs.append(upload("assets", [
        {"hostname": "WEB-01", "environment": "PRODUCTION", "criticality": "CRITICAL",
         "exposure": "INTERNET_FACING", "owner": "Infrastructure", "source": "Synthetic workflow fixture"},
        {"hostname": "WEB-02", "environment": "DEVELOPMENT", "criticality": "LOW",
         "exposure": "INTERNAL_ONLY", "owner": "Development", "source": "Synthetic workflow fixture"},
        {"hostname": "APP-01", "environment": "PRODUCTION", "criticality": "HIGH", "owner": "Applications"},
        {"hostname": "DB-01", "environment": "PRODUCTION", "criticality": "CRITICAL", "owner": "Data"},
    ], "workflow-assets.json"))
    assets = {r["hostname"]: r["id"] for r in request("GET", "/assets")["items"]}
    jobs.append(upload("software", "hostname,product,vendor,version\n"
                       "WEB-01,nginx,nginx,1.24.0\nWEB-02,nginx,nginx,1.24.0\n", "workflow-software.csv"))
    jobs.append(upload("sbom", {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"bom-ref": "app", "type": "application", "name": "ExampleApp", "version": "1.0.0"}},
        "components": [
            {"bom-ref": "direct", "type": "library", "name": "example-direct", "version": "1.0.0"},
            {"bom-ref": "transitive", "type": "library", "name": "example-transitive", "version": "1.0.0"},
        ],
        "dependencies": [{"ref": "app", "dependsOn": ["direct"]}, {"ref": "direct", "dependsOn": ["transitive"]}],
    }, "workflow-sbom.json", assets["WEB-01"]))
    jobs.append(upload("vulnerabilities", [{
        "identifier": "SYNTH-WORKFLOW-001", "title": "Synthetic nginx demonstration advisory",
        "description": "Fictional fixture, not an advisory about nginx.", "cvss_score": 9.8,
        "known_exploited": True, "exploit_available": True, "synthetic": True,
        "source": "Synthetic workflow intelligence", "attack_complexity": "LOW", "privileges_required": "NONE",
        "recommendation": "For this synthetic fixture only, upgrade to fixture version 1.26.2.",
        "affected_ranges": [{"product": "nginx", "vendor": "nginx", "ecosystem": "generic",
                             "version_scheme": "numeric", "affected": ">=1.20,<1.26.2",
                             "fixed_versions": ["1.26.2"]}],
    }], "workflow-advisories.json"))
    for source, target in (("WEB-01", "APP-01"), ("APP-01", "DB-01")):
        request("POST", "/relationships", {
            "source_asset_id": assets[source], "target_asset_id": assets[target], "type": "CONNECTS_TO",
            "description": "Synthetic documented service connectivity", "source": "Synthetic network fixture",
        })
    request("POST", "/business-context", {
        "asset_id": assets["WEB-01"], "business_owner": "ExampleCorp",
        "application": "Authentication", "data_classification": "RESTRICTED",
        "business_function": "Synthetic production login service",
    })
    installation = next(i for i in request("GET", "/installations")["items"]
                        if i["asset_id"] == assets["WEB-01"] and i["original_name"] == "nginx")
    request("POST", "/services", {
        "asset_id": assets["WEB-01"], "installation_id": installation["id"],
        "name": "HTTPS", "port": 443, "protocol": "TCP", "exposure": "INTERNET_FACING", "status": "RUNNING",
    })
    request("POST", "/exposure-observations", {
        "asset_id": assets["WEB-01"], "exposure": "INTERNET_FACING",
        "note": "Synthetic load-balancer inventory evidence", "source": "Synthetic network observation",
    })
    vuln = request("GET", "/vulnerabilities")["items"][0]
    request("POST", "/exploitability-observations", {
        "asset_id": assets["WEB-01"], "vulnerability_id": vuln["id"],
        "reachability": "REACHABLE", "complexity": "LOW", "privileges": "NONE",
        "note": "Synthetic prerequisites observation", "source": "Synthetic analyst evidence",
    })
    correlation = request("POST", "/correlation/run")
    risks = request("GET", "/risk?page_size=100")["items"]
    web = next(r for r in risks if r["asset_id"] == assets["WEB-01"] and r["vulnerability_id"] == vuln["id"])
    dev = next(r for r in risks if r["asset_id"] == assets["WEB-02"] and r["vulnerability_id"] == vuln["id"])
    assert web["priority"] == "CRITICAL" and web["score"] > dev["score"], (web, dev)
    assert web["factors"] and web["reasoning"] and web["evidence_ids"]
    compare = request("GET", f"/risk/compare?ids={web['id']},{dev['id']}")
    assert len(compare["explanation"]) == 2
    paths = request("GET", f"/attack-paths?risk_id={web['id']}")["items"]
    assert any(path["asset_ids"] == [assets["WEB-01"], assets["APP-01"], assets["DB-01"]] for path in paths), paths
    task = request("POST", "/remediation", {
        "risk_id": web["id"], "action": "Upgrade to supported synthetic fixture version",
        "fixed_version": "1.26.2", "owner": "Infrastructure", "priority": "CRITICAL",
        "due_date": (datetime.now(timezone.utc) + timedelta(days=7)).date().isoformat(), "status": "IN_PROGRESS",
    })
    before_report = request("POST", "/reports", {"title": "Before fixture upgrade", "perspective": "technical"})
    before_active = request("GET", "/dashboard")["totals"]["active_risks"]
    jobs.append(upload("software", "hostname,product,vendor,version\nWEB-01,nginx,nginx,1.26.2\n", "upgrade.csv"))
    request("POST", "/correlation/run")
    after = request("GET", f"/risk/{web['id']}")
    assert after["status"] == "VERIFIED", after
    assert after["score"] == 0 and after["priority"] == "INFORMATIONAL", after
    assert request("GET", f"/remediation/{task['id']}")["status"] == "VERIFIED"
    after_active = request("GET", "/dashboard")["totals"]["active_risks"]
    assert after_active < before_active
    verification = request("GET", f"/verifications?risk_id={web['id']}")["items"]
    assert verification and verification[-1]["before"] and verification[-1]["after"]
    after_report = request("POST", "/reports", {"title": "After fixture upgrade", "perspective": "executive"})
    exports = {}
    for format in ("json", "markdown", "pdf"):
        content = request("GET", f"/reports/{after_report['id']}/export?format={format}")
        assert content
        exports[format] = len(json.dumps(content)) if isinstance(content, dict) else len(content)
    for dataset in ("risk", "assets", "vulnerabilities", "remediation"):
        content = request("GET", f"/reports/{after_report['id']}/export?format=csv&dataset={dataset}")
        assert content
        exports[f"csv_{dataset}"] = len(content)
    print(json.dumps({
        "workflow": "PASS", "imports": [{"kind": j["kind"], "imported": j["imported"]} for j in jobs],
        "web_priority": web["priority"], "web_score": web["score"], "development_score": dev["score"],
        "verified_score": after["score"], "verified_priority": after["priority"],
        "potential_paths": len(paths), "verification_status": after["status"],
        "verification_method": verification[-1]["method"], "risk_id": web["id"],
        "reports": [before_report["id"], after_report["id"]], "export_bytes": exports,
        "active_risks_before": before_active, "active_risks_after": after_active,
        "correlation": correlation,
    }, indent=2))


if __name__ == "__main__":
    main()
