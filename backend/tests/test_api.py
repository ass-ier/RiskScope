import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app import models as m


def post(client, url, data):
    response = client.post(url, json=data)
    assert response.status_code == 200, response.text
    return response.json()


def seed(client):
    result = client.post("/api/demo")
    assert result.status_code == 200, result.text
    risks = client.get("/api/risk", params={"page_size": 100}).json()["items"]
    assets = client.get("/api/assets", params={"search": "WEB-01"}).json()["items"]
    return next(risk for risk in risks if risk["asset_id"] == assets[0]["id"] and risk["match_id"])


def test_empty_workspace(client):
    result = client.get("/api/dashboard").json()
    assert result["totals"]["assets"] == 0
    assert result["trend"] == []
    assert client.get("/api/meta").json()["assets"]["writable"]


def test_demo_never_overwrites_existing_inventory(client):
    asset = post(client, "/api/assets", {"hostname": "WEB-01", "owner": "Existing local owner"})
    response = client.post("/api/demo")
    assert response.status_code == 422 and "empty inventory" in response.text
    assert client.get(f"/api/assets/{asset['id']}").json()["owner"] == "Existing local owner"


def test_crud_context_and_audit(client):
    zone = post(client, "/api/zones", {"name": "DMZ", "subnet": "10.0.0.0/24"})
    asset = post(client, "/api/assets", {"hostname": "EDIT-01", "zone_id": zone["id"]})
    assert asset["exposure"] == "UNKNOWN"
    response = client.patch(f"/api/assets/{asset['id']}", json={
        "environment": "PRODUCTION", "criticality": "CRITICAL", "exposure": "INTERNET_FACING"
    })
    assert response.status_code == 200, response.text
    post(client, "/api/business-context", {
        "asset_id": asset["id"], "business_owner": "Analyst", "data_classification": "RESTRICTED"
    })
    observations = client.get("/api/exposure-observations", params={"asset_id": asset["id"]}).json()
    assert observations["total"] == 1
    audit = client.get("/api/audit", params={"object_type": "asset", "order": "desc"}).json()
    assert any(event["before"].get("criticality") == "UNKNOWN" and
               event["after"].get("criticality") == "CRITICAL" for event in audit["items"])
    assert client.post("/api/assets", json={"hostname": "EDIT-01"}).status_code == 409


def test_input_validation_and_cross_asset_service(client):
    one = post(client, "/api/assets", {"hostname": "ONE"})
    two = post(client, "/api/assets", {"hostname": "TWO"})
    software = post(client, "/api/software", {"canonical_name": "nginx"})
    installation = post(client, "/api/installations", {
        "asset_id": one["id"], "software_id": software["id"], "original_name": "nginx", "version": "1.24.0"
    })
    assert client.post("/api/services", json={
        "asset_id": two["id"], "installation_id": installation["id"], "name": "HTTPS", "port": 443
    }).status_code == 422
    assert client.post("/api/services", json={"asset_id": one["id"], "name": "HTTPS", "port": 65536}).status_code == 422
    assert client.post("/api/assets", json={"hostname": "X", "criticality": "banana"}).status_code == 422
    assert client.get("/api/assets?sort=id;DROP TABLE asset").status_code == 422
    assert client.get("/api/assets?page_size=1000").status_code == 422
    assert client.get("/api/assets?unexpected=1").status_code == 422


def test_import_rows_errors_formula_and_limit(client):
    raw = b"hostname,environment\nGOOD,production\nBAD,not-real\n"
    response = client.post("/api/imports/assets", files={"file": ("inventory.csv", raw, "text/csv")})
    assert response.status_code == 200, response.text
    job = response.json()
    assert job["imported"] == 1 and job["rejected"] == 1
    error = client.get(f"/api/imports/{job['id']}/errors.csv")
    assert error.status_code == 200 and "not-real" in error.text
    assert client.post("/api/imports/assets", files={
        "file": ("bad.json", b"{" * 50, "application/json")
    }).status_code == 422
    assert client.post("/api/imports/assets", files={
        "file": ("large.csv", b"x" * (10 * 1024 * 1024 + 1), "text/csv")
    }).status_code == 413
    assert client.post("/api/assets", json={"hostname": "EVIL"},
                       headers={"Origin": "https://attacker.example"}).status_code == 403


def test_analyst_override_preserves_automated_result(client):
    risk = seed(client)
    changed = post(client, f"/api/risk/{risk['id']}/review", {
        "actor": "Analyst", "reason": "Documented emergency exception", "priority": "LOW",
        "severity": "MEDIUM", "exposure": "RESTRICTED", "confidence": "HIGH",
    })
    assert changed["priority"] == risk["priority"]
    assert changed["analyst_override"]["priority"] == "LOW"
    client.post("/api/correlation/run")
    again = client.get(f"/api/risk/{risk['id']}").json()
    assert again["analyst_override"]["priority"] == "LOW"
    assert client.get("/api/risk?priority=LOW").json()["total"] >= 1
    assert client.post(f"/api/risk/{risk['id']}/review", json={
        "actor": "Analyst", "reason": "", "priority": "HIGH"
    }).status_code == 422


def test_remediation_verification_gating_and_audit(client):
    risk = seed(client)
    task = post(client, "/api/remediation", {
        "risk_id": risk["id"], "action": "Apply supported fixture upgrade", "owner": "Infra",
        "due_date": "2026-01-01", "status": "ASSIGNED",
    })
    assert client.patch(f"/api/remediation/{task['id']}", json={"status": "VERIFIED"}).status_code == 422
    assert client.post(f"/api/risk/{risk['id']}/verify", json={
        "actor": "Analyst", "reason": "Test", "evidence_id": 9999999
    }).status_code == 404
    proof = post(client, "/api/evidence", {
        "type": "REMEDIATION_EVIDENCE", "summary": "Observed vendor-backported patch, signed package record",
        "actor": "Analyst", "source": "Manual verification",
    })
    verification = post(client, f"/api/risk/{risk['id']}/verify", {
        "actor": "Analyst", "reason": "Verified documented vendor backport",
        "evidence_id": proof["id"],
    })
    assert verification["before"]["status"] != "VERIFIED"
    assert verification["after"]["status"] == "VERIFIED"
    assert client.get(f"/api/remediation/{task['id']}").json()["status"] == "VERIFIED"
    assert client.get("/api/risk", params={"active": "true", "ids": str(risk["id"])}).json()["total"] == 0
    assert client.get("/api/risk", params={"active": "false", "ids": str(risk["id"])}).json()["total"] == 1


def test_acceptance_expiry_reopens_and_retains_history(client, db):
    risk = seed(client)
    record = post(client, f"/api/risk/{risk['id']}/accept", {
        "reason": "Approved temporary exception", "approver": "Risk owner",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        "compensating_controls": "Restricted ingress with monitoring",
    })
    assert client.get(f"/api/risk/{risk['id']}").json()["status"] == "RISK_ACCEPTED"
    acceptance = db.get(m.RiskAcceptance, record["id"])
    acceptance.expires_at = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    db.commit()
    assert client.get(f"/api/risk/{risk['id']}").json()["status"] == "OPEN"
    assert client.get("/api/acceptances", params={"risk_id": risk["id"]}).json()["total"] == 1
    assert client.post(f"/api/risk/{risk['id']}/accept", json={
        "reason": "Past", "approver": "Owner", "expires_at": "2020-01-01T00:00:00Z",
        "compensating_controls": "None",
    }).status_code == 422


def test_rejected_and_deferred_consistent_queue(client):
    risk = seed(client)
    for status in ("FALSE_POSITIVE", "DEFERRED"):
        post(client, f"/api/risk/{risk['id']}/review", {
            "actor": "Analyst", "reason": "Documented review", "status": status,
        })
        client.post("/api/correlation/run")
        assert client.get("/api/risk", params={"active": "true", "ids": str(risk["id"])}).json()["total"] == 0
        assert client.get(f"/api/risk/{risk['id']}").json()["status"] == status
        post(client, f"/api/risk/{risk['id']}/review", {
            "actor": "Analyst", "reason": "Reopen for next action", "status": "OPEN"
        })


def test_reports_all_formats_and_complete_json(client):
    risk = seed(client)
    post(client, "/api/assets", {"hostname": "=SUM(1,1)"})
    for perspective in ("executive", "technical"):
        report = post(client, "/api/reports", {"title": "Fixture report", "perspective": perspective})
        identifier = report["id"]
        for format in ("pdf", "markdown", "json"):
            response = client.get(f"/api/reports/{identifier}/export", params={"format": format})
            assert response.status_code == 200, response.text
            assert len(response.content) > 100
            if format == "pdf":
                assert response.content.startswith(b"%PDF")
            if format == "json":
                snapshot = response.json()
                assert any(row["id"] == risk["id"] for row in snapshot["risk"])
                for key in ("evidence", "audit", "installations", "affected-ranges", "matches",
                            "assessment-history", "verifications", "acceptances", "attack-paths"):
                    assert key in snapshot
        for dataset in ("risk", "assets", "vulnerabilities", "remediation"):
            csv = client.get(f"/api/reports/{identifier}/export", params={"format": "csv", "dataset": dataset})
            assert csv.status_code == 200 and csv.content
            if dataset == "assets":
                assert "'=SUM" in csv.text
        assert client.get("/api/reports").json()["items"][-1].get("snapshot") is None


def test_graph_relationship_removal_and_case_workflow(client):
    risk = seed(client)
    graph = client.get("/api/graph").json()
    assert graph["nodes"] and graph["edges"]
    paths = client.get("/api/attack-paths", params={"risk_id": risk["id"]}).json()["items"]
    assert paths
    identifier = paths[0]["relationship_ids"][0]
    assert client.delete(f"/api/relationships/{identifier}").status_code == 200
    remaining = client.get("/api/attack-paths", params={"risk_id": risk["id"]}).json()["items"]
    assert all(identifier not in row["relationship_ids"] for row in remaining)
    case = post(client, "/api/cases", {"title": "Investigate critical fixture"})
    post(client, "/api/case-risks", {"case_id": case["id"], "risk_id": risk["id"]})
    post(client, "/api/case-assets", {"case_id": case["id"], "asset_id": risk["asset_id"]})
    post(client, "/api/notes", {"case_id": case["id"], "actor": "Analyst", "text": "Reviewed evidence"})
    assert client.get("/api/notes", params={"case_id": case["id"]}).json()["total"] == 1


def test_settings_recalculate_and_risk_comparison(client):
    risk = seed(client)
    original = client.get("/api/settings").json()
    settings = {**original, "weights": {key: 0 for key in original["weights"]}}
    response = client.put("/api/settings", json=settings)
    assert response.status_code == 200, response.text
    updated = client.get(f"/api/risk/{risk['id']}").json()
    assert updated["score"] == 0
    assert updated["rules_version"] != risk["rules_version"]
    risks = client.get("/api/risk").json()["items"]
    ids = ",".join(str(row["id"]) for row in risks[:2])
    comparison = client.get("/api/risk/compare", params={"ids": ids})
    assert comparison.status_code == 200 and len(comparison.json()["explanation"]) == 2


def test_reference_safety_and_history_queries(client, db):
    seed(client)
    vuln = db.scalar(select(m.Vulnerability))
    assert client.post("/api/references", json={
        "vulnerability_id": vuln.id, "url": "javascript:alert(1)"
    }).status_code == 422
    for route in ("timeline", "audit", "assessment-history", "snapshots"):
        result = client.get(f"/api/{route}", params={"page_size": 2})
        assert result.status_code == 200
        assert len(result.json()["items"]) <= 2
    assert json.loads(client.get("/openapi.json").text)["info"]["title"] == "RiskScope"


def test_context_filters_retirement_and_snapshot_pagination(client):
    risk = seed(client)
    match = client.get(f"/api/matches/{risk['match_id']}").json()
    installation = client.get(f"/api/installations/{match['installation_id']}").json()
    software_id = installation["software_id"]
    for route in ("risk", "matches", "components"):
        response = client.get(f"/api/{route}", params={"software_id": software_id})
        assert response.status_code == 200, response.text
    post(client, "/api/remediation", {
        "risk_id": risk["id"], "action": "Fixture patch", "due_date": "2020-01-01"
    })
    assert client.get("/api/remediation", params={"asset_id": risk["asset_id"]}).json()["total"] == 1
    assert client.get("/api/risk?overdue=true").json()["total"] >= 1
    paths = client.get("/api/attack-paths", params={"asset_id": risk["asset_id"]})
    assert paths.status_code == 200 and paths.json()["total"] > 0
    service = post(client, "/api/services", {"asset_id": risk["asset_id"], "name": "Old service", "port": 22})
    assert client.delete(f"/api/services/{service['id']}").status_code == 200
    assert client.get("/api/services", params={"ids": str(service["id"])}).json()["total"] == 0
    assert client.get(f"/api/services/{service['id']}").json()["status"] == "REMOVED"
    report = post(client, "/api/reports", {"title": "Paginated snapshot"})
    assert "snapshot" not in report
    summary = client.get(f"/api/reports/{report['id']}/summary")
    assert summary.status_code == 200 and "dashboard" in summary.json()
    rows = client.get(f"/api/reports/{report['id']}/records/risk?page_size=1&page=2")
    assert rows.status_code == 200, rows.text
    assert len(rows.json()["items"]) == 1 and rows.json()["total"] >= 2


def test_deadlines_match_dashboard_queue_and_trend(client):
    risk = seed(client)
    today = datetime.now(timezone.utc).date().isoformat()
    tasks = [post(client, "/api/remediation", {
        "risk_id": risk["id"], "action": f"Task {index}", "due_date": today
    }) for index in range(2)]
    assert client.get("/api/dashboard").json()["overdue"] == 0
    for task in tasks:
        assert client.patch(f"/api/remediation/{task['id']}", json={"due_date": "2020-01-01"}).status_code == 200
    client.post("/api/correlation/run")
    dashboard = client.get("/api/dashboard").json()
    assert dashboard["overdue"] == 1
    assert dashboard["trend"][-1]["overdue"] == 1
    assert client.get("/api/risk?overdue=true").json()["total"] == 1
    post(client, f"/api/risk/{risk['id']}/review", {
        "actor": "Analyst", "reason": "Deferred with retained deadlines", "status": "DEFERRED"
    })
    assert client.get("/api/dashboard").json()["overdue"] == 0
    assert client.get("/api/risk?overdue=true").json()["total"] == 0


def test_positive_fractional_severity_is_not_informational(client):
    risk = seed(client)
    response = client.patch(f"/api/vulnerabilities/{risk['vulnerability_id']}", json={"cvss_score": 0.05})
    assert response.status_code == 200, response.text
    assert client.get(f"/api/risk/{risk['id']}").json()["severity"] == "LOW"


def test_inventory_edit_verifies_and_reintroduction_reopens(client):
    risk = seed(client)
    match = client.get(f"/api/matches/{risk['match_id']}").json()
    endpoint = f"/api/installations/{match['installation_id']}"
    response = client.patch(endpoint, json={"version": "1.26.2"},
                            params={"reason": "Observed supported fixture upgrade", "actor": "Analyst"})
    assert response.status_code == 200, response.text
    verified = client.get(f"/api/risk/{risk['id']}").json()
    assert verified["status"] == "VERIFIED"
    assert verified["score"] == 0 and verified["priority"] == "INFORMATIONAL"
    assert any(factor["name"] == "applicability" for factor in verified["factors"])
    assert client.patch(endpoint, json={"version": "1.24.0"}).status_code == 200
    assert client.get(f"/api/risk/{risk['id']}").json()["status"] == "OPEN"
    assert client.get("/api/verifications", params={"risk_id": risk["id"]}).json()["total"] == 1


def test_dashboard_focus_filters_match_evidence_counts(client):
    risk = seed(client)
    post(client, f"/api/risk/{risk['id']}/review", {
        "actor": "Analyst", "reason": "Distinguish environment from global intelligence",
        "exposure": "EXTERNALLY_REACHABLE", "exploitability": "NO_KNOWN_EXPLOIT"
    })
    dashboard = client.get("/api/dashboard").json()
    assert client.get("/api/risk?internet_exposed=true&active=true").json()["total"] == dashboard["internet_exposed"]
    assert client.get("/api/risk?known_exploited=true&active=true").json()["total"] == dashboard["known_exploited"]


def test_new_unknown_version_does_not_keep_stale_verification(client):
    risk = seed(client)
    match = client.get(f"/api/matches/{risk['match_id']}").json()
    endpoint = f"/api/installations/{match['installation_id']}"
    assert client.patch(endpoint, json={"version": "1.26.2"}).status_code == 200
    assert client.patch(endpoint, json={"version": "vendor-unknown-build"}).status_code == 200
    current = client.get(f"/api/risk/{risk['id']}").json()
    assert current["status"] == "OPEN" and current["confidence"] == "UNKNOWN"
    assert client.get(f"/api/matches/{risk['match_id']}").json()["state"] == "NEEDS_REVIEW"
