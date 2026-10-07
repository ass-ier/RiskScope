import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.core.config import RuntimeConfig
from app.main import app

ORIGIN = "https://riskscope-test.vercel.app"


@pytest.fixture
def hosted(monkeypatch):
    monkeypatch.setenv("RISKSCOPE_MODE", "hosted")
    monkeypatch.setenv("RISKSCOPE_ALLOWED_ORIGINS", ORIGIN)
    with TestClient(app, headers={"Origin": ORIGIN}) as client:
        yield client


def session(client, workspace="uploads"):
    response = client.post("/api/session")
    assert response.status_code == 200, response.text
    return {
        "Authorization": f"Bearer {response.json()['token']}",
        "X-RiskScope-Workspace": workspace,
    }


def test_runtime_and_public_health_require_no_sign_in(hosted):
    assert hosted.get("/api/health").json()["mode"] == "hosted"
    runtime = hosted.get("/api/runtime").json()
    assert runtime["max_upload_bytes"] == 2 * 1024 * 1024
    assert runtime["idle_seconds"] == 3600
    assert hosted.get("/api/assets").status_code == 401
    assert hosted.get("/api/reports/1/export").status_code == 401


def test_private_uploads_and_demo_are_independent(hosted):
    first, second = session(hosted), session(hosted)
    response = hosted.post("/api/assets", headers=first, json={"hostname": "FIRST-GUEST-ONLY"})
    assert response.status_code == 200, response.text
    assert hosted.get("/api/assets", headers=first).json()["total"] == 1
    assert hosted.get("/api/assets", headers=second).json()["total"] == 0
    assert hosted.get("/api/assets/1", headers=second).status_code == 404
    assert hosted.get("/api/evidence", headers=second).json()["total"] == 0
    assert hosted.get("/api/audit", headers=second).json()["total"] == 0
    demo = {**first, "X-RiskScope-Workspace": "demo"}
    assert hosted.get("/api/assets", headers=demo).json()["total"] == 9
    assert hosted.get("/api/vulnerabilities", headers=demo).json()["total"] == 4
    assert hosted.get("/api/attack-paths", headers=demo).json()["total"] == 2
    assert hosted.post("/api/demo", headers=first).status_code == 409
    assert hosted.post("/api/imports/assets", headers=demo, files={
        "file": ("assets.csv", b"hostname\nPRIVATE\n", "text/csv")
    }).status_code == 409


def test_upload_and_export_use_guest_capability(hosted):
    owner, other = session(hosted), session(hosted)
    job = hosted.post("/api/imports/assets", headers=owner, files={
        "file": ("private.csv", b"hostname,environment\nCUSTOM-01,production\n", "text/csv")
    })
    assert job.status_code == 200 and job.json()["imported"] == 1
    assert hosted.get("/api/imports", headers=other).json()["total"] == 0
    created = hosted.post("/api/reports", headers=owner, json={"title": "Guest-specific report"})
    assert created.status_code == 200, created.text
    report = created.json()["id"]
    assert hosted.get(f"/api/reports/{report}", headers=other).status_code == 404
    exported = hosted.get(f"/api/reports/{report}/export?format=json", headers=owner)
    assert exported.json()["assets"][0]["hostname"] == "CUSTOM-01"
    assert exported.headers["cache-control"] == "no-store"
    assert "Content-Disposition" in exported.headers["access-control-expose-headers"]
    assert hosted.get(f"/api/reports/{report}/export?format=pdf", headers=owner).content.startswith(b"%PDF")


def test_exact_cors_and_hostname_policy(hosted):
    preflight = hosted.options("/api/assets", headers={
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type,x-riskscope-workspace",
    })
    assert preflight.status_code == 204
    assert preflight.headers["Access-Control-Allow-Origin"] == ORIGIN
    assert "Access-Control-Allow-Credentials" not in preflight.headers
    for origin in ("https://attacker.vercel.app", ORIGIN + ".attacker.invalid", "null"):
        response = hosted.post("/api/session", headers={"Origin": origin})
        assert response.status_code == 403
        assert "access-control-allow-origin" not in response.headers
    assert hosted.post("/api/session", headers={"Origin": ""}).status_code == 403
    assert hosted.get("/api/health", headers={"Host": "untrusted.invalid"}).status_code == 400
    assert hosted.options("/api/assets", headers={
        "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "X-Unapproved"
    }).status_code == 403


def test_idle_expiry_cleans_files_and_invalidates_token(hosted):
    headers = session(hosted)
    manager = app.state.guests
    guest = next(iter(manager.guests.values()))
    directory = guest.directory
    manager.clock = lambda: guest.touched + manager.config.guest_idle_seconds + 1
    response = hosted.get("/api/assets", headers=headers)
    assert response.status_code == 410
    assert not directory.exists()
    assert not manager.guests


def test_absolute_expiry_despite_activity(hosted):
    headers = session(hosted)
    manager = app.state.guests
    guest = next(iter(manager.guests.values()))
    guest.created -= manager.config.guest_lifetime_seconds + 1
    assert hosted.get("/api/session", headers=headers).status_code == 410


def test_reset_only_selected_workspace_and_end_deletes_both(hosted):
    headers = session(hosted)
    hosted.post("/api/assets", headers=headers, json={"hostname": "TO-RESET"})
    reset = hosted.post("/api/session/reset", headers=headers, json={"workspace": "uploads"})
    assert reset.status_code == 200
    assert hosted.get("/api/assets", headers=headers).json()["total"] == 0
    assert hosted.get("/api/assets", headers={**headers, "X-RiskScope-Workspace": "demo"}).json()["total"] == 9
    guest = next(iter(app.state.guests.guests.values()))
    directory = guest.directory
    assert hosted.delete("/api/session", headers=headers).status_code == 204
    assert not directory.exists()
    assert hosted.get("/api/assets", headers=headers).status_code == 410


def test_old_tokens_cannot_survive_process_restart(monkeypatch):
    monkeypatch.setenv("RISKSCOPE_MODE", "hosted")
    monkeypatch.setenv("RISKSCOPE_ALLOWED_ORIGINS", ORIGIN)
    with TestClient(app, headers={"Origin": ORIGIN}) as first:
        headers = session(first)
        root = app.state.guests.root
    assert not root.exists()
    with TestClient(app, headers={"Origin": ORIGIN}) as second:
        assert second.get("/api/assets", headers=headers).status_code == 410


def test_invalid_workspace_and_tokens_cannot_select_files(hosted):
    headers = session(hosted)
    assert hosted.get("/api/assets", headers={**headers, "X-RiskScope-Workspace": "../../other"}).status_code == 422
    assert hosted.get("/api/assets", headers={"Authorization": "Bearer ../../other"}).status_code == 401
    assert hosted.post("/api/session/reset", headers=headers, json={"workspace": "../demo"}).status_code == 422
    assert hosted.get("/api/examples/not-a-fixture.json").status_code == 404


def test_all_synthetic_example_files_are_downloadable(hosted):
    files = hosted.get("/api/examples").json()
    assert len(files) == 6
    for file in files:
        response = hosted.get(f"/api/examples/{file['filename']}")
        assert response.status_code == 200 and response.content
        assert response.headers["Content-Disposition"].startswith("attachment")


def test_capacity_and_global_heavy_operation_limit(hosted):
    app.state.guests.config.guest_max_sessions = 1
    headers = session(hosted)
    assert hosted.post("/api/session").status_code == 503
    semaphore = app.state.guests.work
    semaphore.acquire()
    try:
        assert hosted.post("/api/correlation/run", headers=headers).status_code == 429
        assert hosted.get("/api/assets", headers=headers).status_code == 200
    finally:
        semaphore.release()


def test_hosted_record_and_upload_limits(hosted):
    headers = session(hosted)
    response = hosted.post("/api/imports/assets", headers=headers, files={
        "file": ("large.csv", b"x" * (2 * 1024 * 1024 + 1), "text/csv")
    })
    assert response.status_code == 413
    response = hosted.post("/api/imports/assets", headers=headers, files={
        "file": ("rows.json", json.dumps([{"hostname": f"HOST-{i}"} for i in range(1001)]).encode(), "application/json")
    })
    assert response.status_code == 422 and "1000" in response.text
    assert hosted.get("/api/assets", headers=headers).json()["total"] == 0
    assert hosted.get("/api/imports", headers=headers).json()["total"] == 0
    response = hosted.post("/api/imports/vulnerabilities", headers=headers, files={
        "file": ("ranges.json", json.dumps([{
            "identifier": "SYNTH-RANGE-LIMIT", "title": "Synthetic range limit",
            "affected_ranges": [{"product": "example", "affected": "<2"}] * 5001,
        }]).encode(), "application/json")
    })
    assert response.status_code == 422 and "5000" in response.text


def test_correlation_budget_rolls_back(hosted):
    headers = session(hosted)
    response = hosted.post("/api/imports/assets", headers=headers, files={
        "file": ("rows.json", json.dumps([{"hostname": f"HOST-{i}"} for i in range(101)]).encode(), "application/json")
    })
    assert response.status_code == 200
    app.state.guests.config.guest_max_correlations = 100
    assert hosted.post("/api/correlation/run", headers=headers).status_code == 413
    assert hosted.get("/api/risk", headers=headers).json()["total"] == 0


def test_sqlite_storage_is_bounded(hosted):
    session(hosted)
    guest = next(iter(app.state.guests.guests.values()))
    engine = guest.engines["uploads"]
    with engine.connect() as connection:
        size = connection.exec_driver_sql("PRAGMA page_size").scalar()
        limit = connection.exec_driver_sql("PRAGMA max_page_count").scalar()
        assert size * limit <= app.state.guests.config.guest_workspace_bytes
        connection.exec_driver_sql("CREATE TABLE quota_probe (data BLOB)")
        with pytest.raises(OperationalError) as error:
            connection.execute(text("INSERT INTO quota_probe VALUES (zeroblob(:size))"), {
                "size": app.state.guests.config.guest_workspace_bytes + 4096
            })
        assert error.value.orig.sqlite_errorcode == sqlite3.SQLITE_FULL
    assert Path(engine.url.database).stat().st_size <= app.state.guests.config.guest_workspace_bytes


def test_configuration_rejects_unbounded_origins(monkeypatch):
    monkeypatch.setenv("RISKSCOPE_MODE", "hosted")
    monkeypatch.delenv("RISKSCOPE_ALLOWED_ORIGINS", raising=False)
    with pytest.raises(ValueError, match="ALLOWED_ORIGINS"):
        RuntimeConfig.from_env()
    for origin in ("https://*.vercel.app", "http://public.example", "https://example.com/path"):
        with pytest.raises(ValueError):
            RuntimeConfig(mode="hosted", allowed_origins=(origin,))


def test_render_cannot_accidentally_publish_local_mode(monkeypatch):
    monkeypatch.setenv("RENDER_EXTERNAL_HOSTNAME", "riskscope-test.onrender.com")
    monkeypatch.setenv("RISKSCOPE_MODE", "local")
    with pytest.raises(ValueError, match="persistent unauthenticated"):
        RuntimeConfig.from_env()
