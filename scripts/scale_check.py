"""Bounded, reproducible real correlation and paginated API benchmark.

Run .venv/bin/python scripts/scale_check.py --output .local/scale-results.json.
The isolated database is retained for inspection; it never replaces the user's DB.
"""
import argparse
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / ".local" / "scale-results.json"))
    args = parser.parse_args()
    (ROOT / ".local").mkdir(exist_ok=True)
    descriptor, path = tempfile.mkstemp(prefix="scale-", suffix=".db", dir=ROOT / ".local")
    os.close(descriptor)
    os.environ["RISKSCOPE_DATABASE_URL"] = f"sqlite:///{path}"
    subprocess.run(
        [str(ROOT / ".venv/bin/alembic"), "upgrade", "head"], cwd=ROOT / "backend", check=True
    )
    from sqlalchemy import func, insert, select
    from fastapi.testclient import TestClient
    from app import models as m
    from app.db import SessionLocal
    from app.main import app
    from app.services.engine import correlate

    timings = {}
    started = time.perf_counter()
    with SessionLocal() as db:
        proof = m.Evidence(
            type="IMPORT_RECORD", source="Synthetic bounded scale fixture",
            summary="Synthetic records solely for local load measurement",
        )
        db.add(proof)
        db.flush()
        evidence_id = proof.id
        db.execute(insert(m.Asset), [
            {"id": i + 1, "hostname": f"SCALE-{i + 1:04d}", "environment": "PRODUCTION" if i < 10 else "LAB",
             "criticality": "CRITICAL" if i % 100 == 99 else "LOW", "owner": "Synthetic scale owner",
             "exposure": "INTERNET_FACING" if i < 5 else "INTERNAL_ONLY", "evidence_id": evidence_id}
            for i in range(1000)
        ])
        db.execute(insert(m.Software), [
            {"id": i + 1, "canonical_name": f"fixture-package-{i}", "vendor": "Synthetic",
             "ecosystem": "generic", "evidence_id": evidence_id} for i in range(2000)
        ])
        db.execute(insert(m.SoftwareInstallation), [
            {"id": i + 1, "asset_id": i // 10 + 1, "software_id": i % 2000 + 1,
             "original_name": f"fixture-package-{i % 2000}", "version": "1.0.0",
             "evidence_id": evidence_id}
            for i in range(10000)
        ])
        db.execute(insert(m.Vulnerability), [
            {"id": i + 1, "identifier": f"SYNTH-SCALE-{i + 1:05d}", "title": f"Synthetic advisory {i + 1}",
             "cvss_score": 7.5, "synthetic": True, "known_exploited": False,
             "evidence_id": evidence_id} for i in range(10000)
        ])
        db.execute(insert(m.AffectedRange), [
            {"vulnerability_id": i + 1, "product": f"fixture-package-{i // 5}", "vendor": "Synthetic",
             "ecosystem": "generic", "version_scheme": "numeric", "affected": ">=1.0,<2.0",
             "fixed_versions": ["2.0.0"], "evidence_id": evidence_id} for i in range(10000)
        ])
        for start in range(0, 1000, 100):
            db.execute(insert(m.AssetRelationship), [
                {"source_asset_id": i + 1, "target_asset_id": (i + offset) % 1000 + 1,
                 "type": "CONNECTS_TO", "description": "Synthetic connectivity", "evidence_id": evidence_id}
                for i in range(start, start + 100) for offset in range(1, 51)
            ])
        db.commit()
        timings["populate_seconds"] = round(time.perf_counter() - started, 3)
        started = time.perf_counter()
        result = correlate(db)
        db.commit()
        timings["correlate_seconds"] = round(time.perf_counter() - started, 3)
        counts = {
            model.__tablename__: db.scalar(select(func.count()).select_from(model))
            for model in (m.Asset, m.SoftwareInstallation, m.Vulnerability, m.AssetRelationship,
                          m.VulnerabilityMatch, m.RiskAssessment, m.RiskFactor, m.AttackPath)
        }
    assert counts["asset"] == 1000
    assert counts["software_installation"] == 10000
    assert counts["vulnerability"] == 10000
    assert counts["asset_relationship"] == 50000
    assert counts["vulnerability_match"] == 50000, counts
    pages = {}
    with TestClient(app) as client:
        for endpoint in ("assets", "installations", "vulnerabilities", "relationships", "risk"):
            started = time.perf_counter()
            response = client.get(f"/api/{endpoint}", params={"page": 2, "page_size": 25})
            elapsed = time.perf_counter() - started
            assert response.status_code == 200, response.text
            assert len(response.json()["items"]) == 25
            pages[endpoint] = {
                "seconds": round(elapsed, 4), "response_bytes": len(response.content),
                "total": response.json()["total"], "returned": len(response.json()["items"]),
            }
        for endpoint in ("dashboard", "graph"):
            started = time.perf_counter()
            response = client.get(f"/api/{endpoint}")
            assert response.status_code == 200, response.text
            pages[endpoint] = {"seconds": round(time.perf_counter() - started, 4),
                               "response_bytes": len(response.content)}
            if endpoint == "graph":
                pages[endpoint]["truncated"] = response.json()["truncated"]
                assert response.json()["truncated"] is True
    output = {
        "database": path, "counts": counts, "timings": timings, "pages": pages,
        "correlation_result": result, "peak_rss_platform_units": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "python": sys.version, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    Path(args.output).write_text(json.dumps(output, indent=2))
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
