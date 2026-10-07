import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session

from app import models as m
from app.db import Base
from app.schemas import SettingsInput
from app.services import engine, imports
from app.services.common import evidence
from app.services.providers import CISAKEVProvider, LocalJSONProvider, NVDProvider, OSVProvider

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


@pytest.fixture
def domain_db():
    connection = create_engine("sqlite:///:memory:")

    @event.listens_for(connection, "connect")
    def foreign_keys(dbapi_connection, _):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(connection)
    with Session(connection) as session:
        yield session
        session.rollback()
    connection.dispose()


def rows(db, model):
    return list(db.scalars(select(model).order_by(model.id)))


def count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def load(db, kind, value, asset_id=None, filename=None):
    return imports.import_data(db, kind, json.dumps(value).encode(), filename or f"{kind}.json", asset_id)


def setup_asset(db, **overrides):
    values = {
        "hostname": "host", "owner": "Owner", "criticality": "LOW",
        "environment": "LAB", "exposure": "INTERNAL_ONLY",
    }
    values.update(overrides)
    job = load(db, "assets", [values])
    assert job.rejected == 0
    return db.scalar(select(m.Asset).where(m.Asset.hostname == values["hostname"]))


def setup_vulnerability(db, **overrides):
    values = {
        "identifier": "SYNTH-TEST-001", "title": "Synthetic test vulnerability", "synthetic": True,
        "cvss_score": 9.8, "known_exploited": True, "exploit_available": None,
        "affected_ranges": [{
            "product": "nginx", "vendor": "nginx", "ecosystem": "generic", "version_scheme": "generic",
            "affected": ">=1.20,<1.26.2", "fixed_versions": ["1.26.2"],
        }],
    }
    values.update(overrides)
    job = load(db, "vulnerabilities", [values])
    assert job.rejected == 0
    return db.scalar(select(m.Vulnerability).where(m.Vulnerability.identifier == values["identifier"]))


def setup_installation(db, **overrides):
    values = {"hostname": "host", "product": "nginx", "vendor": "nginx", "version": "1.24.0"}
    values.update(overrides)
    job = load(db, "software", [values])
    assert job.rejected == 0
    return db.scalar(select(m.SoftwareInstallation).order_by(m.SoftwareInstallation.id.desc()))


def basic_risk(db, **asset_overrides):
    setup_asset(db, **asset_overrides)
    installation = setup_installation(db)
    setup_vulnerability(db)
    engine.correlate(db)
    return rows(db, m.RiskAssessment)[0], installation


def fixture_data(name):
    return (FIXTURES / name).read_bytes()


def test_asset_csv_json_validation_provenance_and_path_safety(domain_db):
    db = domain_db
    job = imports.import_data(
        db, "assets",
        b"hostname,environment,criticality,owner\nWEB01,production,critical,Team\nbad,not-real,low,Team\n",
        "../../outside\\inventory.csv",
    )
    assert (job.processed, job.imported, job.skipped, job.rejected) == (2, 1, 0, 1)
    assert job.filename == "inventory.csv"
    asset = rows(db, m.Asset)[0]
    assert (asset.environment, asset.criticality) == ("PRODUCTION", "CRITICAL")
    assert asset.import_job_id == job.id
    observed = db.get(m.Evidence, asset.evidence_id)
    assert observed.import_job_id == job.id and observed.content["digest"] == job.digest
    assert rows(db, m.ImportRecord)[1].error
    assert rows(db, m.AuditEvent) and rows(db, m.TimelineEvent)
    duplicate = load(db, "assets", [{"hostname": "WEB01", "environment": "production"}])
    assert duplicate.skipped == 1 and count(db, m.Asset) == 1
    assert asset.criticality == "CRITICAL" and asset.owner == "Team"
    assert asset.import_job_id == duplicate.id
    assert db.in_transaction()


@pytest.mark.parametrize("data", [
    b"", b"{", b'{"assets":[]}', b'{"hostname":"x"}', b'["' + b"a" * 20001 + b'"]',
    b'[{"hostname":"x","hostname":"y"}]', b'[{"hostname":"x","number":NaN}]',
    b"hostname,hostname\nx,y\n", b"wrong\nx\n", b'hostname,owner\nx,"unterminated\n',
    b"hostname,owner\nx,y,z\n", b"\xff",
])
def test_invalid_whole_inventory_rejected_without_job(domain_db, data):
    with pytest.raises(ValueError):
        imports.import_data(domain_db, "assets", data, "upload.csv")
    assert count(domain_db, m.ImportJob) == 0


def test_upload_limits_and_json_depth(domain_db):
    with pytest.raises(ValueError, match="10 MiB"):
        imports.import_data(domain_db, "assets", b"x" * (imports.MAX_UPLOAD_BYTES + 1), "x.csv")
    with pytest.raises(ValueError, match="complexity"):
        imports.parse_json(("[" * 40 + "0" + "]" * 40).encode())
    with pytest.raises(ValueError, match="Unsupported"):
        imports.import_data(domain_db, "not-a-kind", b"[]", "x.json")


@pytest.mark.parametrize("name", ["nginx", "Nginx", "nginx web server", "nginx/1.24"])
def test_conservative_aliases_and_idempotent_version_updates(domain_db, name):
    db = domain_db
    setup_asset(db)
    installation = setup_installation(db, product=name)
    original_evidence, first_seen = installation.evidence_id, installation.first_seen
    assert rows(db, m.Software)[0].canonical_name == "nginx"
    assert installation.original_name == name and installation.normalization_confidence == "HIGH"
    duplicate = load(db, "software", [{"hostname": "host", "product": name, "vendor": "nginx", "version": "1.24.0"}])
    assert duplicate.skipped == 1 and count(db, m.SoftwareInstallation) == 1
    assert installation.evidence_id != original_evidence
    updated = load(db, "software", [{"hostname": "host", "product": name, "vendor": "nginx", "version": "1.26.2"}])
    assert updated.imported == 1
    assert installation.version == "1.26.2"
    assert installation.first_seen == first_seen and installation.last_seen >= first_seen
    assert installation.evidence_id != original_evidence and count(db, m.SoftwareInstallation) == 1


def test_no_version_inference_unknown_asset_and_row_types(domain_db):
    setup_asset(domain_db)
    job = load(domain_db, "software", [
        {"hostname": "host", "product": "nginx/1.24", "vendor": "nginx"},
        {"hostname": "missing", "product": "nginx"},
        {"hostname": "host", "product": "nginx", "unexpected": True}, 7,
    ])
    assert job.imported == 1 and job.rejected == 3
    assert rows(domain_db, m.SoftwareInstallation)[0].version == ""
    assert imports.normalize_product("nginx-plus")[0] == "nginx-plus"


def test_vulnerability_nested_records_cache_and_reference_validation(domain_db):
    db = domain_db
    vulnerability = setup_vulnerability(db, references=[{"label": "User-supplied reference", "url": "https://example.invalid/advisory"}])
    assert count(db, m.AffectedRange) == count(db, m.VulnerabilityReference) == 1
    assert db.get(m.Evidence, vulnerability.evidence_id).type == "VULNERABILITY_RECORD"
    cache = rows(db, m.ProviderCache)[0]
    assert cache.enabled and len(cache.digest) == 64 and cache.downloaded_at
    setup_vulnerability(db, references=[{"label": "User-supplied reference", "url": "https://example.invalid/advisory"}])
    assert count(db, m.Vulnerability) == count(db, m.AffectedRange) == count(db, m.VulnerabilityReference) == 1
    assert rows(db, m.ImportJob)[-1].skipped == 1
    invalid = load(db, "vulnerabilities", [
        {"identifier": "SYNTH-BAD", "title": "Invalid reference", "references": [{"url": "javascript:alert(1)"}]},
        {"identifier": "SYNTH-BAD2", "title": "Invalid reference", "references": [{"url": "https://"}]},
        {"identifier": "SYNTH-BAD3", "title": "Invalid range", "affected_ranges": [{"product": "", "affected": "<2"}]},
    ])
    assert invalid.rejected == 3 and count(db, m.Vulnerability) == 1


def test_vulnerability_reimport_replaces_ranges_without_losing_matches(domain_db):
    db = domain_db
    risk, _ = basic_risk(db)
    match_id = risk.match_id
    setup_vulnerability(db, affected_ranges=[{
        "product": "nginx", "vendor": "nginx", "ecosystem": "generic", "version_scheme": "generic",
        "affected": "<1.27", "fixed_versions": ["1.27"],
    }])
    engine.correlate(db)
    assert count(db, m.VulnerabilityMatch) == 1 and risk.match_id == match_id
    assert db.get(m.VulnerabilityMatch, match_id).rule == "<1.27"


@pytest.mark.parametrize("name,expected_format,components,deps", [
    ("examplecorp-cyclonedx.json", "CycloneDX JSON", 3, 2),
    ("examplecorp-spdx.json", "SPDX JSON", 3, 2),
    ("examplecorp-cyclonedx.xml", "CycloneDX XML", 2, 1),
])
def test_sbom_formats_dependency_metadata_and_digest_dedup(domain_db, name, expected_format, components, deps):
    db = domain_db
    asset = setup_asset(db)
    data = fixture_data(name)
    job = imports.import_data(db, "sbom", data, name, asset.id)
    assert job.imported == components and job.processed == components
    sbom = rows(db, m.SBOM)[0]
    assert sbom.format == expected_format and sbom.asset_id == asset.id
    assert count(db, m.SBOMComponent) == count(db, m.SoftwareInstallation) == components
    assert count(db, m.Dependency) == deps
    parser = db.scalar(select(m.SBOMComponent).where(m.SBOMComponent.name == "demo-parser"))
    assert parser.purl == "pkg:npm/demo-parser@1.0.0" and parser.licenses
    assert parser.direct is (True if name.endswith(".xml") else False)
    assert parser.evidence_id and parser.import_job_id == job.id and parser.installation_id
    duplicate = imports.import_data(db, "sbom", data, name, asset.id)
    assert duplicate.skipped == components and duplicate.imported == 0 and count(db, m.SBOM) == 1
    other = setup_asset(db, hostname="other")
    imports.import_data(db, "sbom", data, name, other.id)
    assert count(db, m.SBOM) == 2


@pytest.mark.parametrize("mutator", [
    lambda doc: doc.update(components=[]),
    lambda doc: doc.update(components={}),
    lambda doc: doc["components"].append(copy.deepcopy(doc["components"][0])),
    lambda doc: doc["dependencies"].append({"ref": "missing", "dependsOn": []}),
    lambda doc: doc["dependencies"].append({"ref": "demo-http", "dependsOn": ["missing"]}),
    lambda doc: doc["dependencies"].append({"ref": "demo-http", "dependsOn": ["demo-parser"]}),
    lambda doc: doc["components"][0].update(name=""),
    lambda doc: doc["components"][0].update(hashes="invalid"),
])
def test_malformed_sbom_rejected_before_records(domain_db, mutator):
    db = domain_db
    asset = setup_asset(db)
    doc = json.loads(fixture_data("examplecorp-cyclonedx.json"))
    mutator(doc)
    before = count(db, m.ImportJob)
    with pytest.raises(ValueError):
        load(db, "sbom", doc, asset.id)
    assert count(db, m.ImportJob) == before
    assert count(db, m.SBOM) == count(db, m.SBOMComponent) == 0


def test_sbom_requires_asset_and_rejects_unsafe_xml(domain_db):
    db = domain_db
    with pytest.raises(ValueError, match="asset_id"):
        imports.import_data(db, "sbom", fixture_data("examplecorp-cyclonedx.json"), "bom.json")
    asset = setup_asset(db)
    for data in (b'<!DOCTYPE bom [<!ENTITY x SYSTEM "file:///etc/passwd">]><bom>&x;</bom>', b"<root/>", b"{}"):
        with pytest.raises(ValueError):
            imports.import_data(db, "sbom", data, "bom.xml", asset.id)
    assert count(db, m.SBOM) == 0


def test_sbom_cycles_are_recorded_without_infinite_traversal(domain_db):
    asset = setup_asset(domain_db)
    doc = json.loads(fixture_data("examplecorp-cyclonedx.json"))
    doc["dependencies"][-1]["dependsOn"] = ["demo-http"]
    job = load(domain_db, "sbom", doc, asset.id)
    assert job.imported == 3 and any("cycle" in warning for warning in job.warnings)
    assert count(domain_db, m.Dependency) == 3


@pytest.mark.parametrize("reverse", [False, True])
def test_sbom_graph_depth_is_bounded_independent_of_reference_order(domain_db, reverse):
    asset = setup_asset(domain_db)
    names = [f"component-{index:02}" for index in range(35)]
    if reverse:
        names.reverse()
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [{"bom-ref": name, "name": name} for name in names],
        "dependencies": [{"ref": source, "dependsOn": [target]} for source, target in zip(names, names[1:])],
    }
    with pytest.raises(ValueError, match="dependency depth"):
        load(domain_db, "sbom", doc, asset.id)


def test_sbom_stable_identity_retains_qualifiers():
    assert imports._package_identity("pkg:deb/nginx@1.24?arch=amd64#bin", "ref") == "pkg:deb/nginx?arch=amd64#bin"
    assert imports._package_identity("pkg:npm/@scope/name@1.0", "ref") == "pkg:npm/@scope/name"


@pytest.mark.parametrize("version,rule,scheme,expected", [
    ("1.24.0", ">=1.20,<1.26.2", "generic", True),
    ("1.26.2", ">=1.20,<1.26.2", "generic", False),
    ("1.9", ">=1.10", "generic", False),
    ("1.10", ">1.9", "generic", True),
    ("1.0.0", "==1", "generic", True),
    ("1.0", "!=1.0.0", "generic", False),
    ("1.0.0", ">=1.0.0,<2.0.0", "semver", True),
    ("1.0.0-rc.1", ">=1.0.0", "semver", None),
    ("01.0.0", ">=1.0.0", "semver", None),
    ("1.0", ">=1.0", "semver", None),
    ("1.24.0-vendor1", "<1.26", "generic", None),
    ("1.24", ">=1.20 || <2.0", "generic", None),
    ("1.24", "1.20 - 1.25", "generic", None),
    ("1.24", "^1.20", "generic", None),
    ("1.24", "<1.26.x", "generic", None),
    ("", "<1.26", "generic", None),
    ("1.24", "<1.26", "unknown", None),
    ("1.24", "<1.26", "rpm", None),
    ("1.2.post1", ">=1.2,<2", "pep440", True),
    ("1.2rc1", ">=1.2rc1,<2", "python", True),
    ("1.24", "^1.26", "pep440", None),
])
def test_version_comparison_is_strict_and_never_lexical(version, rule, scheme, expected):
    affected, method, confidence = engine.evaluate_version(version, rule, scheme)
    assert affected is expected and method
    assert confidence == ("UNKNOWN" if expected is None else "HIGH")


def test_mixed_ranges_unknown_never_becomes_unaffected(domain_db):
    db = domain_db
    setup_asset(db)
    setup_installation(db, version="1.26.2")
    setup_vulnerability(db, affected_ranges=[
        {"product": "nginx", "vendor": "nginx", "version_scheme": "generic", "affected": "<1.26.2"},
        {"product": "nginx", "vendor": "nginx", "version_scheme": "rpm", "affected": "<2"},
    ])
    engine.correlate(db)
    match = rows(db, m.VulnerabilityMatch)[0]
    assert match.affected is None and match.state == "NEEDS_REVIEW"
    assert rows(db, m.RiskAssessment)[0].status == "OPEN"


@pytest.mark.parametrize("vendor,ecosystem,scheme,expected", [
    ("different-vendor", "generic", "generic", None),
    ("nginx", "npm", "generic", None),
    ("", "generic", "generic", "POTENTIAL"),
    ("nginx", "generic", "pep440", "NEEDS_REVIEW"),
    ("nginx", "python", "pep440", "CONFIRMED"),
])
def test_product_vendor_ecosystem_guardrails(domain_db, vendor, ecosystem, scheme, expected):
    db = domain_db
    setup_asset(db)
    setup_installation(db, vendor=vendor, ecosystem=ecosystem)
    rule_ecosystem = "python" if ecosystem == "python" else "generic"
    setup_vulnerability(db, affected_ranges=[{
        "product": "nginx", "vendor": "nginx", "ecosystem": rule_ecosystem,
        "version_scheme": scheme, "affected": "<1.26.2",
    }])
    engine.correlate(db)
    matches = rows(db, m.VulnerabilityMatch)
    assert (matches[0].state if matches else None) == expected


def test_demo_exact_factors_global_flags_ranking_and_idempotence(domain_db):
    db = domain_db
    result = imports.demo(db)
    assert result["seeded"] and result["synthetic"] and result["assets"] == 9
    assert count(db, m.Asset) == 9
    asset_map = {asset.id: asset.hostname for asset in rows(db, m.Asset)}
    vulnerability_map = {v.id: v.identifier for v in rows(db, m.Vulnerability)}
    risks = {
        (asset_map[risk.asset_id], vulnerability_map.get(risk.vulnerability_id)): risk
        for risk in rows(db, m.RiskAssessment) if risk.vulnerability_id
    }
    web1 = risks[("WEB-01", "SYNTH-EXAMPLE-001")]
    web2 = risks[("WEB-02", "SYNTH-EXAMPLE-001")]
    low_cvss = risks[("WEB-01", "SYNTH-EXPOSED-075")]
    lab = risks[("LAPTOP-01", "SYNTH-LAB-098")]
    assert web1.score == 100 and web1.priority == "CRITICAL"
    assert web2.score == 63.2 and web2.priority == "HIGH"
    assert low_cvss.score == 88.5 and low_cvss.priority == "CRITICAL"
    assert lab.score == 36.8 and lab.priority == "MEDIUM"
    assert low_cvss.score > lab.score and web1.score > web2.score
    first, second = ({factor["name"]: factor for factor in risk.factors} for risk in (web1, web2))
    assert first["known_exploitation"]["value"] == second["known_exploitation"]["value"] == "YES"
    assert first["known_exploitation"]["contribution"] == second["known_exploitation"]["contribution"] == 18
    assert first["exposure"]["contribution"] == 16 and second["exposure"]["contribution"] == 2.4
    assert first["service"]["contribution"] == 4 and first["path"]["contribution"] == 6
    assert all("evidence_ids" in factor and factor["reasoning"] for factor in web1.factors)
    assert "SYNTHETIC" in " ".join(web1.uncertainties)
    assert count(db, m.RiskFactor) == sum(len(risk.factors) for risk in rows(db, m.RiskAssessment))
    assert count(db, m.AssessmentHistory) == count(db, m.RiskAssessment)
    before = {model: count(db, model) for model in (m.Asset, m.SoftwareInstallation, m.RiskAssessment, m.SBOM)}
    assert imports.demo(db)["seeded"] is False
    assert all(count(db, model) == total for model, total in before.items())
    assert ("APP-01", "SYNTH-TRANSITIVE-001") in risks


def test_demo_api_exposes_canonical_hostname_search_and_remains_idempotent(client):
    response = client.post("/api/demo")
    assert response.status_code == 200 and response.json()["seeded"] is True
    for hostname in ("WEB-01", "WEB-02", "APP-01", "APP-02", "DB-01", "DB-02", "DC-01", "FILE-01", "LAPTOP-01"):
        result = client.get("/api/assets", params={"search": hostname})
        assert result.status_code == 200
        assert hostname in {asset["hostname"] for asset in result.json()["items"]}
    web = next(
        asset for asset in client.get("/api/assets", params={"search": "WEB-01"}).json()["items"]
        if asset["hostname"] == "WEB-01"
    )
    risks = client.get("/api/risk", params={"asset_id": web["id"], "page_size": 100}).json()["items"]
    assert any(risk["match_id"] and risk["priority"] == "CRITICAL" for risk in risks)
    repeated = client.post("/api/demo")
    assert repeated.status_code == 200 and repeated.json()["seeded"] is False
    assert client.get("/api/assets").json()["total"] == 9


def test_settings_change_scores_version_and_preserve_analyst_overrides(domain_db):
    db = domain_db
    risk, _ = basic_risk(db)
    prior_score, version = risk.score, risk.rules_version
    risk.analyst_override = {"priority": "CRITICAL", "confidence": "HIGH", "exposure": "RESTRICTED"}
    risk.analyst_reason = "Synthetic analyst decision"
    settings = SettingsInput().model_dump()
    settings["weights"]["cvss"] = 0
    db.add(m.Setting(key="risk_engine", value=settings))
    engine.correlate(db)
    assert risk.score < prior_score and risk.rules_version != version
    assert risk.analyst_override == {"priority": "CRITICAL", "confidence": "HIGH", "exposure": "RESTRICTED"}
    assert risk.priority != "CRITICAL" and risk.exposure == "INTERNAL_ONLY"
    assert risk.analyst_reason == "Synthetic analyst decision"
    history = rows(db, m.AssessmentHistory)[-1].snapshot
    assert history["automated"]["priority"] != "CRITICAL" and history["effective"]["priority"] == "CRITICAL"
    assert engine.snapshot(db).counts["CRITICAL"] == 1
    assert engine.DEFAULT_SETTINGS == SettingsInput().model_dump()


def test_latest_exposure_and_service_fk_are_not_asset_wide(domain_db):
    db = domain_db
    risk, installation = basic_risk(db, exposure="INTERNET_FACING", criticality="CRITICAL")
    obs = evidence(db, "NETWORK_OBSERVATION", "test", "New asset is isolated")
    db.add(m.ExposureObservation(asset_id=risk.asset_id, exposure="ISOLATED", evidence_id=obs.id))
    db.add(m.Service(
        asset_id=risk.asset_id, installation_id=None, name="unrelated HTTPS", port=443,
        exposure="INTERNET_FACING", status="RUNNING", evidence_id=obs.id,
    ))
    engine.correlate(db)
    factors = {factor["name"]: factor for factor in risk.factors}
    assert risk.exposure == "ISOLATED" and factors["exposure"]["contribution"] == 0
    assert factors["service"]["contribution"] == 0 and installation.id is not None


@pytest.mark.parametrize("status", ["STOPPED", "REMOVED"])
def test_inactive_services_keep_history_without_risk_or_asset_exposure_contributions(domain_db, status):
    db = domain_db
    risk, installation = basic_risk(db)
    proof = evidence(db, "SERVICE_OBSERVATION", "Synthetic service fixture", "Explicit synthetic service exposure")
    service = m.Service(
        asset_id=risk.asset_id, installation_id=installation.id, name="telnet", port=23,
        exposure="INTERNET_FACING", status="RUNNING", evidence_id=proof.id,
    )
    db.add(service)
    db.flush()
    observation = m.ExposureObservation(
        asset_id=risk.asset_id, service_id=service.id, exposure="INTERNET_FACING", evidence_id=proof.id,
    )
    db.add(observation)
    engine.correlate(db)
    assert next(f for f in risk.factors if f["name"] == "service")["contribution"] == 4
    assert risk.exposure == "INTERNAL_ONLY"
    service_findings = [
        finding for finding in rows(db, m.RiskAssessment)
        if finding.rule_key in (f"auto:internet-admin:{service.id}", f"auto:unencrypted-service:{service.id}")
    ]
    assert len(service_findings) == 2 and all(finding.status == "OPEN" for finding in service_findings)
    service.status, service.exposure = status, "UNKNOWN"
    engine.correlate(db)
    assert next(f for f in risk.factors if f["name"] == "service")["contribution"] == 0
    assert risk.exposure == "INTERNAL_ONLY"
    assert db.get(m.Asset, risk.asset_id).exposure == "INTERNAL_ONLY"
    assert all(finding.status == "DEFERRED" for finding in service_findings)
    assert db.get(m.Service, service.id).status == status
    assert rows(db, m.ExposureObservation) == [observation]
    assert observation.exposure == "INTERNET_FACING" and observation.service_id == service.id
    assert count(db, m.RemediationVerification) == 0


def test_unknown_intelligence_is_not_no_exploit(domain_db):
    db = domain_db
    risk, _ = basic_risk(db)
    vulnerability = rows(db, m.Vulnerability)[0]
    vulnerability.known_exploited = None
    vulnerability.exploit_available = None
    engine.correlate(db)
    assert risk.exploitability == "UNKNOWN"
    factors = {factor["name"]: factor for factor in risk.factors}
    assert factors["known_exploitation"]["value"] == "UNKNOWN"
    assert "known_exploitation" in " ".join(risk.uncertainties)


def test_potential_paths_deleted_edges_cycles_limits_and_status_filters(domain_db):
    db = domain_db
    imports.demo(db)
    assets = {asset.hostname: asset for asset in rows(db, m.Asset)}
    assert engine.discover_paths(db)["paths"] == 2
    paths = rows(db, m.AttackPath)
    assert paths[0].asset_ids == [assets[name].id for name in ("WEB-01", "APP-01", "DB-01")]
    assert all(path.confidence == "POTENTIAL" and "not confirmed" in path.reasoning for path in paths)
    load(db, "relationships", [{
        "source_asset_id": assets["DB-01"].id, "target_asset_id": assets["WEB-01"].id, "type": "CONNECTS_TO",
    }])
    result = engine.discover_paths(db)
    assert result["paths"] == 2 and result["expansions"] <= result["expansion_limit"]
    settings = SettingsInput(max_paths=1).model_dump()
    db.add(m.Setting(key="risk_engine", value=settings))
    result = engine.discover_paths(db)
    assert result["paths"] == 1 and result["truncated"]
    connection = db.scalar(select(m.AssetRelationship).where(
        m.AssetRelationship.source_asset_id == assets["APP-01"].id,
        m.AssetRelationship.target_asset_id == assets["DB-01"].id,
    ))
    db.delete(connection)
    assert engine.discover_paths(db)["paths"] == 0
    assert count(db, m.AttackPath) == 0
    engine.correlate(db)
    assert all(factor["contribution"] == 0 for risk in rows(db, m.RiskAssessment)
               for factor in risk.factors if factor["name"] == "path")


def test_paths_need_evidence_and_do_not_traverse_structural_relationships(domain_db):
    db = domain_db
    risk, _ = basic_risk(db, exposure="INTERNET_FACING")
    target = setup_asset(db, hostname="critical", criticality="CRITICAL")
    db.add(m.AssetRelationship(source_asset_id=risk.asset_id, target_asset_id=target.id, type="CONNECTS_TO"))
    assert engine.discover_paths(db)["paths"] == 0
    edge = rows(db, m.AssetRelationship)[0]
    edge.evidence_id = target.evidence_id
    edge.type = "MEMBER_OF"
    assert engine.discover_paths(db)["paths"] == 0
    edge.type = "CONNECTS_TO"
    assert engine.discover_paths(db)["paths"] == 1
    risk.status = "DEFERRED"
    assert engine.discover_paths(db)["paths"] == 0


def test_dense_graph_has_global_expansion_bound(domain_db):
    db = domain_db
    risk, _ = basic_risk(db, exposure="INTERNET_FACING")
    assets = [db.get(m.Asset, risk.asset_id)] + [setup_asset(db, hostname=f"node-{index}") for index in range(12)]
    obs = assets[0].evidence_id
    for source in assets:
        for target in assets:
            if source.id != target.id:
                db.add(m.AssetRelationship(
                    source_asset_id=source.id, target_asset_id=target.id, type="CONNECTS_TO", evidence_id=obs,
                ))
    db.add(m.Setting(key="risk_engine", value=SettingsInput(max_graph_edges=100, max_path_depth=6).model_dump()))
    result = engine.discover_paths(db)
    assert result["truncated"] and result["expansions"] <= 1200
    assert result["edges_considered"] == 100


@pytest.mark.parametrize("status", ["RISK_ACCEPTED", "DEFERRED", "FALSE_POSITIVE"])
def test_recorrelation_preserves_analyst_lifecycle_choices(domain_db, status):
    db = domain_db
    risk, _ = basic_risk(db)
    risk.status, risk.analyst_reason = status, "Analyst disposition"
    match = db.get(m.VulnerabilityMatch, risk.match_id)
    match.analyst_state, match.analyst_reason = "REJECTED", "Backported vendor fix"
    engine.correlate(db)
    assert risk.status == status and risk.analyst_reason == "Analyst disposition"
    assert match.analyst_state == "REJECTED" and match.analyst_reason == "Backported vendor fix"
    assert engine.discover_paths(db)["paths"] == 0


def test_fresh_fixed_version_verification_and_reintroduction(domain_db):
    db = domain_db
    risk, installation = basic_risk(db)
    db.add(m.Remediation(risk_id=risk.id, action="Synthetic upgrade", status="REMEDIATED"))
    risk.status = "REMEDIATED"
    assert engine.correlate(db)["verified"] == 0
    assert risk.status == "REMEDIATED" and count(db, m.RemediationVerification) == 0
    setup_installation(db, version="1.26.2")
    result = engine.correlate(db)
    assert result["verified"] == 1 and risk.status == "VERIFIED" and risk.verified_version == "1.26.2"
    verification = rows(db, m.RemediationVerification)[0]
    assert verification.before["version"] == "1.24.0" and verification.after["version"] == "1.26.2"
    assert verification.evidence_id == installation.evidence_id and verification.method == "VERSION_EVIDENCE"
    assert rows(db, m.Remediation)[0].status == "VERIFIED"
    engine.correlate(db)
    assert count(db, m.RemediationVerification) == 1
    setup_installation(db, version="1.24.0")
    engine.correlate(db)
    assert risk.status == "OPEN" and rows(db, m.Remediation)[0].status == "OPEN"
    assert any(event.action == "RISK_REINTRODUCED" for event in rows(db, m.AuditEvent))


def test_analyst_verified_same_version_is_not_reopened_on_unchanged_inventory(domain_db):
    db = domain_db
    risk, installation = basic_risk(db)
    risk.status, risk.verified_version = "VERIFIED", installation.version
    engine.correlate(db)
    assert risk.status == "VERIFIED"
    setup_installation(db, version="1.24.0")
    engine.correlate(db)
    assert risk.status == "VERIFIED"
    setup_installation(db, version="1.25.0")
    engine.correlate(db)
    assert risk.status == "OPEN"


def test_verified_version_can_be_genuinely_reintroduced_after_unaffected_observation(domain_db):
    db = domain_db
    risk, installation = basic_risk(db)
    risk.status, risk.verified_version = "VERIFIED", installation.version
    setup_installation(db, version="1.26.2")
    engine.correlate(db)
    assert risk.status == "VERIFIED"
    setup_installation(db, version="1.24.0")
    engine.correlate(db)
    assert risk.status == "OPEN"


def test_removed_applicability_metadata_removes_stale_path_factors(domain_db):
    db = domain_db
    risk, _ = basic_risk(db, exposure="INTERNET_FACING")
    critical = setup_asset(db, hostname="critical", criticality="CRITICAL")
    load(db, "relationships", [{"source_asset_id": risk.asset_id, "target_asset_id": critical.id}])
    engine.correlate(db)
    assert next(f for f in risk.factors if f["name"] == "path")["contribution"] == 6
    match = db.get(m.VulnerabilityMatch, risk.match_id)
    rule = db.get(m.AffectedRange, match.range_id)
    match.range_id = None
    db.flush()
    db.delete(rule)
    engine.correlate(db)
    assert next(f for f in risk.factors if f["name"] == "path")["contribution"] == 0
    assert match.state == "NEEDS_REVIEW" and count(db, m.AttackPath) == 0


@pytest.mark.parametrize("fixed_versions,new_version", [
    ([], "1.26.2"), (["1.26.x"], "1.26.2"), (["1.26.2"], "1.26.2-vendor1"),
])
def test_no_verification_without_supported_fixed_version_and_comparison(domain_db, fixed_versions, new_version):
    db = domain_db
    risk, _ = basic_risk(db)
    rule = rows(db, m.AffectedRange)[0]
    rule.fixed_versions = fixed_versions
    setup_installation(db, version=new_version)
    engine.correlate(db)
    assert risk.status == "OPEN" and count(db, m.RemediationVerification) == 0


def test_metadata_or_status_change_alone_never_verifies(domain_db):
    db = domain_db
    risk, installation = basic_risk(db)
    risk.status = "REMEDIATED"
    rows(db, m.AffectedRange)[0].affected = "<1.24"
    rows(db, m.AffectedRange)[0].fixed_versions = ["1.24"]
    engine.correlate(db)
    assert risk.status == "REMEDIATED" and count(db, m.RemediationVerification) == 0
    installation.version = "1.26.2"
    engine.correlate(db)
    assert count(db, m.RemediationVerification) == 0


@pytest.mark.parametrize("kind,content", [
    ("ASSET_INVENTORY", {"asset_id": 1, "version": "1.26.2"}),
    ("SOFTWARE_INVENTORY", {"asset_id": 1, "version": "1.24.0"}),
    ("SOFTWARE_INVENTORY", {"asset_id": 999, "version": "1.26.2"}),
    ("SOFTWARE_INVENTORY", {"note": "No version observation"}),
    ("SOFTWARE_INVENTORY", {"asset_id": 1, "product": "another-package", "version": "1.26.2"}),
])
def test_unrelated_or_inconsistent_evidence_cannot_automatically_verify(domain_db, kind, content):
    db = domain_db
    risk, installation = basic_risk(db)
    proof = evidence(db, kind, "Synthetic", "Unrelated observation", content)
    installation.version, installation.evidence_id = "1.26.2", proof.id
    engine.correlate(db)
    assert risk.status == "OPEN" and count(db, m.RemediationVerification) == 0


def test_changed_sbom_version_updates_installation_and_can_verify(domain_db):
    db = domain_db
    asset = setup_asset(db)
    doc = json.loads(fixture_data("examplecorp-cyclonedx.json"))
    load(db, "sbom", doc, asset.id)
    setup_vulnerability(db, affected_ranges=[{
        "product": "demo-parser", "vendor": "ExampleCorp synthetic", "ecosystem": "npm",
        "version_scheme": "semver", "affected": ">=1.0.0,<2.0.0", "fixed_versions": ["2.0.0"],
    }])
    engine.correlate(db)
    risk = rows(db, m.RiskAssessment)[0]
    doc["components"][1].update(version="2.0.0", purl="pkg:npm/demo-parser@2.0.0")
    load(db, "sbom", doc, asset.id)
    engine.correlate(db)
    assert count(db, m.SoftwareInstallation) == 3 and count(db, m.SBOM) == 2
    assert risk.status == "VERIFIED" and risk.verified_version == "2.0.0"


def test_acceptance_expiration_and_real_snapshots(domain_db):
    db = domain_db
    risk, _ = basic_risk(db)
    first = rows(db, m.RiskSnapshot)[0]
    assert first.open_risk == first.new_risks == 1
    risk.status = "RISK_ACCEPTED"
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    db.add(m.RiskAcceptance(
        risk_id=risk.id, reason="Synthetic acceptance", approver="Analyst", expires_at=past,
        compensating_controls="Synthetic restricted access",
    ))
    db.add(m.Remediation(risk_id=risk.id, action="Upgrade", status="RISK_ACCEPTED", due_date=past))
    db.flush()
    assert engine.expire_acceptances(db) == 1
    assert risk.status == "OPEN" and rows(db, m.Remediation)[0].status == "OPEN"
    later = engine.snapshot(db)
    assert later.open_risk == 1 and later.overdue == 1 and later.new_risks == 0
    assert first.overdue == 0
    risk.status = "DEFERRED"
    final = engine.snapshot(db)
    assert final.open_risk == final.overdue == 0


@pytest.mark.parametrize("status", [
    "OPEN", "ASSIGNED", "IN_PROGRESS", "REMEDIATED", "VERIFIED", "RISK_ACCEPTED", "FALSE_POSITIVE", "DEFERRED",
])
def test_snapshot_effective_priorities_match_reporting_without_recorrelation(domain_db, status):
    from app.services import reporting

    db = domain_db
    risk, _ = basic_risk(db)
    original = rows(db, m.RiskSnapshot)[0]
    original_counts = dict(original.counts)
    risk.analyst_override = {"priority": "CRITICAL"}
    risk.status = status
    current = engine.snapshot(db)
    dashboard = reporting.dashboard(db)
    assert engine.ACTIVE_STATUSES == reporting.ACTIVE
    assert current.counts == dashboard["priorities"]
    assert current.open_risk == dashboard["totals"]["active_risks"]
    assert current.counts["CRITICAL"] == (1 if status in reporting.ACTIVE else 0)
    assert original.counts == original_counts and original.counts["CRITICAL"] == 0


@pytest.mark.parametrize("older_days,latest_days,expected_status", [
    (-2, 2, "RISK_ACCEPTED"),
    (2, -1, "OPEN"),
    (-2, -1, "OPEN"),
])
def test_only_latest_acceptance_controls_reopening(domain_db, older_days, latest_days, expected_status):
    db = domain_db
    risk, _ = basic_risk(db)
    risk.status = "RISK_ACCEPTED"
    now = datetime.now(timezone.utc)
    for index, days in enumerate((older_days, latest_days)):
        db.add(m.RiskAcceptance(
            risk_id=risk.id, reason=f"Synthetic acceptance {index}", approver="Analyst",
            expires_at=(now + timedelta(days=days)).isoformat(), compensating_controls="Synthetic controls",
            created_at=(now + timedelta(seconds=index)).isoformat(),
        ))
    db.add(m.Remediation(risk_id=risk.id, action="Upgrade", status="RISK_ACCEPTED"))
    db.flush()
    assert engine.expire_acceptances(db) == sum(days < 0 for days in (older_days, latest_days))
    assert risk.status == expected_status and rows(db, m.Remediation)[0].status == expected_status
    assert engine.expire_acceptances(db) == 0


def test_batched_correlation_persists_factors_history_without_n_plus_one_reads(domain_db):
    db = domain_db
    asset = setup_asset(db)
    setup_installation(db)
    amount = engine.WRITE_BATCH_SIZE + 5
    db.add_all(m.Vulnerability(
        id=index + 1, identifier=f"SYNTH-BATCH-{index}", title="Synthetic batch record",
        cvss_score=5, synthetic=True, evidence_id=asset.evidence_id,
    ) for index in range(amount))
    db.flush()
    db.add_all(m.AffectedRange(
        vulnerability_id=index + 1, product="nginx", vendor="nginx", ecosystem="generic",
        version_scheme="numeric", affected=">=1.0,<2.0", evidence_id=asset.evidence_id,
    ) for index in range(amount))
    db.flush()
    queries = []

    def record_query(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            queries.append(statement)

    event.listen(db.bind, "before_cursor_execute", record_query)
    try:
        first = engine.correlate(db)
        assert first["matched"] == first["risks"] == amount
        assert len(queries) < 45
        queries.clear()
        second = engine.correlate(db)
        assert second["matched"] == second["risks"] == amount and second["new_risks"] == 0
        assert len(queries) < 45
    finally:
        event.remove(db.bind, "before_cursor_execute", record_query)
    assert count(db, m.VulnerabilityMatch) == count(db, m.RiskAssessment) == amount
    assert count(db, m.RiskFactor) == amount * 14
    assert count(db, m.AssessmentHistory) == amount * 2


def test_non_cve_rules_evidence_lifecycle_and_manual_risks_preserved(domain_db):
    db = domain_db
    asset = setup_asset(db, owner="", criticality="UNKNOWN", exposure="INTERNET_FACING")
    installation = setup_installation(db, lifecycle="END_OF_LIFE")
    db.add(m.Service(
        asset_id=asset.id, installation_id=installation.id, name="telnet", port=23, status="RUNNING",
        exposure="INTERNET_FACING", evidence_id=installation.evidence_id,
    ))
    manual = m.RiskAssessment(
        asset_id=asset.id, title="Analyst-created non-CVE finding", category="IDENTITY_RISK",
        rule_key="manual", severity="HIGH", confidence="MEDIUM", evidence_ids=[asset.evidence_id],
        recommendation="Keep the analyst recommendation.", analyst_reason="Evidence-backed manual concern.",
    )
    db.add(manual)
    engine.correlate(db)
    risks = rows(db, m.RiskAssessment)
    keys = {risk.rule_key for risk in risks}
    assert {"auto:missing-owner", "auto:unknown-criticality"} <= keys
    assert any(key.startswith("auto:internet-admin") for key in keys)
    assert any(key.startswith("auto:unencrypted-service") for key in keys)
    lifecycle = next(risk for risk in risks if risk.category == "SOFTWARE_LIFECYCLE")
    assert lifecycle.priority != "CRITICAL" and lifecycle.evidence_ids
    assert manual.score == 76 and manual.priority == "HIGH"
    assert manual.title == "Analyst-created non-CVE finding" and manual.severity == "HIGH"
    assert manual.confidence == "MEDIUM" and manual.recommendation == "Keep the analyst recommendation."
    factors = {factor["name"]: factor for factor in manual.factors}
    assert factors["analyst_severity"]["contribution"] == 60
    assert factors["analyst_severity"]["evidence_ids"] == [asset.evidence_id]
    assert factors["exposure"]["contribution"] == 16
    assert manual.reasoning[0] == "Evidence-backed manual concern."
    settings = SettingsInput(configuration_rules=False, lifecycle_rules=False).model_dump()
    settings["weights"]["exposure"] = 0
    db.add(m.Setting(key="risk", value=settings))
    manual.analyst_override = {"priority": "CRITICAL"}
    engine.correlate(db)
    assert lifecycle.status == "DEFERRED" and manual.status == "OPEN"
    assert manual.score == 60 and manual.analyst_override == {"priority": "CRITICAL"}
    assert engine.get_settings(db)["max_graph_edges"] == settings["max_graph_edges"]
    history = rows(db, m.AssessmentHistory)[-1].snapshot
    assert history["automated"]["priority"] == "HIGH"
    assert history["effective"]["priority"] == "CRITICAL"
    manual.status = "RISK_ACCEPTED"
    engine.correlate(db)
    assert manual.status == "RISK_ACCEPTED" and manual.score == 60


def test_local_provider_only_external_adapters_explicitly_disabled():
    snapshot = LocalJSONProvider("Synthetic local", "1").load(
        b'{"source":"Synthetic snapshot","version":"2","vulnerabilities":[{"identifier":"SYNTH-1"}]}'
    )
    assert snapshot.source == "Synthetic snapshot" and snapshot.version == "2" and len(snapshot.digest) == 64
    for provider in (NVDProvider(), OSVProvider(), CISAKEVProvider()):
        assert provider.enabled is False
        with pytest.raises(NotImplementedError, match="disabled"):
            provider.load()
