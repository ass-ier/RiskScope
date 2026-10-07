from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Record:
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[str] = mapped_column(String(40), default=now, index=True)
    updated_at: Mapped[str] = mapped_column(String(40), default=now, onupdate=now)


class Evidence(Record, Base):
    __tablename__ = "evidence"
    type: Mapped[str] = mapped_column(String(60), default="ANALYST_NOTE")
    source: Mapped[str] = mapped_column(String(500), default="Manual")
    summary: Mapped[str] = mapped_column(Text)
    content: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    confidence: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    actor: Mapped[str] = mapped_column(String(200), default="Local analyst")
    import_job_id: Mapped[int | None] = mapped_column(ForeignKey("import_job.id"), index=True)


class Provenance:
    source: Mapped[str] = mapped_column(String(500), default="Manual")
    confidence: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), index=True)
    import_job_id: Mapped[int | None] = mapped_column(ForeignKey("import_job.id"), index=True)


class NetworkZone(Record, Provenance, Base):
    __tablename__ = "network_zone"
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    subnet: Mapped[str] = mapped_column(String(80), default="")
    vlan: Mapped[str] = mapped_column(String(80), default="")
    gateway: Mapped[str] = mapped_column(String(80), default="")


class Asset(Record, Provenance, Base):
    __tablename__ = "asset"
    hostname: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    ip: Mapped[str] = mapped_column(String(80), default="")
    mac: Mapped[str] = mapped_column(String(80), default="")
    os: Mapped[str] = mapped_column(String(200), default="")
    os_version: Mapped[str] = mapped_column(String(100), default="")
    environment: Mapped[str] = mapped_column(String(30), default="UNKNOWN", index=True)
    owner: Mapped[str] = mapped_column(String(200), default="")
    business_unit: Mapped[str] = mapped_column(String(200), default="")
    location: Mapped[str] = mapped_column(String(200), default="")
    criticality: Mapped[str] = mapped_column(String(30), default="UNKNOWN", index=True)
    exposure: Mapped[str] = mapped_column(String(40), default="UNKNOWN", index=True)
    zone_id: Mapped[int | None] = mapped_column(ForeignKey("network_zone.id"), index=True)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE", index=True)


class BusinessContext(Record, Provenance, Base):
    __tablename__ = "business_context"
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), unique=True)
    business_owner: Mapped[str] = mapped_column(String(200), default="")
    application: Mapped[str] = mapped_column(String(200), default="")
    business_function: Mapped[str] = mapped_column(Text, default="")
    data_classification: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    regulatory_importance: Mapped[str] = mapped_column(Text, default="")


class AssetRelationship(Record, Provenance, Base):
    __tablename__ = "asset_relationship"
    source_asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    target_asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    type: Mapped[str] = mapped_column(String(40), default="CONNECTS_TO")
    description: Mapped[str] = mapped_column(Text, default="")
    __table_args__ = (UniqueConstraint("source_asset_id", "target_asset_id", "type"),)


class Software(Record, Provenance, Base):
    __tablename__ = "software"
    canonical_name: Mapped[str] = mapped_column(String(200), index=True)
    vendor: Mapped[str] = mapped_column(String(200), default="")
    ecosystem: Mapped[str] = mapped_column(String(60), default="generic")
    lifecycle: Mapped[str] = mapped_column(String(40), default="UNKNOWN")
    __table_args__ = (UniqueConstraint("canonical_name", "vendor", "ecosystem"),)


class SoftwareInstallation(Record, Provenance, Base):
    __tablename__ = "software_installation"
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    software_id: Mapped[int] = mapped_column(ForeignKey("software.id"), index=True)
    original_name: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(200), default="")
    architecture: Mapped[str] = mapped_column(String(60), default="")
    package_identifier: Mapped[str] = mapped_column(String(1000), default="")
    installation_source: Mapped[str] = mapped_column(String(200), default="")
    normalization_method: Mapped[str] = mapped_column(String(100), default="exact")
    normalization_confidence: Mapped[str] = mapped_column(String(30), default="HIGH")
    first_seen: Mapped[str] = mapped_column(String(40), default=now)
    last_seen: Mapped[str] = mapped_column(String(40), default=now)
    __table_args__ = (UniqueConstraint("asset_id", "software_id", "package_identifier"),)


class Service(Record, Provenance, Base):
    __tablename__ = "service"
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    installation_id: Mapped[int | None] = mapped_column(ForeignKey("software_installation.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(20), default="TCP")
    version: Mapped[str] = mapped_column(String(100), default="")
    exposure: Mapped[str] = mapped_column(String(40), default="UNKNOWN")
    status: Mapped[str] = mapped_column(String(30), default="UNKNOWN")


class SBOM(Record, Provenance, Base):
    __tablename__ = "sbom"
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    format: Mapped[str] = mapped_column(String(40))
    serial: Mapped[str] = mapped_column(String(500), default="")
    digest: Mapped[str] = mapped_column(String(64), index=True)


class SBOMComponent(Record, Provenance, Base):
    __tablename__ = "sbom_component"
    sbom_id: Mapped[int] = mapped_column(ForeignKey("sbom.id"), index=True)
    installation_id: Mapped[int | None] = mapped_column(ForeignKey("software_installation.id"), index=True)
    ref: Mapped[str] = mapped_column(String(1000))
    name: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(200), default="")
    vendor: Mapped[str] = mapped_column(String(200), default="")
    purl: Mapped[str] = mapped_column(String(1000), default="")
    hashes: Mapped[list] = mapped_column(JSON, default=list)
    licenses: Mapped[list] = mapped_column(JSON, default=list)
    direct: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    __table_args__ = (UniqueConstraint("sbom_id", "ref"),)


class Dependency(Record, Base):
    __tablename__ = "dependency"
    sbom_id: Mapped[int] = mapped_column(ForeignKey("sbom.id"), index=True)
    source_component_id: Mapped[int] = mapped_column(ForeignKey("sbom_component.id"), index=True)
    target_component_id: Mapped[int] = mapped_column(ForeignKey("sbom_component.id"), index=True)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"))
    __table_args__ = (UniqueConstraint("source_component_id", "target_component_id"),)


class Vulnerability(Record, Provenance, Base):
    __tablename__ = "vulnerability"
    identifier: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_version: Mapped[str] = mapped_column(String(30), default="")
    cvss_vector: Mapped[str] = mapped_column(String(300), default="")
    cwe: Mapped[str] = mapped_column(String(100), default="")
    published_at: Mapped[str] = mapped_column(String(40), default="")
    modified_at: Mapped[str] = mapped_column(String(40), default="")
    known_exploited: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    exploit_available: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    exploit_maturity: Mapped[str] = mapped_column(String(40), default="UNKNOWN")
    attack_complexity: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    privileges_required: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    user_interaction: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)


class AffectedRange(Record, Base):
    __tablename__ = "affected_range"
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerability.id"), index=True)
    product: Mapped[str] = mapped_column(String(200), index=True)
    vendor: Mapped[str] = mapped_column(String(200), default="")
    ecosystem: Mapped[str] = mapped_column(String(60), default="generic")
    version_scheme: Mapped[str] = mapped_column(String(40), default="unknown")
    affected: Mapped[str] = mapped_column(String(500))
    fixed_versions: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"))


class VulnerabilityReference(Record, Base):
    __tablename__ = "vulnerability_reference"
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerability.id"), index=True)
    label: Mapped[str] = mapped_column(String(200), default="")
    url: Mapped[str] = mapped_column(String(2000))


class VulnerabilityMatch(Record, Base):
    __tablename__ = "vulnerability_match"
    installation_id: Mapped[int] = mapped_column(ForeignKey("software_installation.id"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerability.id"), index=True)
    range_id: Mapped[int | None] = mapped_column(ForeignKey("affected_range.id"))
    state: Mapped[str] = mapped_column(String(30), default="NEEDS_REVIEW", index=True)
    method: Mapped[str] = mapped_column(String(100))
    observed_version: Mapped[str] = mapped_column(String(200), default="")
    rule: Mapped[str] = mapped_column(String(500), default="")
    confidence: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    evidence_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    affected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    analyst_state: Mapped[str | None] = mapped_column(String(30))
    analyst_reason: Mapped[str] = mapped_column(Text, default="")
    __table_args__ = (UniqueConstraint("installation_id", "vulnerability_id"),)


class ExposureObservation(Record, Provenance, Base):
    __tablename__ = "exposure_observation"
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("service.id"), index=True)
    exposure: Mapped[str] = mapped_column(String(40), default="UNKNOWN")
    note: Mapped[str] = mapped_column(Text, default="")


class ExploitabilityObservation(Record, Provenance, Base):
    __tablename__ = "exploitability_observation"
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerability.id"), index=True)
    reachability: Mapped[str] = mapped_column(String(40), default="UNKNOWN")
    privileges: Mapped[str] = mapped_column(String(40), default="UNKNOWN")
    complexity: Mapped[str] = mapped_column(String(40), default="UNKNOWN")
    note: Mapped[str] = mapped_column(Text, default="")


class RiskAssessment(Record, Base):
    __tablename__ = "risk_assessment"
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    vulnerability_id: Mapped[int | None] = mapped_column(ForeignKey("vulnerability.id"), index=True)
    match_id: Mapped[int | None] = mapped_column(ForeignKey("vulnerability_match.id"), unique=True)
    category: Mapped[str] = mapped_column(String(40), default="VULNERABILITY", index=True)
    rule_key: Mapped[str] = mapped_column(String(100), default="")
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    priority: Mapped[str] = mapped_column(String(30), default="INFORMATIONAL", index=True)
    score: Mapped[float] = mapped_column(Float, default=0, index=True)
    confidence: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    exposure: Mapped[str] = mapped_column(String(40), default="UNKNOWN")
    exploitability: Mapped[str] = mapped_column(String(40), default="UNKNOWN")
    status: Mapped[str] = mapped_column(String(30), default="OPEN", index=True)
    owner: Mapped[str] = mapped_column(String(200), default="")
    due_date: Mapped[str | None] = mapped_column(String(40))
    factors: Mapped[list[dict]] = mapped_column(JSON, default=list)
    reasoning: Mapped[list[str]] = mapped_column(JSON, default=list)
    uncertainties: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    rules_version: Mapped[str] = mapped_column(String(100), default="1.0")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    analyst_override: Mapped[dict] = mapped_column(JSON, default=dict)
    analyst_reason: Mapped[str] = mapped_column(Text, default="")
    verified_version: Mapped[str | None] = mapped_column(String(200))
    __table_args__ = (Index("ix_risk_asset_status_score", "asset_id", "status", "score"),)


class RiskFactor(Record, Base):
    __tablename__ = "risk_factor"
    risk_id: Mapped[int] = mapped_column(ForeignKey("risk_assessment.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    value: Mapped[str] = mapped_column(String(500))
    contribution: Mapped[float] = mapped_column(Float)
    evidence_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    reasoning: Mapped[str] = mapped_column(Text)


class AssessmentHistory(Record, Base):
    __tablename__ = "assessment_history"
    risk_id: Mapped[int] = mapped_column(ForeignKey("risk_assessment.id"), index=True)
    snapshot: Mapped[dict] = mapped_column(JSON)


class AttackPath(Record, Base):
    __tablename__ = "attack_path"
    risk_id: Mapped[int] = mapped_column(ForeignKey("risk_assessment.id"), index=True)
    source_asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    target_asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    asset_ids: Mapped[list[int]] = mapped_column(JSON)
    relationship_ids: Mapped[list[int]] = mapped_column(JSON)
    evidence_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    reasoning: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(30), default="POTENTIAL")


class Remediation(Record, Base):
    __tablename__ = "remediation"
    risk_id: Mapped[int] = mapped_column(ForeignKey("risk_assessment.id"), index=True)
    action: Mapped[str] = mapped_column(Text)
    fixed_version: Mapped[str] = mapped_column(String(200), default="")
    owner: Mapped[str] = mapped_column(String(200), default="")
    priority: Mapped[str] = mapped_column(String(30), default="MEDIUM")
    due_date: Mapped[str | None] = mapped_column(String(40), index=True)
    status: Mapped[str] = mapped_column(String(30), default="OPEN", index=True)
    completed_at: Mapped[str | None] = mapped_column(String(40))


class RemediationVerification(Record, Base):
    __tablename__ = "remediation_verification"
    risk_id: Mapped[int] = mapped_column(ForeignKey("risk_assessment.id"), index=True)
    method: Mapped[str] = mapped_column(String(60))
    actor: Mapped[str] = mapped_column(String(200))
    reason: Mapped[str] = mapped_column(Text)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"))
    before: Mapped[dict] = mapped_column(JSON)
    after: Mapped[dict] = mapped_column(JSON)


class RiskAcceptance(Record, Base):
    __tablename__ = "risk_acceptance"
    risk_id: Mapped[int] = mapped_column(ForeignKey("risk_assessment.id"), index=True)
    reason: Mapped[str] = mapped_column(Text)
    approver: Mapped[str] = mapped_column(String(200))
    expires_at: Mapped[str] = mapped_column(String(40), index=True)
    compensating_controls: Mapped[str] = mapped_column(Text)
    expired: Mapped[bool] = mapped_column(Boolean, default=False)


class Case(Record, Base):
    __tablename__ = "case_record"
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(30), default="OPEN", index=True)


class CaseRisk(Record, Base):
    __tablename__ = "case_risk"
    case_id: Mapped[int] = mapped_column(ForeignKey("case_record.id"), index=True)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risk_assessment.id"), index=True)
    __table_args__ = (UniqueConstraint("case_id", "risk_id"),)


class CaseAsset(Record, Base):
    __tablename__ = "case_asset"
    case_id: Mapped[int] = mapped_column(ForeignKey("case_record.id"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    __table_args__ = (UniqueConstraint("case_id", "asset_id"),)


class AnalystNote(Record, Base):
    __tablename__ = "analyst_note"
    risk_id: Mapped[int | None] = mapped_column(ForeignKey("risk_assessment.id"), index=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("case_record.id"), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("asset.id"), index=True)
    actor: Mapped[str] = mapped_column(String(200))
    text: Mapped[str] = mapped_column(Text)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"))


class TimelineEvent(Record, Base):
    __tablename__ = "timeline_event"
    action: Mapped[str] = mapped_column(String(100), index=True)
    object_type: Mapped[str] = mapped_column(String(60), index=True)
    object_id: Mapped[int] = mapped_column(Integer, index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("asset.id"), index=True)
    risk_id: Mapped[int | None] = mapped_column(ForeignKey("risk_assessment.id"), index=True)
    actor: Mapped[str] = mapped_column(String(200), default="System")
    summary: Mapped[str] = mapped_column(Text)
    evidence_ids: Mapped[list[int]] = mapped_column(JSON, default=list)


class AuditEvent(Record, Base):
    __tablename__ = "audit_event"
    action: Mapped[str] = mapped_column(String(100), index=True)
    object_type: Mapped[str] = mapped_column(String(60), index=True)
    object_id: Mapped[int] = mapped_column(Integer, index=True)
    actor: Mapped[str] = mapped_column(String(200), default="System")
    reason: Mapped[str] = mapped_column(Text)
    before: Mapped[dict] = mapped_column(JSON, default=dict)
    after: Mapped[dict] = mapped_column(JSON, default=dict)


class ImportJob(Record, Base):
    __tablename__ = "import_job"
    kind: Mapped[str] = mapped_column(String(40))
    filename: Mapped[str] = mapped_column(String(200))
    digest: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(40), default="COMPLETED")
    processed: Mapped[int] = mapped_column(Integer, default=0)
    imported: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)


class ImportRecord(Record, Base):
    __tablename__ = "import_record"
    import_job_id: Mapped[int] = mapped_column(ForeignKey("import_job.id"), index=True)
    row_number: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(40))
    object_type: Mapped[str] = mapped_column(String(60), default="")
    object_id: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[dict] = mapped_column(JSON, default=dict)


class Report(Record, Base):
    __tablename__ = "report"
    title: Mapped[str] = mapped_column(String(500))
    perspective: Mapped[str] = mapped_column(String(30), default="technical")
    snapshot: Mapped[dict] = mapped_column(JSON)


class RiskSnapshot(Record, Base):
    __tablename__ = "risk_snapshot"
    counts: Mapped[dict] = mapped_column(JSON)
    open_risk: Mapped[int] = mapped_column(Integer)
    remediated: Mapped[int] = mapped_column(Integer)
    new_risks: Mapped[int] = mapped_column(Integer, default=0)
    overdue: Mapped[int] = mapped_column(Integer, default=0)


class Setting(Record, Base):
    __tablename__ = "setting"
    key: Mapped[str] = mapped_column(String(100), unique=True)
    value: Mapped[dict] = mapped_column(JSON)


class ProviderCache(Record, Base):
    __tablename__ = "provider_cache"
    source: Mapped[str] = mapped_column(String(200), unique=True)
    version: Mapped[str] = mapped_column(String(200), default="")
    digest: Mapped[str] = mapped_column(String(64), default="")
    downloaded_at: Mapped[str | None] = mapped_column(String(40))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
