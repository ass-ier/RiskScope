from datetime import datetime
from ipaddress import ip_address, ip_network
import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, create_model, field_validator

from app import models as m

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
Text = Annotated[str, StringConstraints(strip_whitespace=True, max_length=20000)]
Priority = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
Confidence = Literal["HIGH", "MEDIUM", "LOW", "UNKNOWN"]
Exposure = Literal[
    "INTERNET_FACING", "EXTERNALLY_REACHABLE", "INTERNAL_ONLY", "RESTRICTED", "ISOLATED", "UNKNOWN"
]
RiskStatus = Literal[
    "OPEN", "ASSIGNED", "IN_PROGRESS", "REMEDIATED", "VERIFIED", "RISK_ACCEPTED", "FALSE_POSITIVE", "DEFERRED"
]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, from_attributes=True)


class ProvenanceInput(Input):
    source: str = Field(default="Manual", max_length=500)
    confidence: Confidence = "UNKNOWN"
    evidence_id: int | None = None


class AssetInput(ProvenanceInput):
    hostname: Name
    ip: str = Field(default="", max_length=80)
    mac: str = Field(default="", max_length=80)
    os: str = Field(default="", max_length=200)
    os_version: str = Field(default="", max_length=100)
    environment: Literal["PRODUCTION", "STAGING", "DEVELOPMENT", "TEST", "LAB", "UNKNOWN"] = "UNKNOWN"
    owner: str = Field(default="", max_length=200)
    business_unit: str = Field(default="", max_length=200)
    location: str = Field(default="", max_length=200)
    criticality: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] = "UNKNOWN"
    exposure: Exposure = "UNKNOWN"
    zone_id: int | None = None
    tags: list[str] = Field(default_factory=list, max_length=100)
    description: Text = ""
    status: Literal["ACTIVE", "INACTIVE", "RETIRED", "UNKNOWN"] = "ACTIVE"

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, value):
        if value:
            ip_address(value)
        return value

    @field_validator("mac")
    @classmethod
    def valid_mac(cls, value):
        if value and not re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", value):
            raise ValueError("MAC must contain six hexadecimal octets")
        return value


class ZoneInput(ProvenanceInput):
    name: Name
    description: Text = ""
    subnet: str = Field(default="", max_length=80)
    vlan: str = Field(default="", max_length=80)
    gateway: str = Field(default="", max_length=80)

    @field_validator("subnet")
    @classmethod
    def valid_subnet(cls, value):
        if value:
            ip_network(value, strict=False)
        return value

    @field_validator("gateway")
    @classmethod
    def valid_gateway(cls, value):
        if value:
            ip_address(value)
        return value


class BusinessInput(ProvenanceInput):
    asset_id: int
    business_owner: str = Field(default="", max_length=200)
    application: str = Field(default="", max_length=200)
    business_function: Text = ""
    data_classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "UNKNOWN"] = "UNKNOWN"
    regulatory_importance: Text = ""


class RelationshipInput(ProvenanceInput):
    source_asset_id: int
    target_asset_id: int
    type: Literal[
        "HOSTS", "CONNECTS_TO", "DEPENDS_ON", "AUTHENTICATES_TO", "MANAGES", "BACKS_UP", "ROUTES_TO", "MEMBER_OF"
    ] = "CONNECTS_TO"
    description: Text = ""


class SoftwareInput(ProvenanceInput):
    canonical_name: Name
    vendor: str = Field(default="", max_length=200)
    ecosystem: str = Field(default="generic", max_length=60)
    lifecycle: Literal["SUPPORTED", "END_OF_LIFE", "UNKNOWN"] = "UNKNOWN"


class InstallationInput(ProvenanceInput):
    asset_id: int
    software_id: int
    original_name: Name
    version: str = Field(default="", max_length=200)
    architecture: str = Field(default="", max_length=60)
    package_identifier: str = Field(default="", max_length=1000)
    installation_source: str = Field(default="", max_length=200)


class ServiceInput(ProvenanceInput):
    asset_id: int
    installation_id: int | None = None
    name: Name
    port: int = Field(ge=1, le=65535)
    protocol: Literal["TCP", "UDP"] = "TCP"
    version: str = Field(default="", max_length=100)
    exposure: Exposure = "UNKNOWN"
    status: Literal["RUNNING", "STOPPED", "REMOVED", "UNKNOWN"] = "UNKNOWN"


class VulnerabilityInput(ProvenanceInput):
    identifier: Name
    title: str = Field(min_length=1, max_length=500)
    description: Text = ""
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_version: str = Field(default="", max_length=30)
    cvss_vector: str = Field(default="", max_length=300)
    cwe: str = Field(default="", max_length=100)
    published_at: str = Field(default="", max_length=40)
    modified_at: str = Field(default="", max_length=40)
    known_exploited: bool | None = None
    exploit_available: bool | None = None
    exploit_maturity: Literal["MATURE", "FUNCTIONAL", "PROOF_OF_CONCEPT", "UNKNOWN"] = "UNKNOWN"
    attack_complexity: Literal["LOW", "HIGH", "UNKNOWN"] = "UNKNOWN"
    privileges_required: Literal["NONE", "LOW", "HIGH", "UNKNOWN"] = "UNKNOWN"
    user_interaction: Literal["NONE", "REQUIRED", "UNKNOWN"] = "UNKNOWN"
    recommendation: Text = ""
    synthetic: bool = False


class RangeInput(Input):
    vulnerability_id: int
    product: Name
    vendor: str = Field(default="", max_length=200)
    ecosystem: str = Field(default="generic", max_length=60)
    version_scheme: str = Field(default="unknown", max_length=40)
    affected: str = Field(min_length=1, max_length=500)
    fixed_versions: list[str] = Field(default_factory=list, max_length=100)
    evidence_id: int | None = None


class ReferenceInput(Input):
    vulnerability_id: int
    label: str = Field(default="", max_length=200)
    url: str = Field(max_length=2000)

    @field_validator("url")
    @classmethod
    def safe_url(cls, value):
        if not value.startswith(("https://", "http://")):
            raise ValueError("References must use http or https")
        return value


class ExposureInput(ProvenanceInput):
    asset_id: int
    service_id: int | None = None
    exposure: Exposure = "UNKNOWN"
    note: Text = ""


class ExploitabilityInput(ProvenanceInput):
    asset_id: int
    vulnerability_id: int
    reachability: Literal["REACHABLE", "BLOCKED", "UNKNOWN"] = "UNKNOWN"
    privileges: Literal["NONE", "LOW", "HIGH", "UNKNOWN"] = "UNKNOWN"
    complexity: Literal["LOW", "HIGH", "UNKNOWN"] = "UNKNOWN"
    note: Text = ""


class EvidenceInput(Input):
    type: Literal[
        "ASSET_INVENTORY", "SOFTWARE_INVENTORY", "SBOM", "VULNERABILITY_RECORD",
        "NETWORK_OBSERVATION", "SERVICE_OBSERVATION", "EXPLOIT_INTELLIGENCE",
        "REMEDIATION_EVIDENCE", "ANALYST_NOTE", "IMPORT_RECORD"
    ] = "ANALYST_NOTE"
    source: str = Field(default="Manual", max_length=500)
    summary: Text = Field(min_length=1)
    content: dict[str, Any] = Field(default_factory=dict)
    confidence: Confidence = "UNKNOWN"
    actor: Name = "Local analyst"


class RemediationInput(Input):
    risk_id: int
    action: Text = Field(min_length=1)
    fixed_version: str = Field(default="", max_length=200)
    owner: str = Field(default="", max_length=200)
    priority: Priority = "MEDIUM"
    due_date: str | None = None
    status: RiskStatus = "OPEN"

    @field_validator("due_date")
    @classmethod
    def valid_date(cls, value):
        if value:
            datetime.fromisoformat(value)
        return value


class CaseInput(Input):
    title: str = Field(min_length=1, max_length=500)
    description: Text = ""
    owner: str = Field(default="", max_length=200)
    status: Literal["OPEN", "INVESTIGATING", "REMEDIATION", "VERIFICATION", "CLOSED"] = "OPEN"


class CaseRiskInput(Input):
    case_id: int
    risk_id: int


class CaseAssetInput(Input):
    case_id: int
    asset_id: int


class NoteInput(Input):
    risk_id: int | None = None
    case_id: int | None = None
    asset_id: int | None = None
    actor: Name
    text: Text = Field(min_length=1)
    evidence_id: int | None = None


class RiskCreate(Input):
    asset_id: int
    title: str = Field(min_length=1, max_length=500)
    category: Literal[
        "SOFTWARE_LIFECYCLE", "EXPOSURE", "CONFIGURATION", "DEPENDENCY",
        "ASSET_RISK", "NETWORK_RISK", "IDENTITY_RISK"
    ]
    severity: Priority = "MEDIUM"
    confidence: Confidence = "UNKNOWN"
    evidence_id: int
    recommendation: Text
    reason: Text = Field(min_length=1)
    actor: Name


class Decision(Input):
    actor: Name
    reason: Text = Field(min_length=1)
    status: Literal["OPEN", "IN_PROGRESS", "REMEDIATED", "FALSE_POSITIVE", "DEFERRED"] | None = None
    match_state: Literal["CONFIRMED", "POTENTIAL", "REJECTED", "NEEDS_REVIEW"] | None = None
    priority: Priority | None = None
    severity: Priority | None = None
    confidence: Confidence | None = None
    exposure: Exposure | None = None
    exploitability: Literal["KNOWN_EXPLOITED", "EXPLOIT_AVAILABLE", "NO_KNOWN_EXPLOIT", "UNKNOWN"] | None = None
    clear_overrides: bool = False


class AcceptInput(Input):
    reason: Text = Field(min_length=1)
    approver: Name
    expires_at: datetime
    compensating_controls: Text = Field(min_length=1)


class VerifyInput(Input):
    actor: Name
    reason: Text = Field(min_length=1)
    evidence_id: int
    method: Literal["ANALYST"] = "ANALYST"


class ReportInput(Input):
    title: str = Field(default="RiskScope assessment", min_length=1, max_length=500)
    perspective: Literal["technical", "executive"] = "technical"


class ReportSummary(BaseModel):
    id: int
    title: str
    perspective: str
    created_at: str
    updated_at: str


class Weights(Input):
    cvss: float = Field(default=3, ge=0, le=10)
    known_exploitation: float = Field(default=18, ge=0, le=30)
    exploit_available: float = Field(default=6, ge=0, le=20)
    exposure: float = Field(default=16, ge=0, le=30)
    criticality: float = Field(default=14, ge=0, le=30)
    production: float = Field(default=6, ge=0, le=20)
    service: float = Field(default=4, ge=0, le=20)
    privileges: float = Field(default=3, ge=0, le=10)
    complexity: float = Field(default=3, ge=0, le=10)
    path: float = Field(default=6, ge=0, le=20)


class SettingsInput(Input):
    weights: Weights = Field(default_factory=Weights)
    max_path_depth: int = Field(default=4, ge=1, le=6)
    max_paths: int = Field(default=200, ge=1, le=500)
    max_graph_edges: int = Field(default=500, ge=10, le=1000)
    lifecycle_rules: bool = True
    configuration_rules: bool = True


class Page(BaseModel):
    items: list[dict[str, Any]]
    total: int
    page: int
    page_size: int


# Each resource has an explicit validated write DTO. Read DTOs are generated once
# from declared column types and validate every database result before serialization.
RESOURCES: dict[str, tuple[type, type[Input] | None]] = {
    "assets": (m.Asset, AssetInput),
    "zones": (m.NetworkZone, ZoneInput),
    "business-context": (m.BusinessContext, BusinessInput),
    "relationships": (m.AssetRelationship, RelationshipInput),
    "software": (m.Software, SoftwareInput),
    "installations": (m.SoftwareInstallation, InstallationInput),
    "services": (m.Service, ServiceInput),
    "vulnerabilities": (m.Vulnerability, VulnerabilityInput),
    "affected-ranges": (m.AffectedRange, RangeInput),
    "references": (m.VulnerabilityReference, ReferenceInput),
    "exposure-observations": (m.ExposureObservation, ExposureInput),
    "exploitability-observations": (m.ExploitabilityObservation, ExploitabilityInput),
    "evidence": (m.Evidence, EvidenceInput),
    "remediation": (m.Remediation, RemediationInput),
    "cases": (m.Case, CaseInput),
    "case-risks": (m.CaseRisk, CaseRiskInput),
    "case-assets": (m.CaseAsset, CaseAssetInput),
    "notes": (m.AnalystNote, NoteInput),
    "risk": (m.RiskAssessment, None),
    "matches": (m.VulnerabilityMatch, None),
    "risk-factors": (m.RiskFactor, None),
    "assessment-history": (m.AssessmentHistory, None),
    "attack-paths": (m.AttackPath, None),
    "sbom": (m.SBOM, None),
    "components": (m.SBOMComponent, None),
    "dependencies": (m.Dependency, None),
    "imports": (m.ImportJob, None),
    "import-records": (m.ImportRecord, None),
    "timeline": (m.TimelineEvent, None),
    "audit": (m.AuditEvent, None),
    "reports": (m.Report, None),
    "verifications": (m.RemediationVerification, None),
    "acceptances": (m.RiskAcceptance, None),
    "snapshots": (m.RiskSnapshot, None),
    "providers": (m.ProviderCache, None),
}


def read_dto(model: type) -> type[BaseModel]:
    fields = {}
    for column in model.__table__.columns:
        field_type = column.type.python_type
        if field_type is dict:
            field_type = Any
        if column.nullable:
            field_type = field_type | None
        fields[column.name] = (field_type, ...)
    return create_model(
        f"{model.__name__}Read", __config__=ConfigDict(from_attributes=True), **fields
    )


READ_DTOS = {model: read_dto(model) for model, _ in RESOURCES.values()}


def serialize(record) -> dict:
    dto = READ_DTOS.get(type(record))
    if dto is None:
        dto = read_dto(type(record))
    return dto.model_validate(record).model_dump(mode="json")
