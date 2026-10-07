"""Deterministic, conservative correlation and evidence-backed risk prioritization."""

import json
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from hashlib import sha256

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session, defer

from app import models as m
from app.schemas import SettingsInput, serialize
from app.services.common import ACTIVE_STATUSES, audit, overdue_risk_query
from app.services.imports import normalize_product

DEFAULT_SETTINGS = SettingsInput().model_dump()
PRIORITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
PATH_RELATIONSHIPS = ("CONNECTS_TO", "DEPENDS_ON", "AUTHENTICATES_TO", "MANAGES", "ROUTES_TO")
RULES_VERSION = "1.1"
PRESERVED_STATUSES = ("RISK_ACCEPTED", "FALSE_POSITIVE", "DEFERRED")
EXPOSURE_SCALE = {
    "INTERNET_FACING": 1.0, "EXTERNALLY_REACHABLE": 0.75, "INTERNAL_ONLY": 0.15,
    "RESTRICTED": 0.05, "ISOLATED": 0.0, "UNKNOWN": 0.0,
}
CRITICALITY_SCALE = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.4, "LOW": 0.1, "UNKNOWN": 0.0}
MANUAL_SEVERITY_POINTS = {"CRITICAL": 80, "HIGH": 60, "MEDIUM": 35, "LOW": 15, "INFORMATIONAL": 0}
WRITE_BATCH_SIZE = 200


def get_settings(db: Session) -> dict:
    record = db.scalar(select(m.Setting).where(m.Setting.key == "risk"))
    if record is None:
        record = db.scalar(select(m.Setting).where(m.Setting.key == "risk_engine"))
    return SettingsInput.model_validate(record.value if record else DEFAULT_SETTINGS).model_dump()


def _rules_version(settings):
    return f"{RULES_VERSION}:{sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()[:16]}"


def _numeric(value, semver=False):
    pattern = r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)" if semver else r"\d+(?:\.\d+)*"
    if not isinstance(value, str) or len(value) > 200 or not re.fullmatch(pattern, value):
        return None
    parts = value.split(".")
    if len(parts) > 20 or any(len(part) > 20 for part in parts):
        return None
    numbers = [int(part) for part in parts]
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    return tuple(numbers)


def evaluate_version(version: str, rule: str, scheme: str) -> tuple[bool | None, str, str]:
    """Return (affected, method, confidence); None means unsupported or insufficient evidence."""
    if not version or not isinstance(version, str):
        return None, "missing-version", "UNKNOWN"
    if not isinstance(rule, str) or not rule.strip() or len(rule) > 500:
        return None, "unsupported-range", "UNKNOWN"
    scheme = scheme.casefold().strip() if isinstance(scheme, str) else "unknown"
    if scheme in ("pep440", "python"):
        try:
            parsed = Version(version)
            specifier = SpecifierSet(rule)
            return parsed in specifier, "pep440", "HIGH"
        except (InvalidVersion, InvalidSpecifier):
            return None, "unsupported-pep440-range", "UNKNOWN"
    if scheme not in ("generic", "numeric", "numeric-dotted", "semver"):
        return None, "unsupported-version-scheme", "UNKNOWN"
    semver = scheme == "semver"
    observed = _numeric(version, semver)
    if observed is None:
        return None, "unsupported-version", "UNKNOWN"
    results = []
    for term in rule.split(","):
        match = re.fullmatch(r"\s*(>=|<=|==|!=|>|<|=)?\s*(\d+(?:\.\d+)*)\s*", term)
        if not match:
            return None, "unsupported-range", "UNKNOWN"
        target = _numeric(match[2], semver)
        if target is None:
            return None, "unsupported-range", "UNKNOWN"
        comparison = (observed > target) - (observed < target)
        result = {
            ">=": comparison >= 0, "<=": comparison <= 0, ">": comparison > 0,
            "<": comparison < 0, "==": comparison == 0, "=": comparison == 0, "!=": comparison != 0,
        }[match[1] or "=="]
        results.append(result)
    return all(results), "semver-stable" if semver else "numeric-dotted", "HIGH"


def priority(score: float) -> str:
    return next(
        (name for threshold, name in ((80, "CRITICAL"), (60, "HIGH"), (35, "MEDIUM"), (15, "LOW"))
         if score >= threshold),
        "INFORMATIONAL",
    )


def _severity(cvss):
    if cvss is None:
        return "UNKNOWN"
    if cvss == 0:
        return "INFORMATIONAL"
    return next(
        (name for threshold, name in ((9, "CRITICAL"), (7, "HIGH"), (4, "MEDIUM"))
         if cvss >= threshold),
        "LOW",
    )


def _date(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def _ids(*values):
    result = set()
    for value in values:
        if isinstance(value, (list, tuple, set)):
            result.update(item for item in value if item is not None)
        elif value is not None:
            result.add(value)
    return sorted(result)


def _latest(rows, key):
    result = {}
    for row in rows:
        identity = key(row)
        previous = result.get(identity)
        if previous is None or (row.created_at, row.id) > (previous.created_at, previous.id):
            result[identity] = row
    return result


def expire_acceptances(db: Session):
    now = datetime.now(timezone.utc)
    acceptances = list(db.scalars(select(m.RiskAcceptance)))
    latest = _latest(acceptances, lambda item: item.risk_id)
    expired = 0
    for acceptance in acceptances:
        if acceptance.expired or _date(acceptance.expires_at) > now:
            continue
        before = serialize(acceptance)
        acceptance.expired = True
        expired += 1
        audit(
            db, "RISK_ACCEPTANCE_EXPIRED", acceptance, before,
            reason="Time-limited risk acceptance expired", risk_id=acceptance.risk_id,
        )
        risk = db.get(m.RiskAssessment, acceptance.risk_id)
        if risk and risk.status == "RISK_ACCEPTED" and latest[risk.id].id == acceptance.id:
            before_risk = serialize(risk)
            risk.status = "OPEN"
            audit(db, "RISK_REOPENED", risk, before_risk, reason="Acceptance expired", asset_id=risk.asset_id, risk_id=risk.id)
            for task in db.scalars(select(m.Remediation).where(m.Remediation.risk_id == risk.id)):
                if task.status == "RISK_ACCEPTED":
                    before_task = serialize(task)
                    task.status = "OPEN"
                    audit(db, "REMEDIATION_REOPENED", task, before_task, reason="Acceptance expired", risk_id=risk.id)
    db.flush()
    return expired


class Context:
    def __init__(self, db):
        self.db = db
        self.assessment_batch = []
        self.assets = {item.id: item for item in db.scalars(select(m.Asset))}
        self.software = {item.id: item for item in db.scalars(select(m.Software))}
        self.installations = {item.id: item for item in db.scalars(select(m.SoftwareInstallation))}
        self.vulnerabilities = {item.id: item for item in db.scalars(select(m.Vulnerability))}
        self.ranges = defaultdict(list)
        for item in db.scalars(select(m.AffectedRange)):
            self.ranges[normalize_product(item.product)[0]].append(item)
        self.matches = {
            (item.installation_id, item.vulnerability_id): item for item in db.scalars(select(m.VulnerabilityMatch))
        }
        proof_ids = sorted({
            installation.evidence_id
            for (installation_id, _), match in self.matches.items()
            if (installation := self.installations.get(installation_id))
            and installation.evidence_id
            and installation.version != match.observed_version
            and installation.evidence_id not in match.evidence_ids
        })
        self.fresh_proofs = {}
        self.sbom_proof_installations = {}
        for offset in range(0, len(proof_ids), 500):
            batch = proof_ids[offset:offset + 500]
            self.fresh_proofs.update({
                item.id: item for item in db.scalars(select(m.Evidence).where(
                    m.Evidence.id.in_(batch)
                ))
            })
            self.sbom_proof_installations.update({
                item.evidence_id: item.installation_id
                for item in db.scalars(select(m.SBOMComponent).where(m.SBOMComponent.evidence_id.in_(batch)))
            })
        self.risks = list(db.scalars(select(m.RiskAssessment).options(
            defer(m.RiskAssessment.factors), defer(m.RiskAssessment.reasoning), defer(m.RiskAssessment.uncertainties),
        )))
        self.risk_by_match = {item.match_id: item for item in self.risks if item.match_id is not None}
        self.business = {item.asset_id: item for item in db.scalars(select(m.BusinessContext))}
        self.exposure = _latest(
            db.scalars(select(m.ExposureObservation)), lambda item: (item.asset_id, item.service_id)
        )
        self.exploitability = _latest(
            db.scalars(select(m.ExploitabilityObservation)), lambda item: (item.asset_id, item.vulnerability_id)
        )
        self.services = defaultdict(list)
        self.asset_services = defaultdict(list)
        for item in db.scalars(select(m.Service)):
            self.services[item.installation_id].append(item)
            self.asset_services[item.asset_id].append(item)
        self.remediations = defaultdict(list)
        for item in db.scalars(select(m.Remediation)):
            self.remediations[item.risk_id].append(item)

    def asset_exposure(self, asset):
        observed = self.exposure.get((asset.id, None))
        return (observed.exposure, observed.evidence_id) if observed else (asset.exposure, asset.evidence_id)

    def service_exposure(self, service):
        observed = self.exposure.get((service.asset_id, service.id))
        return (observed.exposure, observed.evidence_id) if observed else (service.exposure, service.evidence_id)


def _range_result(installation, software, ranges):
    evaluations = []
    for rule in ranges:
        vendor = rule.vendor.strip().casefold()
        installed_vendor = software.vendor.strip().casefold()
        ecosystem = rule.ecosystem.strip().casefold()
        installed_ecosystem = software.ecosystem.strip().casefold()
        if vendor and installed_vendor and vendor != installed_vendor:
            continue
        if ecosystem and installed_ecosystem and ecosystem != installed_ecosystem:
            continue
        identity_unknown = bool(vendor and not installed_vendor) or not ecosystem or not installed_ecosystem
        affected, method, confidence = evaluate_version(installation.version, rule.affected, rule.version_scheme)
        if rule.version_scheme.casefold() in ("pep440", "python") and installed_ecosystem != "python":
            affected, method, confidence = None, "pep440-requires-python-ecosystem", "UNKNOWN"
        evaluations.append((rule, affected, method, confidence, identity_unknown))
    if not evaluations:
        return None
    confirmed = [item for item in evaluations if item[1] is True and not item[4]]
    uncertain = [item for item in evaluations if item[1] is None or item[4]]
    if confirmed:
        chosen = confirmed[0]
        affected, state = True, "CONFIRMED"
    elif uncertain:
        chosen = uncertain[0]
        affected = None
        state = "POTENTIAL" if chosen[4] and chosen[1] is not None else "NEEDS_REVIEW"
    else:
        chosen = evaluations[0]
        affected, state = False, "REJECTED"
    methods = sorted({item[2] for item in evaluations})
    return {
        "range_id": chosen[0].id, "affected": affected, "state": state,
        "method": ("identity-uncertain/" if chosen[4] else "") + "+".join(methods),
        "confidence": "HIGH" if affected is not None else ("LOW" if state == "POTENTIAL" else "UNKNOWN"),
        "observed_version": installation.version,
        "rule": " OR ".join(item[0].affected for item in evaluations)[:500],
        "evidence_ids": _ids(installation.evidence_id, software.evidence_id, [item[0].evidence_id for item in evaluations]),
        "evaluations": evaluations,
    }


def _fixed_version_support(version, evaluations):
    for rule, affected, _, _, identity_unknown in evaluations:
        if affected is not False or identity_unknown:
            continue
        for fixed in rule.fixed_versions:
            not_affected, _, _ = evaluate_version(fixed, rule.affected, rule.version_scheme)
            reached, _, _ = evaluate_version(version, f">={fixed}", rule.version_scheme)
            if not_affected is False and reached is True:
                return fixed
    return None


def _verify_changed_version(context, risk, match, prior_match, installation, result):
    if risk.status in PRESERVED_STATUSES or match.analyst_state == "REJECTED":
        return False
    fresh = bool(
        installation.evidence_id and installation.evidence_id not in prior_match.get("evidence_ids", [])
        and prior_match.get("observed_version") != installation.version
    )
    if not fresh:
        return False
    proof = context.fresh_proofs.get(installation.evidence_id)
    if proof is None or proof.type not in ("SOFTWARE_INVENTORY", "SBOM"):
        return False
    record = proof.content.get("record", proof.content)
    if (
        not isinstance(record, dict) or record.get("version") != installation.version
        or (prior_match.get("updated_at") and _date(proof.created_at) < _date(prior_match["updated_at"]))
    ):
        return False
    if proof.type == "SOFTWARE_INVENTORY" and not (
        record.get("asset_id") == installation.asset_id
        or record.get("hostname") == context.assets[installation.asset_id].hostname
    ):
        return False
    observed_product = record.get("product") or record.get("original_name") or record.get("name")
    if (
        not isinstance(observed_product, str)
        or normalize_product(observed_product)[0] != normalize_product(
            context.software[installation.software_id].canonical_name
        )[0]
    ):
        return False
    if proof.type == "SBOM" and context.sbom_proof_installations.get(proof.id) != installation.id:
        return False
    if risk.status == "VERIFIED" and result["affected"] is None and installation.version != risk.verified_version:
        before = serialize(risk)
        risk.status = "OPEN"
        reason = "A newly observed version has uncertain applicability; prior verification does not cover it"
        audit(context.db, "VERIFICATION_REQUIRES_REVIEW", risk, before, reason=reason,
              asset_id=risk.asset_id, risk_id=risk.id)
        for task in context.remediations[risk.id]:
            if task.status in ("VERIFIED", "REMEDIATED"):
                before_task = serialize(task)
                task.status, task.completed_at = "OPEN", None
                audit(context.db, "REMEDIATION_REOPENED", task, before_task, reason=reason, risk_id=risk.id)
        return False
    if (
        risk.status == "VERIFIED" and result["affected"] is True
        and (installation.version != risk.verified_version or prior_match.get("affected") is False)
    ):
        before = serialize(risk)
        risk.status = "OPEN"
        audit(
            context.db, "RISK_REINTRODUCED", risk, before,
            reason="Fresh inventory evidence shows a different, affected version after verification",
            asset_id=risk.asset_id, risk_id=risk.id,
        )
        for task in context.remediations[risk.id]:
            if task.status in ("VERIFIED", "REMEDIATED"):
                before_task = serialize(task)
                task.status, task.completed_at = "OPEN", None
                audit(context.db, "REMEDIATION_REOPENED", task, before_task, reason="Affected version reintroduced", risk_id=risk.id)
        return False
    fixed = _fixed_version_support(installation.version, result["evaluations"])
    if (
        risk.status in ACTIVE_STATUSES and prior_match.get("affected") is True
        and result["affected"] is False and fixed
    ):
        before = serialize(risk)
        risk.status, risk.verified_version = "VERIFIED", installation.version
        verification = m.RemediationVerification(
            risk_id=risk.id, method="VERSION_EVIDENCE", actor="RiskScope correlation",
            reason=f"Fresh version observation is outside all applicable ranges and meets supported fixed version {fixed}",
            evidence_id=installation.evidence_id,
            before={"version": prior_match["observed_version"], "affected": True, "evidence_ids": prior_match["evidence_ids"]},
            after={"version": installation.version, "affected": False, "fixed_version": fixed,
                   "evidence_ids": result["evidence_ids"], "method": result["method"]},
        )
        context.db.add(verification)
        audit(
            context.db, "REMEDIATION_VERIFIED", verification, reason=verification.reason,
            asset_id=risk.asset_id, risk_id=risk.id,
        )
        audit(context.db, "RISK_VERIFIED", risk, before, reason=verification.reason, asset_id=risk.asset_id, risk_id=risk.id)
        for task in context.remediations[risk.id]:
            if task.status in ACTIVE_STATUSES:
                before_task = serialize(task)
                task.status, task.completed_at = "VERIFIED", m.now()
                audit(context.db, "REMEDIATION_VERIFIED", task, before_task, reason=verification.reason, risk_id=risk.id)
        return True
    return False


def _factor(name, value, contribution, reason, *evidence_ids):
    if value is None:
        value = "UNKNOWN"
    elif isinstance(value, bool):
        value = "YES" if value else "NO"
    return {
        "name": name, "value": str(value), "contribution": round(contribution, 4),
        "reasoning": reason, "evidence_ids": _ids(*evidence_ids),
    }


def _assessment_before(risk):
    return {
        field: getattr(risk, field)
        for field in (
            "id", "asset_id", "vulnerability_id", "score", "severity", "priority", "confidence",
            "status", "exposure", "exploitability", "rules_version", "evidence_ids", "verified_version",
        )
    }


def _bulk_audit(db, events):
    if not events:
        return
    audit_rows, timeline_rows = [], []
    for action, record, before, reason, asset_id, risk_id in events:
        audit_rows.append({
            "action": action, "object_type": record.__tablename__, "object_id": record.id,
            "actor": "System", "reason": reason, "before": before, "after": serialize(record),
        })
        timeline_rows.append({
            "action": action, "object_type": record.__tablename__, "object_id": record.id,
            "actor": "System", "summary": reason, "asset_id": asset_id, "risk_id": risk_id,
            "evidence_ids": getattr(record, "evidence_ids", []),
        })
    db.execute(insert(m.AuditEvent), audit_rows)
    db.execute(insert(m.TimelineEvent), timeline_rows)


def _flush_assessments(context):
    batch = context.assessment_batch
    if not batch:
        return
    db = context.db
    db.flush()
    db.execute(
        delete(m.RiskFactor).where(m.RiskFactor.risk_id.in_([item[0].id for item in batch])),
        execution_options={"synchronize_session": "fetch"},
    )
    db.execute(insert(m.RiskFactor), [
        {"risk_id": risk.id, **factor}
        for risk, automated, _, _ in batch for factor in automated["factors"]
    ])
    db.execute(insert(m.AssessmentHistory), [
        {"risk_id": risk.id, "snapshot": {"automated": automated, "effective": effective, "assessed_at": m.now()}}
        for risk, automated, _, effective in batch
    ])
    _bulk_audit(db, [
        (
            "RISK_ASSESSED", risk, before,
            f"Deterministic evidence assessment using rules {automated['rules_version']}",
            risk.asset_id, risk.id,
        )
        for risk, automated, before, _ in batch
    ])
    for risk, _, _, _ in batch:
        db.expire(risk, ["factors", "reasoning", "uncertainties"])
    batch.clear()


def _assess(context, risk, match, evaluations, settings, paths):
    asset = context.assets[risk.asset_id]
    vulnerability = context.vulnerabilities[risk.vulnerability_id]
    installation = context.installations[match.installation_id]
    weights = settings["weights"]
    exposed, exposed_evidence = context.asset_exposure(asset)
    business = context.business.get(asset.id)
    classification = business.data_classification if business else "UNKNOWN"
    criticality_multiplier = max(
        CRITICALITY_SCALE.get(asset.criticality, 0),
        {"RESTRICTED": 0.75, "CONFIDENTIAL": 0.5}.get(classification, 0),
    )
    observation = context.exploitability.get((asset.id, vulnerability.id))
    privileges = (
        observation.privileges if observation and observation.privileges != "UNKNOWN" else vulnerability.privileges_required
    )
    complexity = (
        observation.complexity if observation and observation.complexity != "UNKNOWN" else vulnerability.attack_complexity
    )
    applicable_services = [
        service for service in context.services[installation.id]
        if service.asset_id == asset.id and service.status == "RUNNING"
    ]
    service = max(
        applicable_services, key=lambda item: EXPOSURE_SCALE.get(context.service_exposure(item)[0], 0), default=None
    )
    service_exposure, service_evidence = context.service_exposure(service) if service else ("UNKNOWN", None)
    service_multiplier = {
        "INTERNET_FACING": 1, "EXTERNALLY_REACHABLE": 0.75, "INTERNAL_ONLY": 0.25, "RESTRICTED": 0.1,
    }.get(service_exposure, 0)
    fixed_versions = sorted({fixed for item in evaluations for fixed in item[0].fixed_versions})
    factors = [
        _factor("cvss", vulnerability.cvss_score, (vulnerability.cvss_score or 0) * weights["cvss"],
                "Published base severity; not an environmental priority on its own", vulnerability.evidence_id),
        _factor("known_exploitation", vulnerability.known_exploited,
                weights["known_exploitation"] if vulnerability.known_exploited is True else 0,
                "Global vulnerability intelligence; identical on every affected asset", vulnerability.evidence_id),
        _factor("exploit_available", vulnerability.exploit_available,
                weights["exploit_available"] if vulnerability.exploit_available is True else 0,
                "Public exploit availability is separate from known exploitation", vulnerability.evidence_id),
        _factor("exposure", exposed, weights["exposure"] * EXPOSURE_SCALE.get(exposed, 0),
                "Latest explicit asset-level observation, otherwise inventory; never inferred from IP", exposed_evidence),
        _factor("criticality", f"{asset.criticality}; data classification {classification}",
                weights["criticality"] * criticality_multiplier,
                "Maximum of asset criticality and documented business data-classification multiplier",
                asset.evidence_id, business.evidence_id if business else None),
        _factor("production", asset.environment,
                weights["production"] * {"PRODUCTION": 1, "STAGING": 1 / 3}.get(asset.environment, 0),
                "Production business context; staging contributes one third", asset.evidence_id),
        _factor("service", f"{service.name}: {service_exposure}" if service else "UNKNOWN",
                weights["service"] * service_multiplier,
                "Only a running service explicitly linked to this affected installation contributes",
                service_evidence, service.evidence_id if service else None, installation.evidence_id),
        _factor("privileges", privileges, weights["privileges"] * {"NONE": 1, "LOW": 0.5}.get(privileges, 0),
                "Documented low privilege requirements increase ease of exploitation",
                vulnerability.evidence_id, observation.evidence_id if observation else None),
        _factor("complexity", complexity, weights["complexity"] if complexity == "LOW" else 0,
                "Documented low attack complexity; unknown never means low",
                vulnerability.evidence_id, observation.evidence_id if observation else None),
        _factor("path", len(paths), weights["path"] if paths else 0,
                "Potential evidence-supported route to a critical asset; not proof of exploitation",
                [eid for path in paths for eid in path.evidence_ids]),
        _factor("remediation_available", ", ".join(fixed_versions) or "UNKNOWN", 0,
                vulnerability.recommendation or "No remediation recommendation supplied by the vulnerability source",
                vulnerability.evidence_id),
        _factor("reachability", observation.reachability if observation else "UNKNOWN", 0,
                "Asset-specific reachability is separate from global exploitation intelligence",
                observation.evidence_id if observation else None),
        _factor("exploit_maturity", vulnerability.exploit_maturity, 0,
                "Reported exploit maturity; no inferred exploit capability", vulnerability.evidence_id),
        _factor("user_interaction", vulnerability.user_interaction, 0,
                "Reported user interaction requirement", vulnerability.evidence_id),
    ]
    uncertainties = [f"{factor['name']}: unknown observation; contributes no unsupported points"
                     for factor in factors if factor["value"] == "UNKNOWN"]
    if asset.criticality == "UNKNOWN":
        uncertainties.append("Asset criticality is unknown; this is not evidence of low business importance")
    if classification == "UNKNOWN":
        uncertainties.append("Business data classification is unknown")
    if match.affected is None:
        uncertainties.append("Version or product identity is uncertain; analyst review is required")
    if match.affected is False and risk.status != "VERIFIED":
        uncertainties.append("Current version is outside the evaluated ranges; remediation verification is still required")
    if match.analyst_state:
        uncertainties.append(f"Analyst match decision: {match.analyst_state}; {match.analyst_reason}")
    if vulnerability.synthetic:
        uncertainties.append("SYNTHETIC DATA: this is a fictional vulnerability, not real threat intelligence")
    if match.affected is False and risk.status == "VERIFIED":
        for factor in factors:
            factor["contribution"] = 0
        factors.append(_factor(
            "applicability", "VERIFIED_NOT_AFFECTED", 0,
            "Verified unaffected version: contextual contributions are suppressed. Prior scores remain in assessment history.",
            match.evidence_ids,
        ))
    score = round(min(100, max(0, sum(factor["contribution"] for factor in factors))), 2)
    exploitability = (
        "KNOWN_EXPLOITED" if vulnerability.known_exploited is True else
        "EXPLOIT_AVAILABLE" if vulnerability.exploit_available is True else
        "NO_KNOWN_EXPLOIT" if vulnerability.known_exploited is False and vulnerability.exploit_available is False
        else "UNKNOWN"
    )
    return {
        "score": score, "priority": priority(score), "severity": _severity(vulnerability.cvss_score),
        "confidence": match.confidence, "exposure": exposed, "exploitability": exploitability,
        "factors": factors,
        "reasoning": [
            f"{installation.original_name} {installation.version or '(version unknown)'} is observed on {asset.hostname}.",
            f"Automated applicability: {match.state}; method {match.method}; rule {match.rule}.",
            *[f"{factor['name']}: {factor['value']} (+{factor['contribution']:g}). {factor['reasoning']}" for factor in factors],
            f"Priority {priority(score)} from {score:g}/100; clamped sum, not a probability of exploitation.",
        ],
        "uncertainties": uncertainties,
        "evidence_ids": _ids(asset.evidence_id, vulnerability.evidence_id, match.evidence_ids,
                             [eid for factor in factors for eid in factor["evidence_ids"]]),
        "rules_version": _rules_version(settings),
        "recommendation": vulnerability.recommendation or (
            f"Source-listed fixed versions: {', '.join(fixed_versions)}. Validate applicability with the supplier."
            if fixed_versions else "No fixed version or recommendation was supplied; obtain vendor guidance."
        ),
    }


def _apply_assessment(context, risk, automated, *, before=None):
    before = before if before is not None else _assessment_before(risk)
    for key, value in automated.items():
        setattr(risk, key, value)
    risk.updated_at = m.now()
    effective = serialize(risk)
    for key, value in risk.analyst_override.items():
        if key in ("severity", "priority", "confidence", "exposure", "exploitability"):
            effective[key] = value
    context.assessment_batch.append((risk, automated, before, effective))
    if len(context.assessment_batch) >= WRITE_BATCH_SIZE:
        _flush_assessments(context)


def _configuration_findings(context, settings):
    findings = []
    for asset in context.assets.values():
        if asset.status != "ACTIVE":
            continue
        if settings["configuration_rules"]:
            if not asset.owner and asset.evidence_id:
                findings.append((asset, "missing-owner", "ASSET_RISK", "Asset owner is missing", 15,
                                 [asset.evidence_id], "Assign an accountable owner to the asset.", None))
            if asset.criticality == "UNKNOWN" and asset.evidence_id:
                findings.append((asset, "unknown-criticality", "ASSET_RISK", "Asset criticality is unknown", 20,
                                 [asset.evidence_id], "Classify business criticality with the asset owner.", None))
            for service in context.asset_services[asset.id]:
                if service.status != "RUNNING" or not service.evidence_id:
                    continue
                exposure, exposure_id = context.service_exposure(service)
                admin_ports = {
                    "ssh": (22,), "openssh": (22,), "telnet": (23,), "rdp": (3389,),
                    "remote desktop": (3389,), "vnc": (5900,), "winrm": (5985, 5986),
                }
                if service.port in admin_ports.get(service.name.strip().casefold(), ()) and exposure in (
                    "INTERNET_FACING", "EXTERNALLY_REACHABLE"
                ) and exposure_id:
                    findings.append((
                        asset, f"internet-admin:{service.id}", "EXPOSURE", "Externally exposed administration service",
                        35, _ids(service.evidence_id, exposure_id),
                        "Restrict administrative access to approved management networks and require strong authentication.",
                        (exposure, exposure_id),
                    ))
                if {"telnet": 23, "ftp": 21, "http": 80}.get(service.name.strip().casefold()) == service.port:
                    findings.append((
                        asset, f"unencrypted-service:{service.id}", "CONFIGURATION", "Potential unencrypted service",
                        25, [service.evidence_id],
                        "Verify the observed protocol and enforce encrypted transport; a port alone is not proof of plaintext.",
                        (exposure, exposure_id),
                    ))
    if settings["lifecycle_rules"]:
        for installation in context.installations.values():
            software = context.software[installation.software_id]
            asset = context.assets[installation.asset_id]
            if asset.status == "ACTIVE" and software.lifecycle == "END_OF_LIFE" and software.evidence_id:
                findings.append((
                    asset, f"end-of-life:{installation.id}", "SOFTWARE_LIFECYCLE",
                    f"Unsupported software: {software.canonical_name}", 25, [software.evidence_id],
                    "Replace or upgrade unsupported software using supplier lifecycle guidance; no fixed version is inferred.",
                    None,
                ))
    return findings


def _non_cve(context, settings):
    automatic = {(risk.asset_id, risk.rule_key): risk for risk in context.risks if risk.rule_key.startswith("auto:")}
    seen, created = set(), 0
    for asset, key, category, title, base_score, evidence_ids, recommendation, service_exposure in _configuration_findings(context, settings):
        rule_key = f"auto:{key}"
        identity = (asset.id, rule_key)
        seen.add(identity)
        risk = automatic.get(identity)
        if risk is None:
            risk = m.RiskAssessment(
                asset_id=asset.id, category=category, rule_key=rule_key,
                title=title, owner=asset.owner, evidence_ids=evidence_ids,
            )
            context.db.add(risk)
            context.db.flush()
            context.risks.append(risk)
            created += 1
            audit(context.db, "RISK_CREATED", risk, reason="Evidence-backed non-CVE detection", asset_id=asset.id, risk_id=risk.id)
        exposed, exposure_id = service_exposure or context.asset_exposure(asset)
        factors = [
            _factor("rule", key, base_score, title, evidence_ids),
            _factor("criticality", asset.criticality,
                    settings["weights"]["criticality"] * CRITICALITY_SCALE.get(asset.criticality, 0),
                    "Observed asset business criticality", asset.evidence_id),
            _factor("production", asset.environment,
                    settings["weights"]["production"] if asset.environment == "PRODUCTION" else 0,
                    "Observed production environment", asset.evidence_id),
        ]
        if category in ("EXPOSURE", "CONFIGURATION"):
            factors.append(_factor("exposure", exposed, settings["weights"]["exposure"] * EXPOSURE_SCALE.get(exposed, 0),
                                   "Explicit exposure of the observed service" if service_exposure else "Explicit asset exposure",
                                   exposure_id))
        score = round(min(100, sum(factor["contribution"] for factor in factors)), 2)
        if category == "SOFTWARE_LIFECYCLE":
            score = min(score, 59)
        automated = {
            "score": score, "priority": priority(score), "severity": priority(base_score),
            "confidence": "MEDIUM", "exposure": exposed, "exploitability": "UNKNOWN",
            "factors": factors,
            "reasoning": [f"{factor['name']}: {factor['value']} (+{factor['contribution']:g}). {factor['reasoning']}"
                          for factor in factors],
            "uncertainties": ["A deterministic configuration or lifecycle finding is not proof of exploitability."],
            "evidence_ids": _ids(evidence_ids, [eid for factor in factors for eid in factor["evidence_ids"]]),
            "rules_version": _rules_version(settings), "recommendation": recommendation,
        }
        _apply_assessment(context, risk, automated)
    for identity, risk in automatic.items():
        if identity not in seen and risk.status in ACTIVE_STATUSES:
            before = serialize(risk)
            risk.status = "DEFERRED"
            risk.uncertainties = [
                *risk.uncertainties, "Rule is disabled or its condition is no longer observed; this is not remediation verification."
            ]
            audit(context.db, "AUTOMATED_FINDING_DEFERRED", risk, before,
                  reason="Rule disabled or condition no longer observed", asset_id=risk.asset_id, risk_id=risk.id)
    return created


def _manual_findings(context, settings):
    for risk in context.risks:
        if risk.rule_key != "manual" or risk.vulnerability_id is not None:
            continue
        asset = context.assets.get(risk.asset_id)
        if asset is None:
            continue
        weights = settings["weights"]
        exposed, exposure_id = context.asset_exposure(asset)
        business = context.business.get(asset.id)
        classification = business.data_classification if business else "UNKNOWN"
        criticality_multiplier = max(
            CRITICALITY_SCALE.get(asset.criticality, 0),
            {"RESTRICTED": 0.75, "CONFIDENTIAL": 0.5}.get(classification, 0),
        )
        source_evidence = next(
            (factor["evidence_ids"] for factor in risk.factors if factor["name"] == "analyst_severity"),
            risk.evidence_ids,
        )
        factors = [
            _factor(
                "analyst_severity", risk.severity, MANUAL_SEVERITY_POINTS.get(risk.severity, 0),
                "Analyst-supplied non-CVE severity, not a CVSS score or exploitability claim",
                source_evidence,
            ),
            _factor(
                "exposure", exposed, weights["exposure"] * EXPOSURE_SCALE.get(exposed, 0),
                "Latest explicit asset exposure observation, otherwise asset inventory", exposure_id,
            ),
            _factor(
                "criticality", f"{asset.criticality}; data classification {classification}",
                weights["criticality"] * criticality_multiplier,
                "Maximum of observed asset criticality and business data-classification multiplier",
                asset.evidence_id, business.evidence_id if business else None,
            ),
            _factor(
                "production", asset.environment,
                weights["production"] * {"PRODUCTION": 1, "STAGING": 1 / 3}.get(asset.environment, 0),
                "Production business context; staging contributes one third", asset.evidence_id,
            ),
        ]
        score = round(min(100, max(0, sum(factor["contribution"] for factor in factors))), 2)
        uncertainties = ["Analyst-created non-CVE finding; exploitability has not been automatically established."]
        for label, value in (
            ("Asset exposure", exposed), ("Asset criticality", asset.criticality),
            ("Business data classification", classification), ("Environment", asset.environment),
            ("Finding confidence", risk.confidence),
        ):
            if value == "UNKNOWN":
                uncertainties.append(f"{label} is unknown; no unsupported contextual points are added.")
        automated = {
            "score": score, "priority": priority(score), "severity": risk.severity,
            "confidence": risk.confidence, "exposure": exposed, "exploitability": "UNKNOWN",
            "factors": factors,
            "reasoning": [
                risk.analyst_reason or "Analyst-created non-CVE finding supported by the linked evidence.",
                *[
                    f"{factor['name']}: {factor['value']} (+{factor['contribution']:g}). {factor['reasoning']}"
                    for factor in factors
                ],
                f"Priority {priority(score)} from {score:g}/100; explicit severity plus observed asset context.",
            ],
            "uncertainties": uncertainties,
            "evidence_ids": _ids([eid for factor in factors for eid in factor["evidence_ids"]]),
            "rules_version": _rules_version(settings), "recommendation": risk.recommendation,
        }
        _apply_assessment(context, risk, automated)


def discover_paths(db: Session) -> dict:
    """Rebuild bounded *potential* paths from current observations, not inferred reachability."""
    settings = get_settings(db)
    db.flush()
    db.execute(delete(m.AttackPath), execution_options={"synchronize_session": "fetch"})
    assets = {asset.id: asset for asset in db.scalars(select(m.Asset).where(m.Asset.status == "ACTIVE"))}
    observations = _latest(
        db.scalars(select(m.ExposureObservation).where(m.ExposureObservation.service_id.is_(None))),
        lambda item: item.asset_id,
    )
    evidence_ids = set(db.scalars(select(m.Evidence.id)))
    exploitability = _latest(
        db.scalars(select(m.ExploitabilityObservation)), lambda item: (item.asset_id, item.vulnerability_id)
    )
    matches = {item.id: item for item in db.scalars(select(m.VulnerabilityMatch))}
    relationships = list(db.scalars(
        select(m.AssetRelationship)
        .where(m.AssetRelationship.type.in_(PATH_RELATIONSHIPS), m.AssetRelationship.evidence_id.is_not(None))
        .order_by(m.AssetRelationship.id).limit(settings["max_graph_edges"] + 1)
    ))
    reasons = []
    if len(relationships) > settings["max_graph_edges"]:
        reasons.append("graph-edge-limit")
        relationships = relationships[:settings["max_graph_edges"]]
    graph = defaultdict(list)
    for relationship in relationships:
        if (
            relationship.evidence_id in evidence_ids and relationship.source_asset_id in assets
            and relationship.target_asset_id in assets
        ):
            graph[relationship.source_asset_id].append(relationship)
    risks = list(db.scalars(
        select(m.RiskAssessment).where(
            m.RiskAssessment.status.in_(ACTIVE_STATUSES), m.RiskAssessment.vulnerability_id.is_not(None)
        ).options(
            defer(m.RiskAssessment.factors), defer(m.RiskAssessment.reasoning), defer(m.RiskAssessment.uncertainties),
        ).order_by(m.RiskAssessment.id)
    ))
    count, expansions = 0, 0
    expansion_limit = min(20_000, settings["max_graph_edges"] * settings["max_path_depth"] * 2)
    halted = False
    for risk in risks:
        asset = assets.get(risk.asset_id)
        match = matches.get(risk.match_id)
        if asset is None or match is None or (match.analyst_state or match.state) not in ("CONFIRMED", "POTENTIAL"):
            continue
        if match.affected is False:
            continue
        observed = observations.get(asset.id)
        exposure = observed.exposure if observed else asset.exposure
        exposure_evidence = observed.evidence_id if observed else asset.evidence_id
        override_exposure = risk.analyst_override.get("exposure")
        if override_exposure:
            exposure = override_exposure
        exploit = exploitability.get((asset.id, risk.vulnerability_id))
        if exposure != "INTERNET_FACING" or exposure_evidence not in evidence_ids or (exploit and exploit.reachability == "BLOCKED"):
            continue
        queue = deque([(asset.id, [asset.id], [], _ids(exposure_evidence, match.evidence_ids))])
        while queue:
            current, visited, relationship_ids, path_evidence = queue.popleft()
            if len(relationship_ids) >= settings["max_path_depth"]:
                if graph[current]:
                    reasons.append("path-depth-limit")
                continue
            for edge in graph[current]:
                if expansions >= expansion_limit:
                    reasons.append("expansion-limit")
                    halted = True
                    break
                expansions += 1
                target = edge.target_asset_id
                if target in visited:
                    continue
                next_assets = [*visited, target]
                next_edges = [*relationship_ids, edge.id]
                next_evidence = _ids(path_evidence, edge.evidence_id)
                if assets[target].criticality == "CRITICAL":
                    db.add(m.AttackPath(
                        risk_id=risk.id, source_asset_id=asset.id, target_asset_id=target,
                        asset_ids=next_assets, relationship_ids=next_edges,
                        evidence_ids=_ids(next_evidence, assets[target].evidence_id),
                        reasoning=(
                            "Potential attack path: Internet → " + " → ".join(assets[item].hostname for item in next_assets)
                            + ". Explicit directed relationships connect an internet-reachable affected asset to a critical asset. "
                            "This is a prioritization hypothesis, not confirmed exploitation or proof of lateral movement."
                        ),
                        confidence="POTENTIAL",
                    ))
                    count += 1
                    if count >= settings["max_paths"]:
                        reasons.append("path-count-limit")
                        halted = True
                        break
                queue.append((target, next_assets, next_edges, next_evidence))
            if halted:
                break
        if halted:
            break
    db.flush()
    return {
        "paths": count, "truncated": bool(reasons), "truncation_reasons": sorted(set(reasons)),
        "expansions": expansions, "expansion_limit": expansion_limit, "edges_considered": len(relationships),
        "max_path_depth": settings["max_path_depth"],
    }


def _correlate_candidates(context, candidates):
    db = context.db
    previous, new_matches = {}, []
    for installation, vulnerability_id, result in candidates:
        key = (installation.id, vulnerability_id)
        match = context.matches.get(key)
        previous[key] = serialize(match) if match else {}
        values = {field: value for field, value in result.items() if field != "evaluations"}
        values["method"] = values["method"][:100]
        values["evidence_ids"] = _ids(values["evidence_ids"], context.vulnerabilities[vulnerability_id].evidence_id)
        if match is None:
            new_matches.append({"installation_id": installation.id, "vulnerability_id": vulnerability_id, **values})
        else:
            for field, value in values.items():
                setattr(match, field, value)
    if new_matches:
        for match in db.scalars(insert(m.VulnerabilityMatch).returning(m.VulnerabilityMatch), new_matches):
            context.matches[(match.installation_id, match.vulnerability_id)] = match
    new_risks = []
    for installation, vulnerability_id, result in candidates:
        match = context.matches[(installation.id, vulnerability_id)]
        if match.id not in context.risk_by_match and result["affected"] is not False:
            asset = context.assets[installation.asset_id]
            new_risks.append({
                "asset_id": asset.id, "vulnerability_id": vulnerability_id, "match_id": match.id,
                "title": f"{context.vulnerabilities[vulnerability_id].identifier} on {asset.hostname}",
                "owner": asset.owner, "evidence_ids": match.evidence_ids,
            })
    created_risks = []
    if new_risks:
        created_risks = list(db.scalars(insert(m.RiskAssessment).returning(m.RiskAssessment), new_risks))
        context.risks.extend(created_risks)
        context.risk_by_match.update({risk.match_id: risk for risk in created_risks})
    db.flush()
    pending, events, matched, verified = [], [], 0, 0
    for installation, vulnerability_id, result in candidates:
        key = (installation.id, vulnerability_id)
        match, prior_match = context.matches[key], previous[key]
        if not prior_match or any(
            prior_match.get(field) != getattr(match, field)
            for field in ("state", "observed_version", "rule", "confidence", "affected", "evidence_ids")
        ):
            events.append((
                "VULNERABILITY_MATCHED", match, prior_match,
                f"Conservative applicability assessment: {match.state}", installation.asset_id, None,
            ))
        if result["affected"] is not False and match.analyst_state != "REJECTED":
            matched += 1
        risk = context.risk_by_match.get(match.id)
        if risk is None:
            continue
        if _verify_changed_version(context, risk, match, prior_match, installation, result):
            verified += 1
        if match.analyst_state == "REJECTED" and risk.status not in ("VERIFIED", "RISK_ACCEPTED", "DEFERRED"):
            risk.status = "FALSE_POSITIVE"
        pending.append((risk, match, result["evaluations"]))
    events.extend(
        ("RISK_CREATED", risk, {}, "Affected or uncertain software applicability", risk.asset_id, risk.id)
        for risk in created_risks
    )
    _bulk_audit(db, events)
    return pending, len(created_risks), matched, verified


def correlate(db: Session) -> dict:
    settings = get_settings(db)
    expired = expire_acceptances(db)
    context = Context(db)
    pending, candidates, created, matched, verified = [], [], 0, 0, 0
    evaluated_keys = set()
    evaluated_ranges = 0
    maximum = db.info.get("max_correlations")
    if maximum is not None and sum(map(len, (context.assets, context.installations, context.vulnerabilities))) > maximum:
        from fastapi import HTTPException
        raise HTTPException(413, f"Temporary workspaces allow {maximum} total asset, installation and advisory records. Use local mode for larger inventories.")
    for installation in context.installations.values():
        asset = context.assets.get(installation.asset_id)
        software = context.software.get(installation.software_id)
        if asset is None or software is None or asset.status != "ACTIVE":
            continue
        candidate_groups = defaultdict(list)
        for rule in context.ranges[normalize_product(software.canonical_name)[0]]:
            if rule.vulnerability_id in context.vulnerabilities:
                candidate_groups[rule.vulnerability_id].append(rule)
        for vulnerability_id, ranges in candidate_groups.items():
            evaluated_ranges += len(ranges)
            if maximum is not None and evaluated_ranges > maximum:
                from fastapi import HTTPException
                raise HTTPException(413, f"Temporary workspaces allow {maximum} version-range checks per run. Use local mode for larger datasets.")
            result = _range_result(installation, software, ranges)
            if result is None:
                continue
            evaluated_keys.add((installation.id, vulnerability_id))
            if maximum is not None and len(evaluated_keys) > maximum:
                from fastapi import HTTPException
                raise HTTPException(
                    413, f"Temporary workspaces support {maximum} applicability checks per run. "
                    "Use local mode for larger datasets; this calculation was rolled back."
                )
            candidates.append((installation, vulnerability_id, result))
            if len(candidates) >= WRITE_BATCH_SIZE:
                batch_pending, batch_created, batch_matched, batch_verified = _correlate_candidates(context, candidates)
                pending.extend(batch_pending)
                created, matched, verified = created + batch_created, matched + batch_matched, verified + batch_verified
                candidates.clear()
    if candidates:
        batch_pending, batch_created, batch_matched, batch_verified = _correlate_candidates(context, candidates)
        pending.extend(batch_pending)
        created, matched, verified = created + batch_created, matched + batch_matched, verified + batch_verified
    for key, match in context.matches.items():
        if key not in evaluated_keys and match.affected is not False:
            before = serialize(match)
            match.state, match.affected, match.confidence = "NEEDS_REVIEW", None, "UNKNOWN"
            match.method = "no-current-applicability-rule"
            audit(db, "MATCH_REQUIRES_REVIEW", match, before,
                  reason="No current compatible product/range evidence; absence is not a remediation verification")
            risk = context.risk_by_match.get(match.id)
            if risk and match.installation_id in context.installations:
                pending.append((risk, match, []))
    created += _non_cve(context, settings)
    _manual_findings(context, settings)
    _flush_assessments(context)
    path_result = discover_paths(db)
    paths = defaultdict(list)
    for path in db.scalars(select(m.AttackPath)):
        paths[path.risk_id].append(path)
    for risk, match, evaluations in pending:
        automated = _assess(context, risk, match, evaluations, settings, paths[risk.id])
        _apply_assessment(context, risk, automated)
    _flush_assessments(context)
    db.flush()
    snapshot_record = snapshot(db, new_risks=created)
    return {
        "matched": matched, "risks": len(context.risks), "new_risks": created, "verified": verified,
        "expired_acceptances": expired, "snapshot_id": snapshot_record.id,
        "rules_version": _rules_version(settings), **path_result,
    }


def snapshot(db: Session, new_risks: int = 0) -> m.RiskSnapshot:
    """Persist current observed counts; no dates or historical values are fabricated."""
    db.flush()
    risks = list(db.execute(select(
        m.RiskAssessment.id, m.RiskAssessment.status, m.RiskAssessment.priority,
        m.RiskAssessment.analyst_override, m.RiskAssessment.due_date, m.RiskAssessment.created_at,
    )))
    active = [risk for risk in risks if risk.status in ACTIVE_STATUSES]
    counts = {
        name: sum(risk.analyst_override.get("priority", risk.priority) == name for risk in active)
        for name in PRIORITIES
    }
    overdue = set(db.scalars(overdue_risk_query()))
    previous = db.scalar(select(m.RiskSnapshot).order_by(m.RiskSnapshot.id.desc()).limit(1))
    observed_new = sum(previous is None or risk.created_at > previous.created_at for risk in risks)
    item = m.RiskSnapshot(
        counts=counts, open_risk=len(active),
        remediated=sum(risk.status in ("REMEDIATED", "VERIFIED") for risk in risks),
        new_risks=observed_new, overdue=len(overdue),
    )
    db.add(item)
    db.flush()
    return item
