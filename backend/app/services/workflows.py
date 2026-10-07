from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select

from app import models as m
from app.schemas import AcceptInput, Decision, VerifyInput, serialize
from app.services.common import audit


def require(db, model, identifier):
    record = db.get(model, identifier)
    if record is None:
        raise HTTPException(404, f"{model.__name__} {identifier} not found")
    return record


def set_remediation_status(db, risk, status):
    for task in db.scalars(select(m.Remediation).where(m.Remediation.risk_id == risk.id)):
        before = serialize(task)
        task.status = status
        if status == "VERIFIED":
            task.completed_at = m.now()
        elif status == "OPEN":
            task.completed_at = None
        audit(db, "Remediation status synchronized", task, before, risk_id=risk.id, asset_id=risk.asset_id)


def review(db, risk, decision: Decision):
    before = serialize(risk)
    match = db.get(m.VulnerabilityMatch, risk.match_id) if risk.match_id else None
    if decision.clear_overrides:
        risk.analyst_override = {}
    updates = decision.model_dump(exclude_none=True)
    override = dict(risk.analyst_override)
    for key in ("priority", "severity", "confidence", "exposure", "exploitability"):
        if key in updates:
            override[key] = updates[key]
    if override:
        override.update(actor=decision.actor, updated_at=m.now())
    risk.analyst_override = override
    risk.analyst_reason = decision.reason
    if decision.match_state:
        if not match:
            raise HTTPException(422, "Only vulnerability-backed risks have a match to review")
        match_before = serialize(match)
        match.analyst_state = decision.match_state
        match.analyst_reason = decision.reason
        audit(db, "Match reviewed", match, match_before, decision.reason, decision.actor, risk.asset_id, risk.id)
        if decision.match_state == "REJECTED":
            risk.status = "FALSE_POSITIVE"
        elif risk.status == "FALSE_POSITIVE":
            risk.status = "OPEN"
    if decision.status:
        risk.status = decision.status
        if match:
            if decision.status == "FALSE_POSITIVE":
                match.analyst_state = "REJECTED"
                match.analyst_reason = decision.reason
            elif decision.status == "OPEN" and match.analyst_state == "REJECTED":
                match.analyst_state = None
    if decision.status or decision.match_state:
        set_remediation_status(db, risk, risk.status)
    audit(db, "Analyst reviewed risk", risk, before, decision.reason, decision.actor, risk.asset_id, risk.id)
    return risk


def accept(db, risk, data: AcceptInput):
    expiry = data.expires_at
    if expiry.tzinfo is None:
        raise HTTPException(422, "Acceptance expiry requires an explicit timezone")
    if expiry <= datetime.now(timezone.utc):
        raise HTTPException(422, "Acceptance expiry must be in the future")
    if risk.status in ("VERIFIED", "FALSE_POSITIVE"):
        raise HTTPException(409, "Reopen the risk before accepting it")
    before = serialize(risk)
    record = m.RiskAcceptance(
        risk_id=risk.id, reason=data.reason, approver=data.approver,
        expires_at=expiry.astimezone(timezone.utc).isoformat(),
        compensating_controls=data.compensating_controls,
    )
    db.add(record)
    risk.status = "RISK_ACCEPTED"
    set_remediation_status(db, risk, risk.status)
    audit(db, "Risk accepted", risk, before, data.reason, data.approver, risk.asset_id, risk.id)
    audit(db, "Acceptance recorded", record, reason=data.reason, actor=data.approver, risk_id=risk.id)
    return record


def verify(db, risk, data: VerifyInput):
    proof = require(db, m.Evidence, data.evidence_id)
    if proof.type not in ("REMEDIATION_EVIDENCE", "SOFTWARE_INVENTORY", "ANALYST_NOTE"):
        raise HTTPException(422, "Verification requires remediation, software inventory, or analyst-note evidence")
    if risk.status in ("FALSE_POSITIVE", "VERIFIED"):
        raise HTTPException(409, "Only an unresolved risk can be verified")
    before = serialize(risk)
    risk.status = "VERIFIED"
    if risk.match_id:
        match = require(db, m.VulnerabilityMatch, risk.match_id)
        installation = require(db, m.SoftwareInstallation, match.installation_id)
        risk.verified_version = installation.version
    record = m.RemediationVerification(
        risk_id=risk.id, method="ANALYST", actor=data.actor, reason=data.reason,
        evidence_id=proof.id, before=before,
        after={"status": "VERIFIED", "version": risk.verified_version, "evidence_id": proof.id},
    )
    db.add(record)
    set_remediation_status(db, risk, "VERIFIED")
    audit(db, "Risk explicitly verified by analyst", risk, before, data.reason, data.actor, risk.asset_id, risk.id)
    audit(db, "Verification recorded", record, reason=data.reason, actor=data.actor, risk_id=risk.id)
    return record
