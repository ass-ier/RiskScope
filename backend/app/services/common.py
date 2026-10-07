from datetime import datetime, timezone

from sqlalchemy import case, func, or_, select

from app import models as m
from app.schemas import serialize

ACTIVE_STATUSES = ("OPEN", "ASSIGNED", "IN_PROGRESS", "REMEDIATED")


def overdue_risk_query():
    now = datetime.now(timezone.utc)

    def late(column):
        return case(
            (func.length(column) == 10, column < now.date().isoformat()),
            else_=func.julianday(column) < func.julianday(now.isoformat()),
        )

    overdue_tasks = select(m.Remediation.risk_id).where(
        m.Remediation.status.in_(ACTIVE_STATUSES), late(m.Remediation.due_date)
    )
    return select(m.RiskAssessment.id).where(
        m.RiskAssessment.status.in_(ACTIVE_STATUSES),
        or_(late(m.RiskAssessment.due_date), m.RiskAssessment.id.in_(overdue_tasks)),
    )


def evidence(db, kind: str, source: str, summary: str, content=None, actor="System", import_job_id=None):
    item = m.Evidence(
        type=kind, source=source, summary=summary, content=content or {},
        actor=actor, import_job_id=import_job_id,
    )
    db.add(item)
    db.flush()
    return item


def audit(db, action, record, before=None, reason="", actor="System", asset_id=None, risk_id=None):
    db.flush()
    after = serialize(record)
    db.add(m.AuditEvent(
        action=action, object_type=record.__tablename__, object_id=record.id,
        actor=actor, reason=reason or action, before=before or {}, after=after,
    ))
    db.add(m.TimelineEvent(
        action=action, object_type=record.__tablename__, object_id=record.id,
        actor=actor, summary=reason or action, asset_id=asset_id, risk_id=risk_id,
        evidence_ids=([record.evidence_id] if getattr(record, "evidence_id", None) else []),
    ))
