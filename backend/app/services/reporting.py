import csv
import io
import json
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from sqlalchemy import case, func, select

from app import models as m
from app.schemas import RESOURCES, serialize
from app.services.common import ACTIVE_STATUSES, overdue_risk_query

ACTIVE = ACTIVE_STATUSES


def priority_order():
    value = func.coalesce(
        func.json_extract(m.RiskAssessment.analyst_override, "$.priority"), m.RiskAssessment.priority
    )
    return case(
        (value == "CRITICAL", 4), (value == "HIGH", 3), (value == "MEDIUM", 2), (value == "LOW", 1),
        else_=0,
    )


def effective(risk: dict) -> dict:
    result = dict(risk)
    result["automated_priority"] = risk["priority"]
    result["effective_priority"] = risk.get("analyst_override", {}).get("priority", risk["priority"])
    return result


def enrich(db, risks):
    items = [effective(serialize(risk)) for risk in risks]
    asset_ids = {item["asset_id"] for item in items}
    vuln_ids = {item["vulnerability_id"] for item in items if item["vulnerability_id"]}
    assets = dict(db.execute(select(m.Asset.id, m.Asset.hostname).where(m.Asset.id.in_(asset_ids))).all())
    vulns = dict(db.execute(
        select(m.Vulnerability.id, m.Vulnerability.identifier).where(m.Vulnerability.id.in_(vuln_ids))
    ).all())
    for item in items:
        item["asset_name"] = assets.get(item["asset_id"], "")
        item["vulnerability_identifier"] = vulns.get(item["vulnerability_id"], "")
    return items


def dashboard(db):
    active = m.RiskAssessment.status.in_(ACTIVE)
    def all_count(model):
        return db.scalar(select(func.count()).select_from(model))
    active_count = db.scalar(select(func.count(m.RiskAssessment.id)).where(active))
    # SQLite JSON extraction retains automated values while counting analyst-effective priorities.
    priority = func.coalesce(
        func.json_extract(m.RiskAssessment.analyst_override, "$.priority"), m.RiskAssessment.priority
    )
    priorities = {key: 0 for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")}
    priorities.update(dict(db.execute(
        select(priority, func.count(m.RiskAssessment.id)).where(active).group_by(priority)
    ).all()))
    exposure = func.coalesce(
        func.json_extract(m.RiskAssessment.analyst_override, "$.exposure"), m.RiskAssessment.exposure
    )
    internet = db.scalar(select(func.count(m.RiskAssessment.id)).where(
        active, exposure.in_(("INTERNET_FACING", "EXTERNALLY_REACHABLE"))
    ))
    known = db.scalar(select(func.count(m.RiskAssessment.id)).join(
        m.Vulnerability, m.RiskAssessment.vulnerability_id == m.Vulnerability.id
    ).where(active, m.Vulnerability.known_exploited.is_(True)))
    overdue = db.scalar(select(func.count()).select_from(overdue_risk_query().subquery()))
    top = db.scalars(select(m.RiskAssessment).where(active).order_by(
        priority_order().desc(), m.RiskAssessment.score.desc(), m.RiskAssessment.id
    ).limit(10)).all()
    top_assets = db.execute(select(
        m.Asset.id, m.Asset.hostname, func.max(m.RiskAssessment.score), func.count(m.RiskAssessment.id)
    ).join(m.RiskAssessment, m.RiskAssessment.asset_id == m.Asset.id).where(active).group_by(
        m.Asset.id
    ).order_by(func.max(m.RiskAssessment.score).desc()).limit(10)).all()
    top_vulns = db.execute(select(
        m.Vulnerability.id, m.Vulnerability.identifier, func.count(m.RiskAssessment.id)
    ).join(m.RiskAssessment, m.RiskAssessment.vulnerability_id == m.Vulnerability.id).where(active).group_by(
        m.Vulnerability.id
    ).order_by(func.count(m.RiskAssessment.id).desc()).limit(10)).all()
    return {
        "totals": {
            "assets": all_count(m.Asset), "software": all_count(m.Software),
            "installations": all_count(m.SoftwareInstallation), "vulnerabilities": all_count(m.Vulnerability),
            "risks": all_count(m.RiskAssessment), "active_risks": active_count,
        },
        "priorities": priorities, "internet_exposed": internet, "known_exploited": known,
        "overdue": overdue, "top_risks": enrich(db, top),
        "top_assets": [{"asset_id": r[0], "hostname": r[1], "score": r[2], "risks": r[3]} for r in top_assets],
        "top_vulnerabilities": [
            {"vulnerability_id": r[0], "identifier": r[1], "risks": r[2]} for r in top_vulns
        ],
        "remediation": dict(db.execute(
            select(m.Remediation.status, func.count()).group_by(m.Remediation.status)
        ).all()),
        "trend": [serialize(row) for row in reversed(db.scalars(
            select(m.RiskSnapshot).order_by(m.RiskSnapshot.id.desc()).limit(90)
        ).all())],
    }


def create_report(db, title, perspective):
    # A report is an immutable, complete local snapshot, not a truncated browser page.
    data = {name: [serialize(row) for row in db.scalars(select(model).order_by(model.id))]
            for name, (model, _) in RESOURCES.items()
            if name not in ("reports",)}
    data["risk"] = enrich(db, db.scalars(select(m.RiskAssessment).order_by(m.RiskAssessment.score.desc())))
    data["dashboard"] = dashboard(db)
    from app.services.engine import get_settings
    data["settings"] = get_settings(db)
    data["generated_at"] = m.now()
    data["scope"] = "All local records, including inactive/historical risks"
    data["disclaimer"] = (
        "Contextual prioritization based on supplied evidence, not a security guarantee. "
        "Potential paths are not proof of exploitation. Records marked synthetic are fictional fixtures."
    )
    report = m.Report(title=title, perspective=perspective, snapshot=data)
    db.add(report)
    db.flush()
    return report


def csv_safe(value):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=True)
    if value is None:
        return ""
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + text
    return text


def csv_bytes(rows: list[dict], fields: list[str] | None = None) -> bytes:
    output = io.StringIO(newline="")
    columns = fields or sorted({key for row in rows for key in row})
    if not columns:
        columns = ["id"]
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: csv_safe(row.get(key)) for key in columns})
    return output.getvalue().encode("utf-8-sig")


def markdown(report):
    data = report.snapshot
    dash = data["dashboard"]
    lines = [
        f"# {report.title}", "", f"Perspective: {report.perspective}",
        f"Generated: {data['generated_at']}", "", data["disclaimer"], "",
        "## Security posture", "",
        f"Assets: {dash['totals']['assets']} | Active risks: {dash['totals']['active_risks']} | "
        f"Internet-exposed risks: {dash['internet_exposed']} | Known exploited: {dash['known_exploited']} | "
        f"Overdue remediation: {dash['overdue']}", "",
        "Priorities: " + ", ".join(f"{key}: {count}" for key, count in dash["priorities"].items()), "",
        "## Remediation status", "", json.dumps(dash["remediation"], sort_keys=True), "",
        "## Historical snapshots", "",
    ]
    lines += [f"- {r['created_at']}: open={r['open_risk']}, verified={r['remediated']}, "
              f"new={r['new_risks']}, overdue={r['overdue']}" for r in dash["trend"]]
    lines += ["", "## Business-critical assets", ""]
    lines += [f"- {r['hostname']}: {r['criticality']}, {r['environment']}, {r['exposure']}"
              for r in data["assets"] if r["criticality"] in ("CRITICAL", "HIGH")]
    lines += ["", "## Risk register (including retained history)", ""]
    for risk in data["risk"]:
        lines += [
            f"### R-{risk['id']} | {risk['asset_name']} | {risk['title']}", "",
            f"Status: {risk['status']} | Automated: {risk['priority']} ({risk['score']}) | "
            f"Effective: {risk['effective_priority']} | Category: {risk['category']}",
            f"Exposure: {risk['exposure']} | Exploitability: {risk['exploitability']}",
            f"Rules version: {risk['rules_version']}",
        ]
        lines += [f"- {reason}" for reason in risk["reasoning"]]
        lines += [f"- Uncertainty: {item}" for item in risk["uncertainties"]]
        lines += [f"Recommendation: {risk['recommendation']}", ""]
        if report.perspective == "technical":
            lines += ["Factors: " + json.dumps(risk["factors"], ensure_ascii=True),
                      "Evidence IDs: " + json.dumps(risk["evidence_ids"]),
                      "Analyst judgment: " + json.dumps(risk["analyst_override"]),
                      "Analyst reason: " + risk["analyst_reason"], ""]
    if report.perspective == "technical":
        for key in ("installations", "vulnerabilities", "affected-ranges", "matches", "evidence",
                    "attack-paths", "remediation", "verifications", "acceptances"):
            lines += [f"## {key.replace('-', ' ').title()}", ""]
            lines += [json.dumps(row, ensure_ascii=True) for row in data[key]]
            lines += [""]
    return "\n".join(lines)


def export_report(report, format: str, dataset="risk"):
    if format == "json":
        return json.dumps({
            "id": report.id, "title": report.title, "perspective": report.perspective,
            "created_at": report.created_at, **report.snapshot,
        }, ensure_ascii=True, indent=2).encode(), "application/json", "json"
    if format == "csv":
        return csv_bytes(report.snapshot[dataset]), "text/csv; charset=utf-8", f"{dataset}.csv"
    text = markdown(report)
    if format == "markdown":
        return text.encode(), "text/markdown; charset=utf-8", "md"
    buffer = io.BytesIO()
    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(buffer, pagesize=A4, title=report.title, author="RiskScope")
    elements = []
    for line in text.splitlines():
        if not line:
            elements.append(Spacer(1, 6))
        else:
            level = len(line) - len(line.lstrip("#"))
            style = styles[{1: "Title", 2: "Heading2", 3: "Heading3"}.get(level, "BodyText")]
            # Wrap long structured evidence as readable text, never interpret imported HTML.
            elements.append(Paragraph(escape(line.lstrip("# ")), style))
    def footer(canvas, doc):
        canvas.setFillColor(colors.HexColor("#526174"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(40, 24, "RiskScope | Local evidence assessment")
        canvas.drawRightString(A4[0] - 40, 24, str(doc.page))
    document.build(elements, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue(), "application/pdf", "pdf"
