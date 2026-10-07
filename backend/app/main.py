import os
import json
from contextlib import asynccontextmanager
from html import escape
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError, create_model
from sqlalchemy import String, func, or_, select, true
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import models as m
from app.db import Base, engine, get_db
from app.schemas import (
    READ_DTOS, RESOURCES, AcceptInput, Decision, Input, Page, ReportInput, ReportSummary, RiskCreate,
    SettingsInput, VerifyInput, serialize,
)
from app.services import reporting, workflows
from app.services.common import audit, evidence, overdue_risk_query


@asynccontextmanager
async def lifespan(_):
    with engine.connect() as connection:
        from sqlalchemy import inspect
        if "alembic_version" not in inspect(connection).get_table_names():
            raise RuntimeError("Database not migrated. Run: cd backend && ../.venv/bin/alembic upgrade head")
    yield


app = FastAPI(title="RiskScope", version="1.0.0", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"])
DB = Annotated[Session, Depends(get_db)]


@app.middleware("http")
async def local_request_safety(request: Request, call_next):
    if request.method in ("POST", "PATCH", "PUT", "DELETE"):
        origin = request.headers.get("origin")
        if origin and urlsplit(origin).hostname not in ("127.0.0.1", "localhost", "::1"):
            return JSONResponse({"detail": "Only loopback browser origins are allowed"}, status_code=403)
        limit = 11 * 1024 * 1024 if request.url.path.startswith("/api/imports/") else 2 * 1024 * 1024
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > limit:
                return JSONResponse({"detail": "Request exceeds the local upload limit"}, status_code=413)
        request._body = bytes(body)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'"
    )
    return response


@app.exception_handler(IntegrityError)
async def invalid_relationship(_, exc):
    return JSONResponse(
        status_code=409,
        content={"detail": "A duplicate record or invalid relationship conflicts with existing data"},
    )


def domain():
    from app.services import engine as service
    return service


def freshness(db):
    domain().expire_acceptances(db)
    db.commit()


def persist(db, recalculate=False):
    db.flush()
    if recalculate:
        domain().correlate(db)
    db.commit()


@app.get("/api/health")
def health(db: DB):
    db.execute(select(1))
    return {"status": "ok", "mode": "offline", "version": "1.0.0"}


@app.get("/api/meta")
def metadata():
    return {
        name: {"writable": schema is not None, "schema": schema.model_json_schema() if schema else None}
        for name, (_, schema) in RESOURCES.items()
    }


@app.get("/api/dashboard")
def dashboard(db: DB):
    freshness(db)
    return reporting.dashboard(db)


@app.post("/api/correlation/run")
def correlate(db: DB):
    result = domain().correlate(db)
    db.commit()
    return result


@app.post("/api/demo")
def demo(db: DB):
    from app.services.imports import demo
    try:
        result = demo(db)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return result


@app.get("/api/settings", response_model=SettingsInput)
def settings(db: DB):
    return domain().get_settings(db)


@app.put("/api/settings", response_model=SettingsInput)
def update_settings(payload: SettingsInput, db: DB):
    item = db.scalar(select(m.Setting).where(m.Setting.key == "risk"))
    before = serialize(item) if item else {}
    if item is None:
        item = m.Setting(key="risk")
        db.add(item)
    item.value = payload.model_dump()
    audit(db, "Risk settings changed", item, before, "Weights and rule limits updated", "Local analyst")
    persist(db, recalculate=True)
    return domain().get_settings(db)


@app.post("/api/imports/{kind}")
async def import_file(
    kind: Literal["assets", "software", "vulnerabilities", "sbom", "relationships"],
    db: DB, file: UploadFile = File(), asset_id: int | None = Form(default=None),
):
    from app.services.imports import MAX_UPLOAD_BYTES, import_data
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File exceeds 10 MiB limit")
    try:
        result = import_data(db, kind, data, file.filename or "import", asset_id=asset_id)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return serialize(result)


@app.get("/api/imports/{identifier}/errors.csv")
def import_errors(identifier: int, db: DB):
    workflows.require(db, m.ImportJob, identifier)
    records = db.scalars(select(m.ImportRecord).where(
        m.ImportRecord.import_job_id == identifier,
        m.ImportRecord.status.in_(("REJECTED", "ERROR")),
    ).order_by(m.ImportRecord.row_number))
    return Response(
        reporting.csv_bytes([serialize(row) for row in records],
                            ["row_number", "status", "error", "raw"]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="import-{identifier}-errors.csv"'},
    )


@app.get("/api/risk/compare")
def compare(db: DB, ids: str):
    identifiers = parse_ids(ids, maximum=5)
    if len(identifiers) < 2:
        raise HTTPException(422, "Select between two and five risks")
    freshness(db)
    records = [workflows.require(db, m.RiskAssessment, identifier) for identifier in identifiers]
    records.sort(key=lambda record: (-record.score, record.id))
    items = reporting.enrich(db, records)
    return {
        "items": items,
        "explanation": [
            f"{item['asset_name']} / {item['title']}: automated score {item['score']}, "
            f"automated priority {item['priority']}, analyst-effective priority {item['effective_priority']}. "
            + " ".join(item["reasoning"])
            for item in items
        ],
    }


@app.post("/api/risk")
def create_risk(payload: RiskCreate, db: DB):
    workflows.require(db, m.Asset, payload.asset_id)
    proof = workflows.require(db, m.Evidence, payload.evidence_id)
    risk = m.RiskAssessment(
        asset_id=payload.asset_id, category=payload.category, title=payload.title,
        severity=payload.severity, confidence=payload.confidence, evidence_ids=[proof.id],
        recommendation=payload.recommendation, rule_key="manual",
        reasoning=[payload.reason], analyst_reason=payload.reason,
    )
    db.add(risk)
    audit(db, "Non-CVE risk recorded", risk, reason=payload.reason, actor=payload.actor,
          asset_id=risk.asset_id, risk_id=risk.id)
    persist(db, recalculate=True)
    return serialize(risk)


@app.post("/api/risk/{identifier}/review")
def review_risk(identifier: int, payload: Decision, db: DB):
    risk = workflows.require(db, m.RiskAssessment, identifier)
    result = workflows.review(db, risk, payload)
    domain().discover_paths(db)
    domain().snapshot(db)
    db.commit()
    return serialize(result)


@app.post("/api/risk/{identifier}/accept")
def accept_risk(identifier: int, payload: AcceptInput, db: DB):
    risk = workflows.require(db, m.RiskAssessment, identifier)
    record = workflows.accept(db, risk, payload)
    domain().discover_paths(db)
    domain().snapshot(db)
    db.commit()
    return serialize(record)


@app.post("/api/risk/{identifier}/verify")
def verify_risk(identifier: int, payload: VerifyInput, db: DB):
    risk = workflows.require(db, m.RiskAssessment, identifier)
    record = workflows.verify(db, risk, payload)
    domain().discover_paths(db)
    domain().snapshot(db)
    db.commit()
    return serialize(record)


@app.post("/api/reports", response_model=ReportSummary)
def create_report(payload: ReportInput, db: DB):
    freshness(db)
    report = reporting.create_report(db, payload.title, payload.perspective)
    # Keep the immutable report snapshot out of the audit's after payload.
    db.add(m.TimelineEvent(
        action="Report generated", object_type="report", object_id=report.id,
        summary=f"{payload.perspective.title()} report: {payload.title}",
    ))
    db.commit()
    return {key: getattr(report, key) for key in ReportSummary.model_fields}


@app.get("/api/reports/{identifier}/export")
def export_report(
    identifier: int, db: DB,
    format: Literal["pdf", "markdown", "json", "csv"] = "json",
    dataset: Literal["risk", "assets", "vulnerabilities", "remediation"] = "risk",
):
    report = workflows.require(db, m.Report, identifier)
    data, media, extension = reporting.export_report(report, format, dataset)
    return Response(
        data, media_type=media,
        headers={"Content-Disposition": f'attachment; filename="riskscope-{identifier}.{extension}"'},
    )


@app.get("/api/reports/{identifier}/summary")
def report_summary(identifier: int, db: DB):
    fields = ("dashboard", "generated_at", "scope", "disclaimer", "settings")
    row = db.execute(select(*(
        func.json_extract(m.Report.snapshot, f"$.{key}").label(key) for key in fields
    )).where(m.Report.id == identifier)).mappings().one_or_none()
    if row is None:
        raise HTTPException(404, "Report not found")
    return {key: json.loads(row[key]) if key in ("dashboard", "settings") and row[key] else row[key]
            for key in fields}


@app.get("/api/reports/{identifier}/records/{dataset}", response_model=Page)
def report_records(
    identifier: int, dataset: str, db: DB, page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
):
    if dataset not in RESOURCES or dataset == "reports":
        raise HTTPException(422, "Unsupported report dataset")
    path = f'$."{dataset}"'
    total = db.scalar(select(func.json_array_length(m.Report.snapshot, path)).where(m.Report.id == identifier))
    if total is None:
        raise HTTPException(404, "Report or captured dataset not found")
    rows = func.json_each(m.Report.snapshot, path).table_valued("key", "value")
    values = db.scalars(select(rows.c.value).select_from(m.Report).join(
        rows, true()
    ).where(m.Report.id == identifier).order_by(rows.c.key).offset((page - 1) * page_size).limit(page_size))
    return {"items": [json.loads(value) for value in values], "total": total, "page": page, "page_size": page_size}


def parse_ids(value: str, maximum=100):
    try:
        identifiers = list(dict.fromkeys(int(item) for item in value.split(",")))
    except ValueError as exc:
        raise HTTPException(422, "IDs must be comma-separated integers") from exc
    if not identifiers or len(identifiers) > maximum or any(i < 1 for i in identifiers):
        raise HTTPException(422, f"Select 1 to {maximum} valid IDs")
    return identifiers


def filters(model, request: Request):
    conditions = [model.status != "REMOVED"] if model is m.Service and "status" not in request.query_params else []
    for key, value in request.query_params.items():
        if key in ("page", "page_size", "search", "sort", "order", "actor", "reason"):
            continue
        if key == "ids":
            conditions.append(model.id.in_(parse_ids(value)))
        elif key == "active" and model is m.RiskAssessment:
            if value not in ("true", "false"):
                raise HTTPException(422, "active must be true or false")
            if value == "true":
                conditions.append(model.status.in_(reporting.ACTIVE))
            else:
                conditions.append(model.status.not_in(reporting.ACTIVE))
        elif (model, key) in (
            (m.RiskAssessment, "software_id"), (m.RiskAssessment, "sbom_id"),
            (m.Remediation, "asset_id"), (m.Remediation, "vulnerability_id"), (m.Remediation, "case_id"),
            (m.VulnerabilityMatch, "software_id"), (m.SBOMComponent, "software_id"),
            (m.AttackPath, "asset_id"), (m.AttackPath, "vulnerability_id"),
        ):
            try:
                identifier = int(value)
                if identifier < 1:
                    raise ValueError()
            except ValueError as exc:
                raise HTTPException(422, f"Invalid {key} filter") from exc
            installations = select(m.SoftwareInstallation.id).where(
                m.SoftwareInstallation.software_id == identifier
            )
            if model is m.RiskAssessment:
                if key == "sbom_id":
                    installations = select(m.SBOMComponent.installation_id).where(
                        m.SBOMComponent.sbom_id == identifier
                    )
                conditions.append(model.match_id.in_(select(m.VulnerabilityMatch.id).where(
                    m.VulnerabilityMatch.installation_id.in_(installations)
                )))
            elif model in (m.VulnerabilityMatch, m.SBOMComponent):
                conditions.append(model.installation_id.in_(installations))
            elif model is m.Remediation:
                risks = (select(m.CaseRisk.risk_id).where(m.CaseRisk.case_id == identifier) if key == "case_id"
                         else select(m.RiskAssessment.id).where(getattr(m.RiskAssessment, key) == identifier))
                conditions.append(model.risk_id.in_(risks))
            elif key == "vulnerability_id":
                conditions.append(model.risk_id.in_(select(m.RiskAssessment.id).where(
                    m.RiskAssessment.vulnerability_id == identifier
                )))
            else:
                path_nodes = func.json_each(m.AttackPath.asset_ids).table_valued("value")
                conditions.append(select(1).select_from(path_nodes).where(
                    path_nodes.c.value == identifier
                ).correlate(m.AttackPath).exists())
        elif model is m.RiskAssessment and key == "overdue":
            if value not in ("true", "false"):
                raise HTTPException(422, "overdue must be true or false")
            due = overdue_risk_query()
            conditions.append(model.id.in_(due) if value == "true" else model.id.not_in(due))
        elif model is m.RiskAssessment and key in ("internet_exposed", "known_exploited"):
            if value not in ("true", "false"):
                raise HTTPException(422, f"{key} must be true or false")
            if key == "known_exploited":
                conditions.append(model.vulnerability_id.in_(select(m.Vulnerability.id).where(
                    m.Vulnerability.known_exploited.is_(value == "true")
                )))
            else:
                exposure = func.coalesce(
                    func.json_extract(model.analyst_override, "$.exposure"), model.exposure
                )
                values = (("INTERNET_FACING", "EXTERNALLY_REACHABLE") if value == "true"
                          else ("INTERNAL_ONLY", "RESTRICTED", "ISOLATED"))
                conditions.append(exposure.in_(values))
        elif key in model.__table__.columns:
            column = model.__table__.columns[key]
            if column.type.python_type not in (str, int, float, bool):
                raise HTTPException(422, f"Filtering {key} is unsupported")
            try:
                if column.type.python_type is bool:
                    if value not in ("true", "false"):
                        raise ValueError()
                    parsed = value == "true"
                else:
                    parsed = column.type.python_type(value)
            except ValueError as exc:
                raise HTTPException(422, f"Invalid {key} filter") from exc
            if model is m.RiskAssessment and key in ("priority", "exposure", "severity", "confidence", "exploitability"):
                conditions.append(func.coalesce(
                    func.json_extract(model.analyst_override, f"$.{key}"), getattr(model, key)
                ) == parsed)
            else:
                conditions.append(getattr(model, key) == parsed)
        else:
            raise HTTPException(422, f"Unsupported filter: {key}")
    search = request.query_params.get("search", "")
    if len(search) > 200:
        raise HTTPException(422, "Search is limited to 200 characters")
    if search:
        columns = [getattr(model, column.name) for column in model.__table__.columns
                   if isinstance(column.type, String) and column.name in (
                       "hostname", "canonical_name", "original_name", "identifier", "name", "title",
                       "summary", "action", "filename", "owner", "description", "source",
                   )]
        if columns:
            conditions.append(or_(*(column.contains(search, autoescape=True) for column in columns)))
    return conditions


def foreign_keys(db, model, values):
    table_models = {mapper.local_table.name: mapper.class_ for mapper in Base.registry.mappers}
    for column in model.__table__.columns:
        if values.get(column.name) is None:
            continue
        for fk in column.foreign_keys:
            workflows.require(db, table_models[fk.column.table.name], values[column.name])
    if model is m.AssetRelationship and values["source_asset_id"] == values["target_asset_id"]:
        raise HTTPException(422, "A relationship must join different assets")
    if model in (m.Service, m.ExposureObservation) and values.get("installation_id"):
        installation = workflows.require(db, m.SoftwareInstallation, values["installation_id"])
        if installation.asset_id != values["asset_id"]:
            raise HTTPException(422, "Service installation must belong to this asset")
    if model is m.ExposureObservation and values.get("service_id"):
        service = workflows.require(db, m.Service, values["service_id"])
        if service.asset_id != values["asset_id"]:
            raise HTTPException(422, "Exposure service must belong to this asset")
    if model is m.AnalystNote and not any(values.get(key) for key in ("risk_id", "asset_id", "case_id")):
        raise HTTPException(422, "A note must be linked to a risk, asset, or case")


def prepare_change(db, model, values, request, existing=None):
    foreign_keys(db, model, values)
    reason = request.query_params.get("reason", "Recorded in the local analyst workstation")
    actor = request.query_params.get("actor", "Local analyst")
    if not actor.strip() or len(actor) > 200 or not reason.strip() or len(reason) > 20000:
        raise HTTPException(422, "A valid actor and reason are required")
    if model is m.Remediation:
        risk = workflows.require(db, m.RiskAssessment, values["risk_id"])
        if risk.status in ("VERIFIED", "FALSE_POSITIVE", "RISK_ACCEPTED", "DEFERRED"):
            if not existing or values.get("status") != existing.status:
                raise HTTPException(409, "Reopen or review the risk before changing its remediation status")
        if values.get("status") in ("VERIFIED", "RISK_ACCEPTED", "FALSE_POSITIVE", "DEFERRED"):
            if not existing or values["status"] != existing.status:
                raise HTTPException(422, "Use the risk review, acceptance, or verification action for this status")
        if values.get("fixed_version"):
            fixes = [version for versions in db.scalars(select(m.AffectedRange.fixed_versions).where(
                m.AffectedRange.vulnerability_id == risk.vulnerability_id
            )) for version in versions]
            if values["fixed_version"] not in fixes:
                raise HTTPException(422, "Fixed version must be supported by the vulnerability's imported metadata")
    if hasattr(model, "evidence_id") and model is not m.AnalystNote:
        if not values.get("evidence_id") or (existing and values.get("evidence_id") == existing.evidence_id):
            kind = {
                m.Asset: "ASSET_INVENTORY", m.Software: "SOFTWARE_INVENTORY",
                m.SoftwareInstallation: "SOFTWARE_INVENTORY", m.Vulnerability: "VULNERABILITY_RECORD",
                m.Service: "SERVICE_OBSERVATION", m.ExposureObservation: "NETWORK_OBSERVATION",
                m.AssetRelationship: "NETWORK_OBSERVATION", m.ExploitabilityObservation: "EXPLOIT_INTELLIGENCE",
            }.get(model, "ANALYST_NOTE")
            proof = evidence(db, kind, values.get("source", "Manual"), reason, values, actor)
            values["evidence_id"] = proof.id
    if model is m.SoftwareInstallation:
        values["last_seen"] = m.now()
    return reason, actor


RECALCULATE = {
    m.Asset, m.BusinessContext, m.AssetRelationship, m.Service, m.Software, m.SoftwareInstallation,
    m.Vulnerability, m.AffectedRange, m.ExposureObservation, m.ExploitabilityObservation,
}


def after_change(db, record, before, reason, actor):
    asset_id = record.id if isinstance(record, m.Asset) else getattr(record, "asset_id", None)
    audit(db, "Record updated" if before else "Record created", record, before, reason, actor,
          asset_id=asset_id, risk_id=getattr(record, "risk_id", None))
    if isinstance(record, m.Asset) and record.exposure != before.get("exposure", "UNKNOWN"):
        db.add(m.ExposureObservation(
            asset_id=record.id, exposure=record.exposure, source=record.source,
            evidence_id=record.evidence_id, confidence=record.confidence, note=reason,
        ))
    if isinstance(record, m.ExposureObservation):
        target = workflows.require(
            db, m.Service if record.service_id else m.Asset, record.service_id or record.asset_id
        )
        target_before = serialize(target)
        target.exposure = record.exposure
        audit(db, "Exposure observation applied", target, target_before, reason, actor, asset_id=record.asset_id)
    if isinstance(record, m.Remediation):
        risk = workflows.require(db, m.RiskAssessment, record.risk_id)
        prior = serialize(risk)
        risk.owner, risk.due_date = record.owner, record.due_date
        if risk.status not in ("VERIFIED", "FALSE_POSITIVE", "RISK_ACCEPTED", "DEFERRED"):
            risk.status = record.status
        audit(db, "Remediation assignment updated", risk, prior, reason, actor, risk.asset_id, risk.id)


def register_resource(name, model, schema):
    dto = ReportSummary if model is m.Report else READ_DTOS[model]

    def listing(
        request: Request, db: DB, page: int = Query(1, ge=1),
        page_size: int = Query(25, ge=1, le=100), sort: str = "id",
        order: Literal["asc", "desc"] = "asc",
    ):
        if model in (m.RiskAssessment, m.Remediation, m.RiskAcceptance):
            freshness(db)
        if sort not in model.__table__.columns or model.__table__.columns[sort].type.python_type not in (
            str, int, float, bool
        ):
            raise HTTPException(422, "Unsupported sort column")
        conditions = filters(model, request)
        total = db.scalar(select(func.count()).select_from(model).where(*conditions))
        column = reporting.priority_order() if model is m.RiskAssessment and sort == "priority" else getattr(model, sort)
        if model is m.Report:
            fields = [column for column in model.__table__.columns if column.name != "snapshot"]
            records = db.execute(select(*fields).where(*conditions).order_by(
                column.desc() if order == "desc" else column.asc(), model.id
            ).offset((page - 1) * page_size).limit(page_size)).mappings()
            return {"items": [dict(row) for row in records], "total": total, "page": page, "page_size": page_size}
        rows = db.scalars(select(model).where(*conditions).order_by(
            column.desc() if order == "desc" else column.asc(), model.id
        ).offset((page - 1) * page_size).limit(page_size)).all()
        items = reporting.enrich(db, rows) if model is m.RiskAssessment else [serialize(r) for r in rows]
        return {"items": items, "total": total, "page": page, "page_size": page_size}

    def detail(identifier: int, db: DB):
        if model in (m.RiskAssessment, m.Remediation, m.RiskAcceptance):
            freshness(db)
        if model is m.Report:
            record = db.execute(select(
                *(getattr(model, key) for key in ReportSummary.model_fields)
            ).where(model.id == identifier)).mappings().one_or_none()
            if record is None:
                raise HTTPException(404, "Report not found")
            return dict(record)
        record = workflows.require(db, model, identifier)
        return serialize(record)

    app.add_api_route(f"/api/{name}", listing, methods=["GET"], response_model=Page, name=f"List {name}")
    app.add_api_route(
        f"/api/{name}/{{identifier}}", detail, methods=["GET"], response_model=dto, name=f"Get {name}"
    )
    if schema is None:
        return

    def create(payload, request: Request, db: DB):
        values = payload.model_dump()
        reason, actor = prepare_change(db, model, values, request)
        record = model(**values)
        db.add(record)
        db.flush()
        after_change(db, record, {}, reason, actor)
        persist(db, recalculate=model in RECALCULATE)
        return serialize(record)

    def update(identifier: int, payload, request: Request, db: DB):
        record = workflows.require(db, model, identifier)
        before = serialize(record)
        merged = {key: before[key] for key in schema.model_fields if key in before}
        merged.update(payload.model_dump(exclude_unset=True))
        try:
            values = schema.model_validate(merged).model_dump()
        except ValidationError as exc:
            raise RequestValidationError(exc.errors()) from exc
        reason, actor = prepare_change(db, model, values, request, record)
        for key, value in values.items():
            setattr(record, key, value)
        after_change(db, record, before, reason, actor)
        persist(db, recalculate=model in RECALCULATE)
        return serialize(record)

    patch_schema = create_model(
        f"{schema.__name__}Patch", __base__=Input,
        **{key: (field.annotation | None, None) for key, field in schema.model_fields.items()},
    )
    create.__annotations__["payload"] = Annotated[schema, Body()]
    update.__annotations__["payload"] = Annotated[patch_schema, Body()]
    app.add_api_route(f"/api/{name}", create, methods=["POST"], response_model=dto, name=f"Create {name}")
    app.add_api_route(
        f"/api/{name}/{{identifier}}", update, methods=["PATCH"], response_model=dto, name=f"Update {name}"
    )


@app.delete("/api/relationships/{identifier}")
def delete_relationship(identifier: int, db: DB, actor: str = "Local analyst", reason: str = "Relationship removed"):
    record = workflows.require(db, m.AssetRelationship, identifier)
    before = serialize(record)
    db.add(m.AuditEvent(
        action="Relationship removed", object_type="asset_relationship", object_id=identifier,
        actor=actor, reason=reason, before=before, after={},
    ))
    db.add(m.TimelineEvent(
        action="Relationship removed", object_type="asset_relationship", object_id=identifier,
        actor=actor, summary=reason, asset_id=record.source_asset_id,
    ))
    db.delete(record)
    persist(db, recalculate=True)
    return {"deleted": identifier, "paths_recomputed": True}


@app.delete("/api/services/{identifier}")
def remove_service(identifier: int, db: DB, actor: str = "Local analyst", reason: str = "Service retired"):
    record = workflows.require(db, m.Service, identifier)
    before = serialize(record)
    record.status = "REMOVED"
    record.exposure = "UNKNOWN"
    audit(db, "Service retired", record, before, reason, actor, record.asset_id)
    persist(db, recalculate=True)
    return {"deleted": identifier, "retained_for_history": True}


@app.get("/api/assets/{identifier}/risk")
def asset_risk(identifier: int, request: Request, db: DB,
               page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)):
    workflows.require(db, m.Asset, identifier)
    freshness(db)
    condition = m.RiskAssessment.asset_id == identifier
    rows = db.scalars(select(m.RiskAssessment).where(condition).order_by(
        m.RiskAssessment.score.desc(), m.RiskAssessment.id
    ).offset((page - 1) * page_size).limit(page_size))
    return {"items": reporting.enrich(db, rows), "total": db.scalar(
        select(func.count(m.RiskAssessment.id)).where(condition)
    ), "page": page, "page_size": page_size}


@app.get("/api/assets/{identifier}/attack-paths")
def asset_paths(identifier: int, db: DB, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)):
    workflows.require(db, m.Asset, identifier)
    condition = or_(m.AttackPath.source_asset_id == identifier, m.AttackPath.target_asset_id == identifier)
    rows = db.scalars(select(m.AttackPath).where(condition).order_by(m.AttackPath.id).offset(
        (page - 1) * page_size
    ).limit(page_size))
    return {"items": [serialize(row) for row in rows],
            "total": db.scalar(select(func.count(m.AttackPath.id)).where(condition)),
            "page": page, "page_size": page_size}


@app.get("/api/graph")
def graph(
    db: DB, asset_id: int | None = None, search: str = Query("", max_length=200),
    kind: Literal["all", "asset", "service", "software", "vulnerability"] = "all",
    critical: bool = False, internet: bool = False, known_exploited: bool = False,
    page_size: int = Query(100, ge=1, le=100),
):
    conditions = []
    if asset_id:
        workflows.require(db, m.Asset, asset_id)
        neighbors = {asset_id}
        for path in db.scalars(select(m.AttackPath).where(
            or_(m.AttackPath.source_asset_id == asset_id, m.AttackPath.target_asset_id == asset_id)
        ).limit(100)):
            neighbors.update(path.asset_ids)
        connected = db.execute(select(
            m.AssetRelationship.source_asset_id, m.AssetRelationship.target_asset_id
        ).where(or_(
            m.AssetRelationship.source_asset_id == asset_id, m.AssetRelationship.target_asset_id == asset_id
        )).order_by(m.AssetRelationship.id).limit(100))
        for source_id, target_id in connected:
            neighbors.update((source_id, target_id))
        conditions.append(m.Asset.id.in_(neighbors))
    if search:
        conditions.append(or_(
            m.Asset.hostname.contains(search, autoescape=True),
            m.Asset.id.in_(select(m.SoftwareInstallation.asset_id).where(
                m.SoftwareInstallation.original_name.contains(search, autoescape=True)
            )),
            m.Asset.id.in_(select(m.Service.asset_id).where(m.Service.name.contains(search, autoescape=True))),
            m.Asset.id.in_(select(m.RiskAssessment.asset_id).join(
                m.Vulnerability, m.RiskAssessment.vulnerability_id == m.Vulnerability.id
            ).where(or_(m.Vulnerability.identifier.contains(search, autoescape=True),
                        m.Vulnerability.title.contains(search, autoescape=True)))),
        ))
    if critical:
        conditions.append(m.Asset.criticality == "CRITICAL")
    if internet:
        conditions.append(m.Asset.exposure.in_(("INTERNET_FACING", "EXTERNALLY_REACHABLE")))
    if known_exploited:
        conditions.append(m.Asset.id.in_(select(m.RiskAssessment.asset_id).join(
            m.Vulnerability, m.RiskAssessment.vulnerability_id == m.Vulnerability.id
        ).where(m.Vulnerability.known_exploited.is_(True), m.RiskAssessment.status.in_(reporting.ACTIVE))))
    assets = db.scalars(select(m.Asset).where(*conditions).order_by(m.Asset.id).limit(page_size + 1)).all()
    truncated = len(assets) > page_size
    assets = assets[:page_size]
    ids = [asset.id for asset in assets]
    edge_limit = domain().get_settings(db)["max_graph_edges"]
    relations = db.scalars(select(m.AssetRelationship).where(
        m.AssetRelationship.source_asset_id.in_(ids), m.AssetRelationship.target_asset_id.in_(ids)
    ).order_by(m.AssetRelationship.id).limit(edge_limit + 1)).all()
    truncated |= len(relations) > edge_limit
    nodes = [{"id": f"asset-{r.id}", "label": r.hostname, "kind": "asset", "data": serialize(r)} for r in assets]
    edges = [{"id": f"relationship-{r.id}", "source": f"asset-{r.source_asset_id}",
              "target": f"asset-{r.target_asset_id}", "label": r.type, "data": serialize(r)}
             for r in relations[:edge_limit]]
    for asset in assets:
        if asset.exposure in ("INTERNET_FACING", "EXTERNALLY_REACHABLE"):
            if not any(node["id"] == "internet" for node in nodes):
                nodes.append({"id": "internet", "label": "Internet (observed)", "kind": "internet", "data": {}})
            edges.append({"id": f"exposure-{asset.id}", "source": "internet", "target": f"asset-{asset.id}",
                          "label": "EXPOSED", "data": {"evidence_id": asset.evidence_id}})
    if kind in ("all", "software"):
        installations = db.scalars(select(m.SoftwareInstallation).where(
            m.SoftwareInstallation.asset_id.in_(ids)
        ).order_by(m.SoftwareInstallation.id).limit(page_size + 1)).all()
        truncated |= len(installations) > page_size
        for record in installations[:page_size]:
            nodes.append({"id": f"software-{record.id}", "label": f"{record.original_name} {record.version}",
                          "kind": "software", "data": serialize(record)})
            edges.append({"id": f"runs-{record.id}", "source": f"asset-{record.asset_id}",
                          "target": f"software-{record.id}", "label": "RUNS", "data": {"evidence_id": record.evidence_id}})
    if kind in ("all", "service"):
        services = db.scalars(select(m.Service).where(
            m.Service.asset_id.in_(ids), m.Service.status != "REMOVED"
        ).order_by(
            m.Service.id
        ).limit(page_size + 1)).all()
        truncated |= len(services) > page_size
        for record in services[:page_size]:
            nodes.append({"id": f"service-{record.id}", "label": f"{record.name} :{record.port}",
                          "kind": "service", "data": serialize(record)})
            edges.append({"id": f"hosts-{record.id}", "source": f"asset-{record.asset_id}",
                          "target": f"service-{record.id}", "label": "HOSTS", "data": {"evidence_id": record.evidence_id}})
    if kind in ("all", "vulnerability"):
        risks = db.scalars(select(m.RiskAssessment).where(
            m.RiskAssessment.asset_id.in_(ids), m.RiskAssessment.vulnerability_id.is_not(None),
            m.RiskAssessment.status.in_(reporting.ACTIVE),
        ).order_by(m.RiskAssessment.score.desc(), m.RiskAssessment.id).limit(page_size + 1)).all()
        truncated |= len(risks) > page_size
        for record in risks[:page_size]:
            nodes.append({"id": f"risk-{record.id}", "label": record.title, "kind": "vulnerability",
                          "data": serialize(record)})
            edges.append({"id": f"affected-{record.id}", "source": f"asset-{record.asset_id}",
                          "target": f"risk-{record.id}", "label": "AFFECTED_BY",
                          "data": {"evidence_ids": record.evidence_ids}})
    return {"nodes": nodes, "edges": edges, "truncated": truncated,
            "limits": {"assets": page_size, "per_kind": page_size, "relationships": edge_limit},
            "notice": "Potential relationships, not proof of exploitation. Filter to inspect a bounded subgraph."}


@app.get("/api/sbom/{identifier}/graph")
def sbom_graph(identifier: int, db: DB, page_size: int = Query(100, ge=1, le=100)):
    workflows.require(db, m.SBOM, identifier)
    rows = db.scalars(select(m.SBOMComponent).where(m.SBOMComponent.sbom_id == identifier).order_by(
        m.SBOMComponent.id
    ).limit(page_size + 1)).all()
    truncated = len(rows) > page_size
    rows = rows[:page_size]
    ids = [row.id for row in rows]
    deps = db.scalars(select(m.Dependency).where(
        m.Dependency.sbom_id == identifier, m.Dependency.source_component_id.in_(ids),
        m.Dependency.target_component_id.in_(ids),
    ).limit(501)).all()
    return {
        "nodes": [{"id": f"component-{r.id}", "label": f"{r.name} {r.version}",
                   "kind": "component", "data": serialize(r)} for r in rows],
        "edges": [{"id": f"dependency-{r.id}", "source": f"component-{r.source_component_id}",
                   "target": f"component-{r.target_component_id}", "label": "DEPENDS_ON", "data": serialize(r)}
                  for r in deps[:500]],
        "truncated": truncated or len(deps) > 500, "limits": {"components": page_size, "dependencies": 500},
    }


for resource_name, (resource_model, resource_schema) in RESOURCES.items():
    register_resource(resource_name, resource_model, resource_schema)


@app.get("/docs", response_class=HTMLResponse, include_in_schema=False)
def offline_api_docs():
    rows = "".join(
        f"<tr><td>{escape(method.upper())}</td><td><code>{escape(path)}</code></td>"
        f"<td>{escape(operation.get('summary', ''))}</td></tr>"
        for path, methods in app.openapi()["paths"].items() for method, operation in methods.items()
    )
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
        "<title>RiskScope local API</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;"
        "padding:16px;color:#243348}table{border-collapse:collapse;width:100%}td,th{padding:12px;text-align:left;"
        "border-bottom:1px solid #dbe1e8}a{color:#155bb5}</style><h1>RiskScope local API</h1>"
        "<p>Offline API reference. <a href='/openapi.json'>Download the complete typed OpenAPI contract</a>.</p>"
        "<p>Lists accept page, page_size (1-100), search, sort, order and exact field filters. "
        "Mutations accept application/json unless an import requires multipart/form-data.</p>"
        f"<table><thead><tr><th>Method</th><th>Route</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table></html>"
    )


frontend = Path(os.environ.get(
    "RISKSCOPE_FRONTEND_DIR", str(Path(__file__).resolve().parents[2] / "frontend" / "dist")
))
if (frontend / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=frontend / "assets"), name="frontend-assets")


@app.get("/{path:path}", include_in_schema=False)
def spa(path: str):
    if path.startswith("api/"):
        raise HTTPException(404, "API route not found")
    if not (frontend / "index.html").is_file():
        raise HTTPException(404, "Frontend is not built. Run npm run build in frontend.")
    return FileResponse(frontend / "index.html")
