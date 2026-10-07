"""Bounded, evidence-preserving inventory and SBOM ingestion, without network I/O."""

import csv
import io
import json
import re
from collections import defaultdict, deque
from hashlib import sha256
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from pydantic import Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session
from xml.etree.ElementTree import ParseError

from app import models as m
from app import schemas as s
from app.services.common import audit, evidence
from app.services.providers import LocalJSONProvider, cache_snapshot

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_ROWS = 50_000
MAX_JSON_NODES = 200_000
MAX_DOCUMENT_DEPTH = 32
MAX_COMPONENTS = 5_000
MAX_DEPENDENCIES = 20_000
MAX_FIELD_LENGTH = 20_000
KINDS = {"assets", "software", "vulnerabilities", "sbom", "relationships"}
ENUM_FIELDS = {
    "environment", "criticality", "exposure", "status", "confidence", "lifecycle",
    "exploit_maturity", "attack_complexity", "privileges_required", "user_interaction", "type",
}


class SoftwareRow(s.ProvenanceInput):
    hostname: s.Name
    product: s.Name
    vendor: str = Field(default="", max_length=200)
    version: str = Field(default="", max_length=200)
    ecosystem: str = Field(default="generic", max_length=60)
    architecture: str = Field(default="", max_length=60)
    package_identifier: str = Field(default="", max_length=1000)
    installation_source: str = Field(default="", max_length=200)
    lifecycle: Literal["SUPPORTED", "END_OF_LIFE", "UNKNOWN"] = "UNKNOWN"


def normalize_product(name: str) -> tuple[str, str, str]:
    stripped = name.strip()
    folded = stripped.casefold()
    if folded == "nginx web server" or re.fullmatch(r"nginx/\d+(?:\.\d+)*", folded):
        return "nginx", "conservative-nginx-alias", "HIGH"
    return folded, "casefold-and-trim" if stripped != folded or stripped != name else "exact", "HIGH"


def _bounded(document):
    stack = [(document, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_DOCUMENT_DEPTH:
            raise ValueError("Document complexity exceeds the node or nesting-depth limit")
        if isinstance(value, dict):
            stack.extend((child, depth + 1) for child in value.values())
            if any(len(key) > MAX_FIELD_LENGTH for key in value):
                raise ValueError("Document key is too long")
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, str) and len(value) > MAX_FIELD_LENGTH:
            raise ValueError("Document string exceeds the field-length limit")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON object key: {key[:80]}")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError(f"Non-finite JSON number is not allowed: {value}")


def parse_json(data: bytes):
    if not data or len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("Upload must be nonempty and at most 10 MiB")
    try:
        result = json.loads(
            data.decode("utf-8-sig"), object_pairs_hook=_unique_object, parse_constant=_invalid_constant
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Malformed UTF-8 JSON document") from exc
    _bounded(result)
    return result


def _filename(value: str) -> str:
    clean = value.replace("\\", "/").rsplit("/", 1)[-1]
    clean = "".join(char for char in clean if char.isprintable()).strip()
    return (clean or "upload")[:200]


def _normalize(row: dict) -> dict:
    return {
        key: value.strip().upper() if key in ENUM_FIELDS and isinstance(value, str) else value
        for key, value in row.items()
    }


def _inventory_rows(kind: str, data: bytes, filename: str) -> list:
    if filename.lower().endswith(".json") or data.lstrip().startswith((b"[", b"{")):
        document = parse_json(data)
        if isinstance(document, dict):
            if set(document) != {kind}:
                raise ValueError(f"JSON envelope must have exactly one '{kind}' array")
            document = document[kind]
        if not isinstance(document, list) or not document:
            raise ValueError("Inventory must contain a nonempty array of records")
        rows = document
    else:
        try:
            text = data.decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
            headers = reader.fieldnames
            if not headers or len(headers) > 100 or len(set(headers)) != len(headers):
                raise ValueError("CSV requires unique, nonempty column headers")
            if any(not header or len(header) > 200 for header in headers):
                raise ValueError("Invalid CSV column header")
            required = {
                "assets": {"hostname"}, "software": {"hostname", "product"},
                "relationships": {"source_asset_id", "target_asset_id"},
            }[kind]
            if not required.issubset(headers):
                raise ValueError(f"CSV is missing required columns: {', '.join(sorted(required - set(headers)))}")
            rows = []
            for row in reader:
                if None in row or any(value is None for value in row.values()):
                    raise ValueError("CSV row has a different number of fields than its header")
                if any(len(value) > MAX_FIELD_LENGTH for value in row.values()):
                    raise ValueError("CSV field exceeds the field-length limit")
                if "tags" in row:
                    try:
                        row["tags"] = json.loads(row["tags"] or "[]")
                    except json.JSONDecodeError:
                        # Retaining this value makes the DTO reject this row, not the entire file.
                        pass
                if row.get("zone_id") == "":
                    row["zone_id"] = None
                rows.append(row)
                if len(rows) > MAX_ROWS:
                    raise ValueError("Inventory exceeds the record-count limit")
        except (UnicodeError, csv.Error) as exc:
            raise ValueError("Malformed UTF-8 CSV document") from exc
    if not rows or len(rows) > MAX_ROWS:
        raise ValueError("Inventory is empty or exceeds the record-count limit")
    return rows


class ImportContext:
    def __init__(self, db: Session, job: m.ImportJob):
        self.db, self.job = db, job
        self.assets = {item.hostname: item for item in db.scalars(select(m.Asset))}
        self.assets_by_id = {item.id: item for item in self.assets.values()}
        self.software = {
            (item.canonical_name, item.vendor, item.ecosystem): item for item in db.scalars(select(m.Software))
        }
        self.installations = {
            (item.asset_id, item.software_id, item.package_identifier): item
            for item in db.scalars(select(m.SoftwareInstallation))
        }
        self.vulnerabilities = {item.identifier: item for item in db.scalars(select(m.Vulnerability))}
        self.ranges = defaultdict(list)
        for item in db.scalars(select(m.AffectedRange)):
            self.ranges[item.vulnerability_id].append(item)
        self.references = defaultdict(list)
        for item in db.scalars(select(m.VulnerabilityReference)):
            self.references[item.vulnerability_id].append(item)
        self.relationships = {
            (item.source_asset_id, item.target_asset_id, item.type): item
            for item in db.scalars(select(m.AssetRelationship))
        }
        self.zone_ids = set(db.scalars(select(m.NetworkZone.id)))

    def observation(self, kind, row, number, summary):
        return evidence(
            self.db, kind, self.job.filename, summary,
            {"row_number": number, "digest": self.job.digest, "record": row},
            actor="Local import", import_job_id=self.job.id,
        )

    def provenance(self, item, observation):
        item.source = self.job.filename
        item.import_job_id = self.job.id
        item.evidence_id = observation.id

    def save(self, item, values, observation, *, asset_id=None):
        values = {key: value for key, value in values.items() if key not in ("source", "evidence_id")}
        exists = item.id is not None
        before = s.serialize(item) if exists else {}
        changed = not exists or any(getattr(item, key) != value for key, value in values.items())
        for key, value in values.items():
            setattr(item, key, value)
        if isinstance(item, m.SoftwareInstallation):
            item.last_seen = m.now()
        self.provenance(item, observation)
        self.db.add(item)
        self.db.flush()
        audit(
            self.db, "IMPORT_UPDATED" if exists else "IMPORT_CREATED", item, before,
            reason="Inventory observation refreshed" if exists else "Record imported with provenance",
            actor="Local import", asset_id=asset_id,
        )
        return item, "IMPORTED" if changed else "SKIPPED"

    def asset(self, raw, number):
        values = s.AssetInput.model_validate(_normalize(raw)).model_dump()
        if values["zone_id"] is not None and values["zone_id"] not in self.zone_ids:
            raise ValueError("zone_id does not reference an existing zone")
        obs = self.observation("ASSET_INVENTORY", raw, number, f"Asset inventory: {values['hostname']}")
        obs.confidence = values["confidence"]
        item = self.assets.get(values["hostname"]) or m.Asset()
        # An omitted optional column must not erase previously observed context.
        values = {key: value for key, value in values.items() if key in raw or item.id is None}
        item, status = self.save(item, values, obs)
        self.assets[item.hostname] = item
        self.assets_by_id[item.id] = item
        return item, status

    def software_row(self, raw, number, observation=None):
        values = SoftwareRow.model_validate(_normalize(raw)).model_dump()
        asset = self.assets.get(values["hostname"])
        if asset is None:
            raise ValueError(f"Unknown asset hostname: {values['hostname']}")
        canonical, method, confidence = normalize_product(values["product"])
        vendor, ecosystem = values["vendor"].casefold(), values["ecosystem"].casefold() or "generic"
        obs = observation or self.observation(
            "SOFTWARE_INVENTORY", raw, number, f"Software inventory: {asset.hostname} / {values['product']}"
        )
        obs.confidence = values["confidence"]
        key = (canonical, vendor, ecosystem)
        software = self.software.get(key)
        if software is None:
            software = m.Software(
                **s.SoftwareInput(
                    canonical_name=canonical, vendor=vendor, ecosystem=ecosystem,
                    lifecycle=values["lifecycle"], confidence=values["confidence"],
                ).model_dump()
            )
            self.provenance(software, obs)
            self.db.add(software)
            self.db.flush()
            self.software[key] = software
            audit(self.db, "SOFTWARE_DISCOVERED", software, reason="Canonical product observed", asset_id=asset.id)
        elif "lifecycle" in raw and software.lifecycle != values["lifecycle"]:
            before = s.serialize(software)
            software.lifecycle = values["lifecycle"]
            self.provenance(software, obs)
            audit(self.db, "SOFTWARE_LIFECYCLE_UPDATED", software, before, asset_id=asset.id)
        key = (asset.id, software.id, values["package_identifier"])
        installation = self.installations.get(key) or m.SoftwareInstallation()
        installation_values = s.InstallationInput(
            asset_id=asset.id, software_id=software.id, original_name=values["product"],
            version=values["version"], architecture=values["architecture"],
            package_identifier=values["package_identifier"], installation_source=values["installation_source"],
            confidence=values["confidence"],
        ).model_dump()
        if installation.id is not None:
            for optional in ("architecture", "installation_source"):
                if optional not in raw:
                    installation_values.pop(optional)
        installation_values.update(normalization_method=method, normalization_confidence=confidence)
        installation, status = self.save(installation, installation_values, obs, asset_id=asset.id)
        self.installations[key] = installation
        return installation, status

    def vulnerability(self, raw, number):
        values = dict(raw)
        ranges_raw, refs_raw = values.pop("affected_ranges", []), values.pop("references", [])
        values = s.VulnerabilityInput.model_validate(_normalize(values)).model_dump()
        if not isinstance(ranges_raw, list) or not isinstance(refs_raw, list):
            raise ValueError("affected_ranges and references must be arrays")
        ranges = []
        for rule in ranges_raw:
            if not isinstance(rule, dict):
                raise ValueError("Every affected range must be an object")
            parsed = s.RangeInput.model_validate({**rule, "vulnerability_id": 0}).model_dump()
            parsed["product"] = normalize_product(parsed["product"])[0]
            parsed["vendor"] = parsed["vendor"].casefold()
            parsed["ecosystem"] = parsed["ecosystem"].casefold()
            parsed["version_scheme"] = parsed["version_scheme"].casefold()
            ranges.append(parsed)
        references = []
        for reference in refs_raw:
            if not isinstance(reference, dict):
                raise ValueError("Reference must be an object")
            parsed = s.ReferenceInput.model_validate({**reference, "vulnerability_id": 0}).model_dump()
            try:
                url = urlsplit(parsed["url"])
                if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password:
                    raise ValueError("References must be absolute HTTP(S) URLs without credentials")
            except ValueError as exc:
                raise ValueError("Invalid reference URL") from exc
            references.append(parsed)
        obs = self.observation(
            "VULNERABILITY_RECORD", raw, number,
            f"{'SYNTHETIC: ' if values['synthetic'] else ''}Vulnerability metadata: {values['identifier']}",
        )
        obs.confidence = values["confidence"]
        item = self.vulnerabilities.get(values["identifier"]) or m.Vulnerability()
        item, status = self.save(item, values, obs)
        self.vulnerabilities[item.identifier] = item
        old_ranges = self.ranges[item.id]

        def range_key(value):
            return (
                value["product"], value["vendor"], value["ecosystem"], value["version_scheme"],
                value["affected"], tuple(value["fixed_versions"]),
            )

        remaining = {range_key(s.serialize(rule)): rule for rule in old_ranges}
        current_ranges = []
        seen_ranges = set()
        for rule in ranges:
            key = range_key(rule)
            if key in seen_ranges:
                continue
            seen_ranges.add(key)
            existing = remaining.pop(key, None)
            if existing is None:
                existing = m.AffectedRange(**{**rule, "vulnerability_id": item.id, "evidence_id": obs.id})
                self.db.add(existing)
                self.db.flush()
                status = "IMPORTED"
            else:
                existing.evidence_id = obs.id
            current_ranges.append(existing)
        for obsolete in remaining.values():
            for match in self.db.scalars(
                select(m.VulnerabilityMatch).where(m.VulnerabilityMatch.range_id == obsolete.id)
            ):
                match.range_id = None
            self.db.delete(obsolete)
            status = "IMPORTED"
        self.ranges[item.id] = current_ranges
        old_refs = {(ref.label, ref.url): ref for ref in self.references[item.id]}
        current_refs = []
        seen_refs = set()
        for reference in references:
            key = (reference["label"], reference["url"])
            if key in seen_refs:
                continue
            seen_refs.add(key)
            ref = old_refs.pop(key, None)
            if ref is None:
                ref = m.VulnerabilityReference(**{**reference, "vulnerability_id": item.id})
                self.db.add(ref)
                status = "IMPORTED"
            current_refs.append(ref)
        for obsolete in old_refs.values():
            self.db.delete(obsolete)
            status = "IMPORTED"
        self.references[item.id] = current_refs
        if not ranges:
            self.job.warnings = [*self.job.warnings, f"Row {number}: no affected ranges; cannot correlate"]
        if values["synthetic"] and "SYNTHETIC DATA — not real vulnerability intelligence" not in self.job.warnings:
            self.job.warnings = [*self.job.warnings, "SYNTHETIC DATA — not real vulnerability intelligence"]
        return item, status

    def relationship(self, raw, number):
        values = s.RelationshipInput.model_validate(_normalize(raw)).model_dump()
        if any(values[key] not in self.assets_by_id for key in ("source_asset_id", "target_asset_id")):
            raise ValueError("Relationship endpoints must reference existing assets")
        obs = self.observation("NETWORK_OBSERVATION", raw, number, "Explicit imported asset relationship")
        obs.confidence = values["confidence"]
        key = (values["source_asset_id"], values["target_asset_id"], values["type"])
        item = self.relationships.get(key) or m.AssetRelationship()
        item, status = self.save(item, values, obs, asset_id=values["source_asset_id"])
        self.relationships[key] = item
        return item, status


def _xml_document(data):
    try:
        root = ElementTree.fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (DefusedXmlException, ParseError, UnicodeError, RecursionError) as exc:
        raise ValueError("Malformed or unsafe CycloneDX XML") from exc
    count = 0
    stack = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_JSON_NODES or depth > MAX_DOCUMENT_DEPTH:
            raise ValueError("XML complexity exceeds the node or nesting-depth limit")
        if node.text and len(node.text) > MAX_FIELD_LENGTH:
            raise ValueError("XML field exceeds the field-length limit")
        node.tag = node.tag.rsplit("}", 1)[-1]
        stack.extend((child, depth + 1) for child in node)
    if root.tag != "bom":
        raise ValueError("Expected a CycloneDX XML bom document")

    def component(node):
        result = {
            "bom-ref": node.get("bom-ref"), "name": node.findtext("name") or "",
            "version": node.findtext("version") or "", "publisher": node.findtext("publisher") or "",
            "purl": node.findtext("purl") or "",
            "hashes": [{"alg": child.get("alg", ""), "content": child.text or ""}
                       for child in node.findall("hashes/hash")],
            "licenses": [{"license": {"id": child.findtext("id") or "", "name": child.findtext("name") or ""}}
                         for child in node.findall("licenses/license")],
        }
        supplier = node.findtext("supplier/name")
        if supplier:
            result["supplier"] = {"name": supplier}
        children = node.findall("components/component")
        if children:
            result["components"] = [component(child) for child in children]
        return result

    metadata_root = root.find("metadata/component")
    return {
        "bomFormat": "CycloneDX", "specVersion": "XML", "serialNumber": root.get("serialNumber", ""),
        "metadata": {"component": component(metadata_root)} if metadata_root is not None else {},
        "components": [component(node) for node in root.findall("components/component")],
        "dependencies": [
            {"ref": node.get("ref", ""), "dependsOn": [child.get("ref", "") for child in node]}
            for node in root.findall("dependencies/dependency")
        ],
    }


def _text(value, field, limit=200, required=False):
    if value is None and not required:
        return ""
    if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
        raise ValueError(f"Invalid SBOM {field}")
    return value.strip()


def _list(value, field):
    if not isinstance(value, list):
        raise ValueError(f"SBOM {field} must be an array")
    return value


def _dependency_depth(refs, adjacent):
    """Bound the condensed graph, including a conservative allowance for nodes inside cycles."""
    visited, finished, reverse = set(), [], defaultdict(list)
    for source in refs:
        for target in adjacent[source]:
            reverse[target].append(source)
    for ref in sorted(refs):
        if ref in visited:
            continue
        stack = [(ref, False)]
        while stack:
            current, exiting = stack.pop()
            if exiting:
                finished.append(current)
            elif current not in visited:
                visited.add(current)
                stack.append((current, True))
                stack.extend((target, False) for target in reversed(adjacent[current]) if target not in visited)
    groups, sizes = {}, []
    for ref in reversed(finished):
        if ref in groups:
            continue
        group, size, stack = len(sizes), 0, [ref]
        while stack:
            current = stack.pop()
            if current in groups:
                continue
            groups[current] = group
            size += 1
            stack.extend(target for target in reverse[current] if target not in groups)
        sizes.append(size)
    condensed, indegree = defaultdict(set), [0] * len(sizes)
    cycle = any(size > 1 for size in sizes)
    for source in refs:
        for target in adjacent[source]:
            left, right = groups[source], groups[target]
            if left == right:
                cycle = True
            elif right not in condensed[left]:
                condensed[left].add(right)
                indegree[right] += 1
    distance = sizes.copy()
    queue = deque(index for index, degree in enumerate(indegree) if degree == 0)
    while queue:
        current = queue.popleft()
        if distance[current] - 1 > MAX_DOCUMENT_DEPTH:
            raise ValueError("SBOM dependency depth exceeds the limit")
        for target in condensed[current]:
            distance[target] = max(distance[target], distance[current] + sizes[target])
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    return cycle


def _parse_sbom(data: bytes):
    is_xml = data.lstrip().startswith(b"<")
    document = _xml_document(data) if is_xml else parse_json(data)
    if not isinstance(document, dict):
        raise ValueError("SBOM must be an object")
    nodes, edges, roots, warnings = [], [], [], []
    if document.get("bomFormat") == "CycloneDX":
        format_name = "CycloneDX XML" if is_xml else "CycloneDX JSON"
        if not document.get("specVersion"):
            raise ValueError("CycloneDX specVersion is required")
        metadata = document.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("CycloneDX metadata must be an object")
        entries = _list(document.get("components"), "components")
        if not entries:
            raise ValueError("CycloneDX components must not be empty")
        root_component = metadata.get("component")
        if root_component is not None and not isinstance(root_component, dict):
            raise ValueError("CycloneDX metadata.component must be an object")
        queue = deque([(root_component, True)] if root_component else [])
        queue.extend((item, False) for item in entries)
        while queue:
            item, is_root = queue.popleft()
            if not isinstance(item, dict):
                raise ValueError("SBOM component must be an object")
            ref = _text(item.get("bom-ref") or f"urn:riskscope:component:{len(nodes) + 1}", "bom-ref", 1000, True)
            vendor = item.get("supplier", {})
            if not isinstance(vendor, dict):
                raise ValueError("SBOM supplier must be an object")
            nodes.append({
                "ref": ref, "name": _text(item.get("name"), "name", required=True),
                "version": _text(item.get("version"), "version"),
                "vendor": _text(vendor.get("name") or item.get("publisher"), "vendor"),
                "purl": _text(item.get("purl"), "purl", 1000),
                "hashes": _list(item.get("hashes", []), "hashes"),
                "licenses": _list(item.get("licenses", []), "licenses"),
            })
            if is_root:
                roots.append(ref)
            children = _list(item.get("components", []), "nested components")
            queue.extend((child, False) for child in children)
            if len(nodes) + len(queue) > MAX_COMPONENTS:
                raise ValueError("SBOM exceeds the component limit")
        for dependency in _list(document.get("dependencies", []), "dependencies"):
            if not isinstance(dependency, dict):
                raise ValueError("SBOM dependency must be an object")
            source = _text(dependency.get("ref"), "dependency ref", 1000, True)
            targets = _list(dependency.get("dependsOn", []), "dependsOn")
            # Empty dependency entries must still reference a real component.
            edges.extend((source, _text(target, "dependency target", 1000, True)) for target in targets)
            if not targets:
                edges.append((source, None))
        serial = _text(document.get("serialNumber"), "serialNumber", 500)
    elif isinstance(document.get("spdxVersion"), str) and document["spdxVersion"].startswith("SPDX-"):
        format_name = "SPDX JSON"
        packages = _list(document.get("packages"), "packages")
        if not packages:
            raise ValueError("SPDX packages must not be empty")
        document_ref = _text(document.get("SPDXID", "SPDXRef-DOCUMENT"), "document SPDXID", 1000, True)
        roots = [_text(value, "documentDescribes", 1000, True)
                 for value in _list(document.get("documentDescribes", []), "documentDescribes")]
        for item in packages:
            if not isinstance(item, dict):
                raise ValueError("SPDX package must be an object")
            purl = ""
            for reference in _list(item.get("externalRefs", []), "externalRefs"):
                if not isinstance(reference, dict):
                    raise ValueError("SPDX externalRef must be an object")
                if reference.get("referenceType") == "purl":
                    purl = _text(reference.get("referenceLocator"), "purl", 1000)
            vendor = _text(item.get("supplier"), "supplier")
            if vendor.startswith(("Organization: ", "Person: ")):
                vendor = vendor.split(": ", 1)[1]
            if vendor == "NOASSERTION":
                vendor = ""
            nodes.append({
                "ref": _text(item.get("SPDXID"), "SPDXID", 1000, True),
                "name": _text(item.get("name"), "name", required=True),
                "version": _text(item.get("versionInfo"), "version"), "vendor": vendor, "purl": purl,
                "hashes": _list(item.get("checksums", []), "checksums"),
                "licenses": [item[key] for key in ("licenseConcluded", "licenseDeclared") if item.get(key)],
            })
        for relationship in _list(document.get("relationships", []), "relationships"):
            if not isinstance(relationship, dict):
                raise ValueError("SPDX relationship must be an object")
            source = _text(relationship.get("spdxElementId"), "relationship source", 1000, True)
            target = _text(relationship.get("relatedSpdxElement"), "relationship target", 1000, True)
            kind = relationship.get("relationshipType")
            if kind == "DESCRIBES" and source == document_ref:
                roots.append(target)
            elif kind == "DEPENDENCY_OF":
                edges.append((target, source))
            elif kind == "DEPENDS_ON":
                edges.append((source, target))
            else:
                warnings.append(f"SPDX relationship {kind!r} is not interpreted as a dependency")
        serial = _text(document.get("documentNamespace"), "documentNamespace", 500)
    else:
        raise ValueError("Unsupported SBOM format; expected CycloneDX or SPDX")
    if len(nodes) > MAX_COMPONENTS or len(edges) > MAX_DEPENDENCIES:
        raise ValueError("SBOM exceeds component or dependency limits")
    refs = {node["ref"] for node in nodes}
    if len(refs) != len(nodes):
        raise ValueError("Duplicate SBOM component reference")
    if any(root not in refs for root in roots):
        raise ValueError("Dangling SBOM root reference")
    if any(source not in refs or (target is not None and target not in refs) for source, target in edges):
        raise ValueError("Dangling SBOM dependency reference")
    if len(set(edges)) != len(edges):
        raise ValueError("Duplicate SBOM dependency edge")
    edges = [(source, target) for source, target in edges if target is not None]
    adjacent = defaultdict(list)
    for source, target in edges:
        adjacent[source].append(target)
    if _dependency_depth(refs, adjacent):
        warnings.append("Dependency cycle recorded; it is not evidence of exploitability")
    direct = {target for root in roots for target in adjacent[root] if target not in roots}
    reachable, queue = set(roots), deque(roots)
    while queue:
        for target in adjacent[queue.popleft()]:
            if target not in reachable:
                reachable.add(target)
                queue.append(target)
    for node in nodes:
        node["direct"] = True if node["ref"] in direct else (
            False if node["ref"] in reachable and node["ref"] not in roots else None
        )
    return format_name, serial, nodes, edges, list(dict.fromkeys(warnings))


def _package_identity(purl: str, ref: str):
    if purl.startswith("pkg:"):
        body = re.split(r"[?#]", purl, maxsplit=1)[0]
        suffix = purl[len(body):]
        if "@" in body.rsplit("/", 1)[-1]:
            body = body.rsplit("@", 1)[0]
        return body + suffix
    return f"sbom:{ref}"[:1000]


def _sbom_import(db: Session, context: ImportContext, asset_id, parsed):
    job = context.job
    format_name, serial, nodes, edges, warnings = parsed
    existing = db.scalar(select(m.SBOM).where(m.SBOM.asset_id == asset_id, m.SBOM.digest == job.digest))
    job.warnings = warnings
    if existing:
        components = list(db.scalars(select(m.SBOMComponent).where(m.SBOMComponent.sbom_id == existing.id)))
        job.processed = job.skipped = len(components)
        for number, component in enumerate(components, 1):
            db.add(m.ImportRecord(
                import_job_id=job.id, row_number=number, status="SKIPPED",
                object_type="sbom_component", object_id=component.id,
                raw={"ref": component.ref, "duplicate_of_sbom_id": existing.id},
            ))
        audit(db, "SBOM_DUPLICATE_SKIPPED", existing, reason=f"Digest already imported; import job {job.id}")
        return
    obs = context.observation(
        "SBOM", {"format": format_name, "serial": serial, "components": len(nodes)}, 0,
        f"SBOM import: {job.filename}; presence does not establish exploitability",
    )
    sbom = m.SBOM(asset_id=asset_id, name=job.filename, format=format_name, serial=serial, digest=job.digest)
    context.provenance(sbom, obs)
    db.add(sbom)
    db.flush()
    components = {}
    identities = defaultdict(int)
    for node in nodes:
        identities[(_package_identity(node["purl"], node["ref"]), normalize_product(node["name"])[0])] += 1
    for number, node in enumerate(nodes, 1):
        component_obs = context.observation("SBOM", node, number, f"SBOM component: {node['name']}")
        purl_type = node["purl"][4:].split("/", 1)[0] if node["purl"].startswith("pkg:") else "generic"
        ecosystem = {"pypi": "python"}.get(purl_type, purl_type)
        identity = _package_identity(node["purl"], node["ref"])
        if identities[(identity, normalize_product(node["name"])[0])] > 1:
            identity = f"{identity[:700]}#ref:{sha256(node['ref'].encode()).hexdigest()}"
        installation, _ = context.software_row({
            "hostname": context.assets_by_id[asset_id].hostname, "product": node["name"],
            "version": node["version"], "vendor": node["vendor"], "ecosystem": ecosystem,
            "package_identifier": identity, "installation_source": "SBOM", "confidence": "UNKNOWN",
        }, number, component_obs)
        component = m.SBOMComponent(sbom_id=sbom.id, installation_id=installation.id, **node)
        context.provenance(component, component_obs)
        db.add(component)
        db.flush()
        components[node["ref"]] = component
        db.add(m.ImportRecord(
            import_job_id=job.id, row_number=number, status="IMPORTED",
            object_type="sbom_component", object_id=component.id, raw=node,
        ))
    for source, target in edges:
        db.add(m.Dependency(
            sbom_id=sbom.id, source_component_id=components[source].id,
            target_component_id=components[target].id, evidence_id=obs.id,
        ))
    job.processed = job.imported = len(nodes)
    audit(db, "SBOM_IMPORTED", sbom, reason="Validated component and dependency observations", asset_id=asset_id)


def import_data(
    db: Session, kind: str, data: bytes, filename: str, asset_id: int | None = None
) -> m.ImportJob:
    if kind not in KINDS:
        raise ValueError(f"Unsupported import kind: {kind}")
    if not isinstance(data, bytes) or not data or len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("Upload must be nonempty and at most 10 MiB")
    filename = _filename(filename)
    provider_snapshot = None
    if kind == "sbom":
        if asset_id is None or db.get(m.Asset, asset_id) is None:
            raise ValueError("SBOM import requires an existing asset_id")
        parsed = _parse_sbom(data)
        rows = []
    elif kind == "vulnerabilities":
        provider_snapshot = LocalJSONProvider(source=filename).load(data)
        rows = provider_snapshot.records
        if len(rows) > MAX_ROWS:
            raise ValueError("Vulnerability feed exceeds the record-count limit")
    else:
        rows = _inventory_rows(kind, data, filename)
    job = m.ImportJob(kind=kind, filename=filename, digest=sha256(data).hexdigest())
    db.add(job)
    db.flush()
    context = ImportContext(db, job)
    if kind == "sbom":
        _sbom_import(db, context, asset_id, parsed)
    else:
        handler = {
            "assets": context.asset, "software": context.software_row,
            "vulnerabilities": context.vulnerability, "relationships": context.relationship,
        }[kind]
        for number, row in enumerate(rows, 1):
            job.processed += 1
            try:
                if not isinstance(row, dict):
                    raise ValueError("Record must be a JSON object")
                item, status = handler(row, number)
            except (ValidationError, ValueError) as exc:
                error = str(exc)
                context.observation("IMPORT_RECORD", row, number, f"Rejected import row: {error[:500]}")
                db.add(m.ImportRecord(
                    import_job_id=job.id, row_number=number, status="REJECTED",
                    error=error, raw=row if isinstance(row, dict) else {"value": row},
                ))
                job.rejected += 1
            else:
                db.add(m.ImportRecord(
                    import_job_id=job.id, row_number=number, status=status,
                    object_type=item.__tablename__, object_id=item.id, raw=row,
                ))
                if status == "IMPORTED":
                    job.imported += 1
                else:
                    job.skipped += 1
        if provider_snapshot:
            cache_snapshot(db, provider_snapshot)
    job.status = "COMPLETED_WITH_ERRORS" if job.rejected else "COMPLETED"
    audit(db, "IMPORT_COMPLETED", job, reason=f"{job.imported} imported; {job.skipped} skipped; {job.rejected} rejected")
    db.flush()
    return job


def demo(db: Session) -> dict:
    """Explicit, idempotent synthetic demo seed; never called at application startup."""
    fixtures = Path(__file__).resolve().parents[3] / "fixtures"
    marker = db.scalar(select(m.Setting).where(m.Setting.key == "demo_seed"))
    if marker:
        return {"seeded": False, "synthetic": True, "message": "Synthetic ExampleCorp demo is already loaded"}
    if any(db.scalar(select(model.id).limit(1)) is not None
           for model in (m.Asset, m.Software, m.Vulnerability, m.SBOM)):
        raise ValueError(
            "Load the synthetic demo into an empty inventory. Existing records were preserved; "
            "use a separate database to explore ExampleCorp."
        )
    for kind, name in (
        ("assets", "examplecorp-assets.json"), ("software", "examplecorp-software.csv"),
        ("vulnerabilities", "examplecorp-vulnerabilities.json"),
    ):
        job = import_data(db, kind, (fixtures / name).read_bytes(), name)
        if job.rejected:
            raise ValueError(f"Bundled synthetic fixture {name} failed validation")
    assets = {asset.hostname: asset for asset in db.scalars(select(m.Asset))}
    relation_rows = [
        {
            "source_asset_id": assets[source].id, "target_asset_id": assets[target].id,
            "type": "CONNECTS_TO", "description": "SYNTHETIC: explicitly observed demo application connection",
            "confidence": "HIGH",
        }
        for source, target in (("WEB-01", "APP-01"), ("APP-01", "DB-01"), ("APP-02", "DB-02"))
    ]
    import_data(db, "relationships", json.dumps(relation_rows).encode(), "synthetic-relationships.json")
    obs = evidence(
        db, "SERVICE_OBSERVATION", "SYNTHETIC ExampleCorp fixture",
        "SYNTHETIC: nginx serves HTTPS on WEB-01; no actual host was scanned",
        {"port": 443, "protocol": "TCP", "synthetic": True},
    )
    installation = db.scalar(
        select(m.SoftwareInstallation).join(m.Software)
        .where(m.SoftwareInstallation.asset_id == assets["WEB-01"].id, m.Software.canonical_name == "nginx")
    )
    service = m.Service(
        asset_id=assets["WEB-01"].id, installation_id=installation.id, name="HTTPS", port=443,
        protocol="TCP", version="1.24.0", exposure="INTERNET_FACING", status="RUNNING",
        source="SYNTHETIC ExampleCorp fixture", evidence_id=obs.id, confidence="HIGH",
    )
    db.add(service)
    db.add(m.BusinessContext(
        asset_id=assets["DB-01"].id, business_owner="Synthetic Data Team", application="ExampleCorp demo",
        business_function="SYNTHETIC customer data", data_classification="RESTRICTED",
        evidence_id=assets["DB-01"].evidence_id, source="SYNTHETIC ExampleCorp fixture", confidence="HIGH",
    ))
    import_data(
        db, "sbom", (fixtures / "examplecorp-cyclonedx.json").read_bytes(),
        "examplecorp-cyclonedx.json", asset_id=assets["APP-01"].id,
    )
    db.add(m.Setting(key="demo_seed", value={"synthetic": True, "version": "1"}))
    db.flush()
    audit(db, "SYNTHETIC_SERVICE_SEEDED", service, reason="Explicit demo seed", asset_id=assets["WEB-01"].id)
    from app.services.engine import correlate

    result = correlate(db)
    return {"seeded": True, "synthetic": True, "assets": 9, **result}
