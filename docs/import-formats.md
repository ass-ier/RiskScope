# Local import formats

Imports parse observations, not executable content. RiskScope does **not** fetch package URLs, read imported filesystem paths, run scripts, install packages, execute binaries, or access a network. Filenames are reduced to a display basename and never used as output paths.

All bundled ExampleCorp data is **SYNTHETIC**. Documentation-only reference URLs such as `example.invalid` are not fetched or represented as real advisories.

## API/service contract

`import_data(db, kind, data: bytes, filename, asset_id=None)` returns an `ImportJob`. Kinds are `assets`, `software`, `vulnerabilities`, `relationships`, and `sbom`. The caller commits or rolls back.

Whole-file malformed input, unsupported formats, size/complexity failures, and structurally invalid SBOMs raise `ValueError`. They do not create a success-shaped import. Ordinary inventory/feed row validation failures are retained as `ImportRecord(status="REJECTED", error=...)`; other valid rows can import. Jobs expose `processed`, `imported`, `skipped`, `rejected`, `warnings`, filename and SHA-256 digest. `processed = imported + skipped + rejected`. A mixed-result job has `COMPLETED_WITH_ERRORS`.

Unchanged records are counted as skipped, but inventory observation/evidence and provenance are refreshed. A changed software version updates the same installation, its last-seen timestamp and evidence rather than adding a duplicate. First-seen is preserved. Every row, including a rejected row, has a provenance trail; every successful job is audited. Asset fields omitted from a subsequent partial inventory do not erase previously observed context.

The installation identity is `(asset_id, canonical software identity, package_identifier)`. Canonical software identity includes product, vendor and ecosystem. Use stable package identifiers when identifying multiple installations. Version changes in the `version` field alone update an installation.

Limits:

* Nonempty UTF-8 input, at most **10 MiB** (`MAX_UPLOAD_BYTES`).
* At most 50,000 inventory/feed rows, 100 CSV columns, and 20,000 characters per field.
* JSON/XML at most 200,000 nodes and 32 levels of nesting.
* SBOM at most 5,000 components and 20,000 dependency entries; dependency traversal depth at most 32.
* Duplicate JSON keys, NaN/Infinity, duplicate CSV headers, malformed quoted CSV, and inconsistent CSV row widths are rejected.
* XML uses `defusedxml`, forbidding DTDs, entities and external resources.
* Unknown DTO fields are row errors, rather than silently discarded fields.
* Documented enum fields accept straightforward uppercase normalization, e.g. `production` → `PRODUCTION`. No inference turns missing/unknown data into false or safe.

## Assets: CSV or JSON

```csv
hostname,ip,os,environment,criticality,owner,exposure
WEB-01,192.0.2.10,Linux,production,critical,Synthetic Platform Team,INTERNET_FACING
WEB-02,192.0.2.11,Linux,development,low,Synthetic Development Team,INTERNAL_ONLY
```

Equivalent JSON can be a nonempty array, or exactly `{"assets": [...]}`:

```json
[
  {
    "hostname": "WEB-01",
    "ip": "192.0.2.10",
    "os": "Linux",
    "environment": "PRODUCTION",
    "criticality": "CRITICAL",
    "owner": "Synthetic Platform Team",
    "exposure": "INTERNET_FACING",
    "confidence": "HIGH",
    "tags": ["SYNTHETIC"],
    "description": "Fictional example; not a real observation."
  }
]
```

`hostname` is required and unique (case-sensitive; no unrequested hostname merging). Optional fields follow `AssetInput`: IP, MAC, OS/version, environment, owner, business unit, location, criticality, exposure, existing zone ID, tags, description and status. CSV `tags` must be a quoted JSON array, not a guessed delimiter-separated list.

## Software: CSV or JSON

Import assets first. Required fields are `hostname` and `product`; missing version is retained as unknown.

```csv
hostname,product,vendor,version,ecosystem
WEB-01,Nginx,nginx,1.24.0,generic
WEB-02,nginx web server,nginx,1.24.0,generic
```

```json
{
  "software": [
    {
      "hostname": "WEB-01",
      "product": "nginx/1.24",
      "vendor": "nginx",
      "version": "1.24.0",
      "ecosystem": "generic",
      "architecture": "x86_64",
      "package_identifier": "",
      "installation_source": "Synthetic inventory",
      "lifecycle": "SUPPORTED",
      "confidence": "HIGH"
    }
  ]
}
```

Original name, canonical name, normalization method and confidence are retained. The numeric suffix in `nginx/1.24` is **not a version observation**; without a separate version field applicability requires review. Vendor and ecosystem comparison is trimmed/case-insensitive. No vendor is guessed from the product. A known range vendor against a missing installation vendor is potential, not confirmed. `END_OF_LIFE` is explicit supplied lifecycle metadata, never inferred from a version number.

## Vulnerabilities: JSON snapshots

Use a nonempty array or the following exact envelope. `source` and `version` identify the local provider cache; they do not cause network access.

```json
{
  "source": "SYNTHETIC local demonstration",
  "version": "1",
  "vulnerabilities": [
    {
      "identifier": "SYNTH-EXAMPLE-001",
      "title": "SYNTHETIC nginx applicability example",
      "description": "Fictional range, score, exploitation flag and fixed version.",
      "cvss_score": 9.8,
      "cvss_version": "3.1",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "known_exploited": true,
      "exploit_available": null,
      "exploit_maturity": "UNKNOWN",
      "attack_complexity": "LOW",
      "privileges_required": "NONE",
      "user_interaction": "NONE",
      "recommendation": "SYNTHETIC demo only: record version 1.26.2 and correlate again.",
      "synthetic": true,
      "confidence": "HIGH",
      "affected_ranges": [
        {
          "product": "nginx",
          "vendor": "nginx",
          "ecosystem": "generic",
          "version_scheme": "generic",
          "affected": ">=1.20,<1.26.2",
          "fixed_versions": ["1.26.2"]
        }
      ],
      "references": []
    }
  ]
}
```

Optional vulnerability fields also include `cwe`, `published_at`, `modified_at`, `source`, and `evidence_id` from the write DTO. Import provenance always points to the actual local import observation; raw submitted source/evidence fields remain in import evidence instead of being trusted as the imported observation's provenance.

Ranges and references become separate related models. Reimport by identifier updates metadata and replaces removed range/reference entries without deleting analyst decisions. No affected ranges is accepted with a warning and cannot establish applicability.

Reference objects have exactly `{"label":"Supplier advisory","url":"https://supplier.example/advisory"}`. Only absolute HTTP(S) URLs with a hostname and without embedded credentials are accepted. A reference is source-supplied, not fetched or verified by the importer. Do not label invented URLs as genuine advisories.

`known_exploited` and `exploit_available` are separate nullable booleans. `null` means unknown, not false. Synthetic facts must set `synthetic: true` and label their source/title clearly.

## Relationships: CSV or JSON

The endpoints must be existing numeric asset IDs:

```json
[
  {
    "source_asset_id": 1,
    "target_asset_id": 3,
    "type": "CONNECTS_TO",
    "description": "SYNTHETIC: explicit application connection observation",
    "confidence": "HIGH"
  }
]
```

CSV columns are `source_asset_id,target_asset_id,type,description,confidence`. The unique key is source, target and relationship type. Import provenance becomes network-observation evidence. Relationship direction is preserved. Merely sharing a subnet, IP range or zone never creates an edge.

## SBOM: CycloneDX JSON/XML and SPDX JSON

A supplied **existing `asset_id` is mandatory**. Full examples:

* `fixtures/examplecorp-cyclonedx.json`
* `fixtures/examplecorp-cyclonedx.xml`
* `fixtures/examplecorp-spdx.json`

CycloneDX JSON requires `bomFormat: "CycloneDX"`, `specVersion`, and a nonempty `components` array. A `metadata.component` becomes the root application when supplied. Component fields include `bom-ref`, `name`, `version`, `supplier.name` or `publisher`, `purl`, hashes and licenses. Dependencies are explicit `{"ref":"application","dependsOn":["library"]}` objects. Nested component containment is imported but is **not silently turned into dependency reachability**.

SPDX JSON requires `spdxVersion` beginning `SPDX-` and nonempty `packages`. Packages use `SPDXID`, `name`, `versionInfo`, `supplier`, checksums, license fields and package-manager purl external references. `documentDescribes`/document `DESCRIBES` identify roots; `DEPENDS_ON` and reversed `DEPENDENCY_OF` create graph edges. Other relationship types are recorded as import warnings, not guessed dependencies.

Duplicate component references, duplicate dependency edges and dangling component/root references are errors. Cycles are accepted with a warning and traversed with visited-state guards. Dependencies are not proof of exploitability.

Every component, including root and transitive components, creates or updates an installation so transitive vulnerability correlation is possible. Purl type `pypi` maps to explicit `python` ecosystem; other purl types remain named ecosystems. Purls are stored in full on components. Installation identifiers omit purl versions for stable reimport; multiple components sharing the same logical package get a reference discriminator so simultaneous versions are not collapsed.

Direct dependencies of a known root have `direct: true`; reachable deeper dependencies have `direct: false`; components whose relationship to a root is unknown have `direct: null`. No declared root/graph means unknown, not an invented transitive/direct classification.

SBOM imports are idempotent by **asset ID plus document digest**. Reimporting the identical document for the same asset adds a skipped job trail, not duplicate components. The same document may be imported for another asset.

## Providers and explicit demo loading

`LocalJSONProvider` accepts bytes already available locally and stores cache source, version, digest and observation time. `VulnerabilityProvider`, `ExploitProvider` and `ThreatIntelProvider` protocols permit future adapters. NVD, OSV and CISA KEV adapters are explicitly disabled/unimplemented; requesting them raises a clear error and never performs networking.

`demo(db)` explicitly seeds ExampleCorp and runs correlation once. It is never a startup action. A seed marker makes repeated requests idempotent, preserving later analyst changes and remediation observations. The seeded historical counts are real application events, not fabricated history.

The first demo load requires an empty inventory. If assets, software, vulnerabilities or SBOMs already exist, it refuses without changing them; use a separate database for the demonstration. Repeated loads of an already-marked demo preserve its subsequent history.

The demo's canonical hostnames are `WEB-01`, `WEB-02`, `APP-01`, `APP-02`, `DB-01`, `DB-02`, `DC-01`, `FILE-01`, and `LAPTOP-01`. API hostname searches use these exact hyphenated names. Existing seeded workspaces are not silently renamed or reseeded.
