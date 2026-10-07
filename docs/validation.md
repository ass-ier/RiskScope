# Acceptance evidence

Validated locally on 2026-10-07 with Python 3.12.11 and the checked-in dependency locks. No cloud service, paid API, scanner, LLM, deployment or GitHub publication was used.

## Mandatory phases

| Phase | Delivered behavior |
|---|---|
| Foundation | FastAPI/Pydantic, React/TypeScript, SQLite foreign keys/WAL, actual Alembic migration, local scripts |
| Asset management | Editable inventory, business context, network zones, services, directed relationships, source evidence |
| Software inventory | CSV/JSON ingestion, normalization provenance, stable installation identities, version observations |
| SBOM | CycloneDX JSON/XML, SPDX JSON, direct/transitive/unknown dependency classification, bounded graphs |
| Vulnerability engine | Local feed snapshots, ranges/fixes/references, conservative declared version schemes, separate match decisions |
| Exposure/exploitability | Explicit asset/service observations, global intelligence separated from asset-specific prerequisites |
| Risk | Deterministic configurable contributions, uncertainty/reasoning, current/history/effective assessments, comparison, non-CVE rules |
| Potential paths | Evidence-backed bounded cycle-safe discovery, graph inspection/filtering/zoom, relationship removal recomputation |
| Remediation | Assignments/deadlines, attributable review, acceptance expiry, false positives/deferrals, gated verification, reintroduction, cases/notes/audit |
| Reporting | Immutable technical/executive snapshots, real PDF/Markdown/complete JSON, four CSV datasets, server-paginated captured previews |
| Hardening | Bounded malformed-input handling, provenance/idempotency, safe XML/CSV, protected imports, pagination, tests and documentation |

## Automated checks

```sh
cd backend
../.venv/bin/pytest -q
../.venv/bin/ruff check app tests
../.venv/bin/alembic check
```

**126 tests passed**. Ruff passed. Alembic reported no new upgrade operations. The only warning is an upstream Starlette/httpx test-client deprecation, not a test failure.

```sh
npm --prefix frontend run test
npm --prefix frontend run typecheck
npm --prefix frontend run lint
npm --prefix frontend run build
```

**51 frontend tests passed**. Typecheck, ESLint and production build passed. Tests cover primary/detail routes, forms and errors, server pagination, imports, analyst decisions, verification, comparison, graph inspection and bounded immutable report pages.

Backend coverage includes exact contributions/ranking; numeric, SemVer and explicitly Python PEP 440 comparison boundaries; unsupported/ambiguous input; duplicate/malformed CSV/JSON/SBOM/XML; import limits and provenance; cycle/path bounds and deletion; global intelligence consistency; observation precedence; verification evidence identity/freshness; acceptance expiry; analyst overrides; retirement; all exports; and actual migrations.

## Real HTTP and browser workflow

`scripts/smoke.py` ran against a real loopback Uvicorn server and a fresh migrated database, not only a mocked client:

1. Imported four assets, two nginx installations, a three-component SBOM and a synthetic advisory.
2. Recorded network relationships, associated HTTPS service, business context, exposure and asset-specific exploitability evidence.
3. Correlated WEB-01 at **100 / CRITICAL**, versus WEB-02 at **63.2 / HIGH**, with the same global exploitation intelligence.
4. Discovered the potential WEB-01 -> APP-01 -> DB-01 path.
5. Assigned remediation, imported the supported **synthetic** version `1.26.2`, and correlated.
6. Recorded `VERSION_EVIDENCE` verification and synchronized remediation. WEB-01 became **0 / INFORMATIONAL**, active risks fell from **2 to 1**, and previous assessments/evidence remained available.
7. Generated technical/executive reports and successfully exported PDF, Markdown, complete JSON and risk/asset/vulnerability/remediation CSVs.

Actual Playwright browser interaction independently performed file uploads, SBOM asset selection, relationship and service forms, correlation, risk comparison, graph zoom/fit and evidence inspection, task assignment, upgrade import, verification inspection, report creation and all seven download links. Downloaded files were checked on disk, including a PDF signature and complete structured verification data.

Stopping/restarting the browser workflow server preserved all four imported assets and the verified risk. Startup did not reseed or reset data.

Desktop (1440 x 1000) and mobile (390 x 844) views were visually inspected in two bounded passes. Mobile navigation worked, document width remained 390 pixels, and tables scrolled within their regions. Browser console recorded **zero errors and zero warnings**. Mechanical design inspection returned no findings. A discovered graph-inspector provenance collision was fixed and regression-tested.

## Measured scale, not just pagination

`scripts/scale_check.py` creates an isolated database and runs full correlation before measuring API pages:

| Persisted entity | Count |
|---|---:|
| Assets | 1,000 |
| Software installations | 10,000 |
| Vulnerabilities | 10,000 |
| Asset relationships | 50,000 |
| Vulnerability matches | 50,000 |
| Risk assessments | 50,000 |
| Relational factors | 700,000 |

Final rules version: `1.1:25efa8bf48d52039`.

| Measurement | Observed |
|---|---:|
| Fixture population | 1.090 seconds |
| Full correlation and persistence | 38.355 seconds |
| Peak process RSS | approximately 469 MiB |
| Asset page, 25 records | 3.8 ms |
| Installation page, 25 records | 2.8 ms |
| Vulnerability page, 25 records | 2.8 ms |
| Relationship page, 25 records | 3.0 ms |
| Risk page, 25 of 50,000 | 6.5 ms |
| Dashboard | 663 ms |
| Bounded graph | 58.9 ms |

The browser scale check rendered exactly 25 risk rows, with requests returning 25 of 50,000 records. First page was observed at 134 ms and next-page interaction at 93 ms; no alert appeared. These are local observations, not portable performance guarantees.

The dense scale graph intentionally hit its 500-relationship and 4,000-expansion limits. It reported truncation and zero discovered paths, **not absence of paths**. Graph response size was about 829 KiB. The independent small fixture proves positive path discovery and disappearance on relationship removal.

## Retained local artifacts

Ignored `.local/` files retain HTTP/scale JSON results, browser exports and desktop/mobile screenshots. The retained full-scale database is approximately 1.4 GiB; its exact filename is recorded in `scale-results.json`. Duplicate benchmark databases were removed.

- `.local/riskscope.db`: browser-imported workflow, completed verification and report history.
- `.local/smoke-final.db`: separate final real-HTTP acceptance workspace.
- `.local/examplecorp-preview.db`: explicitly seeded nine-asset ExampleCorp preview, independent of imported workflow data.
- `.local/scale-results.json`: final measured scale result and database path.
- `.local/smoke-results.json`: complete real-HTTP workflow result.
- `.local/final-desktop-dashboard.png`, `.local/final-desktop-risk.png`, `.local/final-mobile-dashboard.png`: final visual evidence.
- `.local/browser-export-*`: actual browser-downloaded report formats.

The first demo load now refuses a nonempty inventory, so fixture data cannot overwrite existing records. Repeated demo loading is idempotent and preserves subsequent decisions.

## Deliberate optional boundaries

CycloneDX XML is implemented with safe parsing. Live NVD, OSV, CISA KEV and vendor network adapters are **not implemented or silently enabled**; provider interfaces and local cache metadata are present. Multi-user hosting/authentication, scanning, exploit execution and patch deployment are not part of this loopback-only workstation.
