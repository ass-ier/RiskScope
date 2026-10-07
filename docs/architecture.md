# Architecture

RiskScope is a single-user, loopback-only analyst workstation. The FastAPI process serves the built React application and a typed `/api` contract. SQLite is the only required datastore. No code path needs an LLM, cloud service, vulnerability scanner, or remotely executed command.

This describes the persistent **local mode**. Optional **hosted mode** places the frontend on Vercel and the API on Render, with anonymous, isolated temporary workspaces rather than a shared local database. See [deployment.md](deployment.md) for its separate lifecycle and limitations.

## Hosted session boundary

`core/config.py` validates mode, exact frontend origins and resource bounds. `services/guests.py` creates migrated empty/demo templates, clones separate databases for each guest's demo/uploads workspace, issues a random bearer capability, enforces leases/limits, and removes expired/reset workspaces. Tokens are hashed in the server registry and held in browser session storage, not cookies or URLs.

The existing `get_db` dependency chooses the authenticated guest database in hosted mode. Every inventory, risk, evidence, graph, import, report and workflow endpoint therefore uses the same isolation boundary; no client-supplied database filename is accepted. Local mode still uses its configured persistent SQLite database.

The frontend bootstraps runtime/session state before rendering data, clears caches on workspace/session changes, and authenticates blob downloads. Hosted mutation origins are exact allowlist matches; CORS does not use wildcard origins or credentials. SQLite page quotas and correlation/import bounds protect the anonymous worker. Hosted mode requires a single process and is not durable multi-user storage.

## Boundaries

- `app/models`: indexed relational entities and foreign keys.
- `app/schemas`: Pydantic v2 write DTOs, generated validated read DTOs, bounded settings and action requests.
- `app/services/imports`: local inventory, feed and SBOM ingestion with row provenance and validation.
- `app/services/engine`: conservative version correlation, contextual risk rules, potential paths and true historical snapshots.
- `app/services/workflows`: attributed analyst decisions, acceptance and verification.
- `app/services/reporting`: immutable report snapshots and PDF, Markdown, JSON and CSV rendering.
- `app/main.py`: paginated API orchestration, local-origin safety and frontend serving.
- `frontend`: React Router pages, TanStack Query server state, reusable resource forms, graph and chart views.

Observations and imported intelligence are inputs. Automated assessments are reproducible outputs, with previous assessments retained. Analyst overrides never overwrite automated priorities. Remediation is a separate workflow; neither inventory presence nor a status edit proves exploitation or proves a fix.

## Persistence and concurrency

Alembic owns schema creation and upgrades; startup does not seed or reset data. SQLite foreign keys, WAL and a five-second busy timeout are enabled on every connection. Mutations commit as a unit; malformed whole-file imports roll back. Row-level import failures are returned as durable import records. This local workload is not a multi-user service and is not intended to be exposed on a LAN.

## API and safety

See local `/docs` for the generated OpenAPI schema. Lists use `page`, `page_size` (maximum 100), `search`, validated `sort` and `order`, and exact column filters. JSON fields cannot be arbitrary filter expressions. SQLAlchemy bound parameters handle user values. Upload streams are bounded, filenames are metadata rather than storage paths, and imported content is never executed. CSV exports neutralize spreadsheet formula prefixes.

Browser writes reject non-loopback origins. Host validation protects against arbitrary hostnames. No remote fonts, analytics, scripts or provider requests are needed. The production build uses same-origin API requests. Optional feed-provider interfaces are documented; unimplemented remote adapters are not presented as working integrations.

## Scale boundaries

Correlation uses product-keyed candidates rather than all installations multiplied by all advisories. Graphs cap nodes and edges and visibly report truncation. Path discovery limits depth, expansion and output; it cannot claim complete attack-path coverage. Reports intentionally export complete immutable structured snapshots, unlike bounded interactive lists. Run `scripts/scale_check.py` to measure the specified local dataset on the current machine.
