# RiskScope

**Asset-Aware Vulnerability Exposure & Risk Prioritization Workstation**

RiskScope connects local asset and software inventory, SBOM dependencies, vulnerability snapshots, exposure observations and business context to explain what needs attention in *this* environment. Automated results, source evidence and analyst judgments remain separate.

This is a local analyst application, not a scanner, exploit framework, patch deployment system or security guarantee. All bundled ExampleCorp advisories, exploitation assertions and fixed versions are **explicitly synthetic fixtures**, not real advisories about nginx or any other product.

## Run locally

Prerequisites: Python 3.12+ and Node.js 20.19+ with npm. Dependency installation requires access to the Python/npm package registries; the installed application runs offline.

```sh
# Use the isolated worktree, not the main checkout.
cd /Users/triplea/Documents/CyberProjects/copilot-worktrees/RiskScope/mk23rd-turbo-broccoli
bash scripts/setup.sh
bash scripts/run.sh
```

The launcher selects a free loopback port and prints the actual URL. To choose a port explicitly:

```sh
PORT=8765 bash scripts/run.sh
```

The database is `.local/riskscope.db`; startup upgrades it with Alembic and never resets or seeds it. Stop the foreground process with Ctrl-C. Back up the database with SQLite's backup command/API, or stop the process before copying it. Do not expose this single-user workstation beyond loopback.

Open **Imports** to bring your own records into an empty workspace, or use the explicit **Load ExampleCorp** action for the synthetic demonstration. No provider networking is enabled. JSON and CSV imports are local files and never execute packages or scripts.

## Deploy to Vercel and Render

Use the included root `vercel.json` for the React frontend and `render.yaml` for the FastAPI backend. Set `VITE_API_BASE_URL` in Vercel to the actual Render HTTPS origin, and `RISKSCOPE_ALLOWED_ORIGINS` in Render to the exact Vercel frontend origin.

**Hosted mode has no sign-in and no permanent storage.** Each anonymous session gets a complete synthetic ExampleCorp demo plus a separate empty **My uploads** workspace. Visitors see explicit temporary-storage warnings, can download all sample datasets, and must acknowledge server processing before uploading.

Sessions expire after 60 minutes of API inactivity or four hours maximum, and may end sooner when Render sleeps/restarts. End session deletes both workspaces; reset affects only the selected one. Closing a tab does not guarantee immediate server deletion. Export results before leaving. Sensitive or large inventories belong in local mode.

See **[deployment setup, environment variables and limits](docs/deployment.md)** for the complete sequence, free-plan caveats and two-origin local testing. These files prepare deployment; they do not publish or provision anything automatically.

## Analyst workflow

1. Import or create assets, software and business/network context.
2. Import a CycloneDX/SPDX SBOM and local vulnerability feed.
3. Correlate, inspect matches and their observed version/rule/confidence.
4. Review exposure and exploitability observations; compare contextual risk factors.
5. Inspect **potential** paths backed by recorded relationships.
6. Assign remediation, set deadlines, review findings or record expiring acceptance.
7. Import the supported fixture upgrade or explicitly verify with attributed evidence.
8. Generate immutable technical/executive reports and download PDF, Markdown, complete JSON or CSV.

The same advisory's global exploitation intelligence applies to every asset. WEB-01 outranks WEB-02 through asset context, not by contradicting the advisory's known-exploitation flag. A separate synthetic advisory demonstrates no known exploitation.

## Development and checks

```sh
bash scripts/test.sh

# Backend alone
cd backend
../.venv/bin/pytest -q
../.venv/bin/ruff check app tests
../.venv/bin/alembic check

# Frontend alone, from repository root
npm --prefix frontend run test
npm --prefix frontend run typecheck
npm --prefix frontend run lint
npm --prefix frontend run build
```

For hot reload run the API on `127.0.0.1:8765` and the Vite development server in a separate terminal. Production setup serves the compiled UI from the same FastAPI origin. Local OpenAPI documentation is available at `/docs` (the API contract at `/openapi.json` works offline).

The real-HTTP acceptance workflow requires a **fresh isolated database**:

```sh
RISKSCOPE_DATABASE_URL="sqlite:///$PWD/.local/smoke.db" PORT=8766 bash scripts/run.sh
# In another terminal:
.venv/bin/python scripts/smoke.py http://127.0.0.1:8766
```

The smoke script refuses to overwrite a nonempty inventory. It exercises imports, observations, correlation, comparison, potential paths, remediation, new-version verification and all export formats.

Run the full bounded scale scenario:

```sh
.venv/bin/python scripts/scale_check.py --output .local/scale-results.json
```

It creates a separate retained database with 1,000 assets, 10,000 installations, 10,000 synthetic advisories and 50,000 asset relationships, correlates 50,000 vulnerability matches, and measures paginated API/dashboard/graph responses. It does not touch the normal workspace database.

## Documentation

- [Architecture](docs/architecture.md)
- [Data model](docs/data-model.md)
- [Risk model and uncertainty](docs/risk-model.md)
- [Import formats and limits](docs/import-formats.md)
- [Potential attack paths](docs/attack-paths.md)
- [Detection rules](docs/detection-rules.md)
- [Usage and verification](docs/usage.md)
- [Measured acceptance results](docs/validation.md)
- [Vercel / Render deployment](docs/deployment.md)
- [Original 81-section specification](docs/implementation-specification.txt)

## Dependencies and boundaries

FastAPI/Pydantic validate APIs; SQLAlchemy/Alembic manage SQLite persistence. Packaging supports explicitly declared Python version comparisons; defusedxml handles optional safe XML parsing. ReportLab generates actual local PDFs. React, TypeScript, Vite and Tailwind implement the workstation; Router provides navigation, TanStack Query manages server state, Recharts renders genuine snapshots, and Cytoscape renders bounded dependency/relationship graphs.

Remote NVD/OSV/CISA KEV/vendor integrations are extension points, not enabled or claimed working integrations. Unknown versions or unsupported ecosystem rules remain reviewable, not falsely confirmed. Graph discovery is bounded and cannot prove exploitation or exhaustive coverage.
