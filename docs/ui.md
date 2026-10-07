# RiskScope frontend

The React 19 / TypeScript workstation uses Vite, Tailwind CSS 4, React Router, TanStack Query, Recharts and Cytoscape.js. No external fonts, remote intelligence calls, browser-only domain database or synthetic dashboard metrics are used.

## Run and validate

From the repository root:

```sh
npm ci --prefix frontend
npm run dev --prefix frontend
npm run test --prefix frontend
npm run typecheck --prefix frontend
npm run lint --prefix frontend
npm run build --prefix frontend
```

The development server binds to loopback. `/api` is proxied to `http://127.0.0.1:8765`; set `VITE_API_PROXY` when a different backend address is required. Production requests remain relative to `/api`, allowing the backend to serve `frontend/dist` on the same origin. The Vite production output preserves the design contract in `index.html`.

## Main investigation

1. **Imports** accepts assets, software, vulnerability JSON, relationships and CycloneDX/SPDX SBOM files. SBOM imports require a named owning asset. Row counts, warnings, rejected records and error CSV downloads are persistent API results. Imports are limited to 10 MiB. The explicit demo action adds synthetic ExampleCorp evidence.
2. **Assets** provides editable business/network context, inventory, software installations, services, risk, relationship management, source observations, notes and history.
3. **Software** preserves canonical products separately from original installation names, normalization confidence, versions and package identifiers.
4. **Vulnerabilities** separates global advisory intelligence from asset-specific exploitability. Affected ranges, known fixes, references and observations are editable.
5. **Correlate & update risk** invokes the actual engine and invalidates cached records. No frontend risk calculation is substituted.
6. **Risk register** supports search, sorting, filters and two-to-five-record comparison. Risk detail shows source observations, deterministic factor contributions, reasoning, uncertainty and analyst decisions independently.
7. **Review** records actor/reason and optional match-state or field overrides. **Accept risk** requires an approver, future expiry and compensating controls. **Verify** requires evidence and explicit analyst confirmation. Marking a task remediated is not verification.
8. **Attack paths** is a bounded, searchable/filterable graph with pan, zoom, fit, evidence and node/edge inspection. The accessible selector provides equivalent inspection without pointer use. An asset-surface view links to exposed, internal, critical and active-risk populations.
9. **Cases** persist linked risks/assets, notes and investigation state. **Remediation** persists action, owner, priority, due date and known fixed version.
10. **Reports** creates a persistent technical/executive snapshot with PDF, Markdown, JSON and four distinct CSV dataset downloads. Report previews are paginated and explicitly distinguish snapshot data from links to current records.
11. **Timeline/audit** exposes searchable paginated events and structured before/after inspection. **Settings** saves the full weight/rule configuration and recalculates on the backend. Optional provider cache state is read-only, not a simulated connection control.

Supporting resources are reachable through the “Evidence & supporting records” navigation group and contextual record links. All read resources have detail routes. All generic writable resources use `/api/meta` input schemas, not guessed model fields.

## API integration

- Lists use `{items,total,page,page_size}` with 25 rows per page; foreign-key selectors request 10 named results at a time and separately resolve their current selected record.
- Details use `/api/{resource}/{id}`. Core actions use the dedicated risk, import, correlation, report and settings endpoints.
- Generic writes include `actor` and `reason` query parameters. Input errors remain visible without discarding entered values.
- Risk tables use analyst-effective priority, severity, confidence, exposure and exploitability. Automated scores, factors and history remain unchanged.
- Graph IDs are opaque. Current backend `risk-*` vulnerability nodes link to risk assessments, while software nodes containing `software_id` link to their installation; canonical products and advisories are linked separately.
- Comparison queries are sent only with two to five valid IDs.

### Contextual join filters required from the API

These filters support detail sections without loading complete inventories into the browser. They are in addition to exact resource-column filters:

| Endpoint | Contextual filters |
|---|---|
| `/api/risk` | `software_id`, `sbom_id`, `overdue` |
| `/api/remediation` | `asset_id`, `vulnerability_id`, `case_id` |
| `/api/matches` | `software_id` |
| `/api/components` | `software_id` |
| `/api/attack-paths` | `asset_id` (including intermediate assets), `vulnerability_id` |

The independently implemented API must apply these filters server-side (SQL joins/subqueries) with the same pagination envelope. Unsupported filters are displayed as explicit errors, never silently ignored or replaced with unrelated records. The frontend does not modify backend files. Generic scalar filters such as evidence `ids`, observation `asset_id`, linked-case `case_id`, source/target relationship IDs and audit `object_type`/`object_id` use the common list contract.

## Accessibility, performance and operating constraints

The interface uses native semantic controls, a skip link, visible focus, labeled searches, paginated selectors, keyboard-scrollable tables, keyboard graph inspection, required verification confirmation and reduced-motion styling. The mobile drawer closes with Escape and returns focus. Errors explain backend connectivity or server validation; skeleton and guided empty states cover loading and unpopulated workspaces.

Cytoscape is loaded only on graph views. Reports and settings are separate route chunks. Domain records are server-persistent; TanStack Query is only an invalidated read cache. Snapshot reports intentionally contain a complete captured dataset but preview 25 rows at a time.

Vitest/Testing Library tests cover route rendering, API serialization/errors, metadata conversion, pagination/filtering, asset creation, rejected saves, analyst review, evidence-backed verification, restricted remediation statuses, imports, comparison and graph inspection. Browser/API integration and desktop/mobile visual inspection belong to the parent integration pass; unit tests do not claim to replace those checks.

Visual decisions and responsive dimensions are recorded in [`../DESIGN.md`](../DESIGN.md).
