# RiskScope frontend integration

Run `npm run test`, `npm run typecheck`, `npm run lint` and `npm run build` from this directory. Vite proxies relative `/api` requests to the loopback backend; `VITE_API_PROXY` overrides its default address.

## Bounded report previews

Report creation, listing and detail return metadata only. The browser never reads an embedded report `snapshot` or fetches all rows to paginate locally.

- `GET /api/reports/{id}/summary` supplies captured dashboard totals, generation time, scope, disclaimer and assessment settings.
- `GET /api/reports/{id}/records/{dataset}?page=1&page_size=25` supplies only the selected immutable page. Changing dataset resets to page one. Inactive snapshot-page queries are immediately released so browsing does not accumulate the whole report in memory.
- The dataset selector supports resource keys except `reports`, including evidence, matches, installations, potential paths and verification history.
- Captured relation names are shown when available; otherwise record IDs are shown. The preview does not query live inventory for names. Explicit links open current records and are labeled accordingly.
- PDF, Markdown, JSON and dataset CSV downloads continue to use the server export endpoints. Downloads do not become browser application state.

The summary and record page have independent loading, empty and retryable error states. Tests verify bounded page requests, dataset changes, immutable labels, query-cache cleanup and continued export access when a preview request fails.
