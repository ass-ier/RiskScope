# Vercel frontend + Render API

This deployment is an **anonymous, temporary analyst demo/testing service**. There is no sign-in, account database or permanent upload storage. The existing local mode remains persistent and offline-capable.

No deployment is performed by these files. Connect the repository and configure the following values in your own Vercel/Render accounts when ready.

## Deployment sequence

1. Choose/create your Vercel project and note its exact production origin, for example `https://your-project.vercel.app`.
2. In Render, create a Blueprint from this repository using root `render.yaml`. Set `RISKSCOPE_ALLOWED_ORIGINS` to that exact Vercel origin when prompted. The Blueprint builds the Python API and starts one worker using `scripts/render-start.sh`.
3. Copy the API's actual HTTPS `onrender.com` origin from Render. Confirm `/api/health` responds with `mode: hosted`.
4. In Vercel, use the **repository root** as Root Directory. Root `vercel.json` supplies the frontend install/build/output commands and SPA fallback. Set `VITE_API_BASE_URL` to the Render origin, without `/api` or another path. Deploy/redeploy the frontend after setting it.
5. If the actual Vercel production origin differs from step 1, update `RISKSCOPE_ALLOWED_ORIGINS` in Render and restart the API. Multiple approved origins use a comma-separated list. Do not use wildcard origins.

The frontend sends requests directly to Render, not through a Vercel Function, so its upload limit is governed by RiskScope rather than a serverless proxy's body limit. Allowed CORS headers cover the anonymous capability and selected workspace. Cookies and third-party-cookie access are not required.

`VITE_*` values are public build-time configuration. **Never put credentials in them.** There are no API keys, passwords or signing secrets required for anonymous sessions.

### Configuration files

| File | Purpose |
|---|---|
| `vercel.json` | Vite install/build/output, SPA route fallback, security headers |
| `render.yaml` | One native Python API instance, free plan, health check, explicit environment configuration |
| `scripts/render-start.sh` | Hosted mode, Render's `PORT`, one Uvicorn worker, no application access logs |
| `.env.example` | Backend configuration examples |
| `frontend/.env.example` | Public frontend API origin and optional local dev proxy |

The Vercel build fails if `VITE_API_BASE_URL` is missing. Its supplied CSP permits `onrender.com` API origins. For a custom API domain, update `connect-src` in `vercel.json` and the matching Vite build guard; also add that hostname to `RISKSCOPE_ALLOWED_HOSTS`. Render's standard hostname is read from `RENDER_EXTERNAL_HOSTNAME`.

No disk or Postgres service is provisioned. Automatic deploys are disabled in the Blueprint; deployments are operator-directed.

## What visitors experience

- First visit creates a cryptographically random anonymous session capability and opens a private copy of the full ExampleCorp synthetic environment.
- A visible banner says **Temporary session / No sign-in**, gives the inactivity/maximum lifetime, and warns that server sleep/restart can remove access sooner.
- Each session has two **separate SQLite databases**: `ExampleCorp · Synthetic demo` and `My uploads · Temporary`. Uploaded data does not overwrite the demo or another session's records.
- The Imports page directs visitors to My uploads. Before uploading, they must acknowledge that processing happens on the server and that storage is temporary.
- All six bundled synthetic asset/software/advisory/CycloneDX JSON/CycloneDX XML/SPDX JSON sample files are downloadable.
- Report and import-error downloads carry the session capability in an Authorization header, never in a URL.
- Reset restores only the selected workspace (seeded demo or empty uploads). End session revokes the capability and deletes both workspaces once in-flight requests finish.
- Expired sessions clear cached UI data and require an explicit new-session action. The application does not silently replace lost uploads with demo data.

This is not browser-only processing. Files are sent to Render and parsed records, evidence, reports and history are stored temporarily on that server. The original upload filename is metadata, never a server path. Imported packages and scripts are not executed.

## Retention and limits

Default hosted limits:

| Limit | Default |
|---|---:|
| Inactivity timeout | 60 minutes since the last authenticated API activity |
| Maximum session lifetime | 4 hours, regardless of activity |
| Concurrent sessions | 12 |
| New sessions | 30 per minute per process |
| Upload body | 2 MiB per file |
| Records/components per import | 1,000 |
| SBOM edges per import | 5,000 |
| Affected-version ranges per advisory import | 5,000 |
| SQLite size | 32 MiB per workspace |
| Correlation workload | 5,000 version-range checks; 5,000 combined assets/installations/advisories |
| Concurrent expensive operations | One per API worker; other attempts receive an explicit retry response |

Idle/expired sessions are cleaned up every 30 seconds and on session operations. Server shutdown cleans up the process-owned temporary directory. A crash can leave temporary files until the host discards its ephemeral filesystem; tokens are held only in process memory and cannot resume after restart.

Browser session storage normally belongs to a tab and survives reloads. Browsers may copy it when duplicating/restoring tabs; such tabs can share the same anonymous session. **Closing a tab is not a guaranteed immediate deletion signal.** End session is the explicit deletion control.

There are no backups or recovery accounts. Do not upload secrets, credentials or sensitive organizational inventories to a public deployment. Operators can access server storage, and hosting providers may retain infrastructure/access metadata under their own policies. Use local mode for confidential or large inventories.

Actor and owner names in an anonymous workspace are user-supplied labels, not authenticated identities.

## Render free-plan behavior

Render documents that free web services can spin down after 15 minutes without inbound traffic, take about a minute to wake, and lose filesystem changes on spin-down, restart or redeploy. These events may end sessions **earlier** than RiskScope's normal timeout. The UI explicitly discloses this and displays a recovery action instead of pretending lost data still exists.

Free services have resource/usage limits and no production-availability guarantee. Review Render's current pricing and limits before enabling a public deployment; the Blueprint does not authorize paid upgrades or guarantee zero charges under every account configuration.

## Single-process requirement

Use **one API worker and one Render instance**, as configured. The capability registry and temporary database leases are process-local. Do not enable autoscaling, multiple Uvicorn workers or a persistent disk without redesigning session routing/lifecycle.

A new deployment intentionally starts fresh sessions. No startup code reads, seeds, resets or deletes the normal local `RISKSCOPE_DATABASE_URL` when hosted mode is enabled.

## Local two-origin verification

Use free loopback ports; replace the examples if occupied:

```sh
# Terminal 1: API only, without changing the normal local database
RISKSCOPE_MODE=hosted \
RISKSCOPE_ALLOWED_ORIGINS=http://127.0.0.1:5174 \
.venv/bin/uvicorn app.main:app --app-dir backend \
  --host 127.0.0.1 --port 8767 --workers 1 --no-access-log

# Terminal 2: frontend, with direct cross-origin API requests
VITE_API_BASE_URL=http://127.0.0.1:8767 \
npm --prefix frontend run dev -- --port 5174 --strictPort
```

Open `http://127.0.0.1:5174`. Use a second browser profile/private window for an independent session. Confirm that uploads in one profile never appear in the other, that Demo/My uploads remain separate, and that exports work without cookies. End/reset a session and verify the explicit deletion/expiry messaging.

Automated checks:

```sh
cd backend
../.venv/bin/pytest -q tests/test_hosted.py
cd ..
npm --prefix frontend run test
npm --prefix frontend run typecheck
npm --prefix frontend run lint
```

## Official references

- [Vite on Vercel](https://vercel.com/docs/frameworks/frontend/vite)
- [Render FastAPI deployment](https://render.com/docs/deploy-fastapi)
- [Render Blueprint specification](https://render.com/docs/blueprint-spec)
- [Render free-service limitations](https://render.com/docs/free)
