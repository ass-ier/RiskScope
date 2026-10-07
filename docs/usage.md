# Using RiskScope

## Start with an empty workspace

Run `bash scripts/setup.sh`, then `bash scripts/run.sh`. The terminal prints a loopback URL. Nothing is seeded automatically. Import local CSV/JSON assets, software and advisory snapshots from Imports, or enter records through the corresponding data page.

In hosted mode, the app opens a temporary copy of the synthetic demo automatically. Use the visible Workspace selector to switch to **My uploads**; the two datasets are separate. Uploads require acknowledgement of temporary server processing. Download reports before the session expires, the server sleeps/restarts, or you reset/end it. There is no sign-in or recovery account. [Hosted details](deployment.md).

Every import shows processed, imported, skipped and rejected counts. Inspect rejected rows and download the error CSV. Imported filenames are labels, never paths written by the server. Correct the file and import again; identical records do not multiply.

## ExampleCorp

Load the synthetic demonstration explicitly. WEB-01 is production, critical and internet-facing; WEB-02 is development, low criticality and internal-only. Both run the same nginx fixture version and inherit the same advisory's global exploitation intelligence. All exploit assertions and supported versions in this dataset are fictional demonstration metadata.

Inspect the risk factors side-by-side. The reason WEB-01 comes first is asset context. The recorded WEB-01 -> APP-01 -> DB-01 relationships support a **potential** path, not a claim of actual compromise.

## Evidence and decisions

Evidence records capture source, type, content, confidence and attribution. Exposure must come from explicit inventory or observations, never an IP-address guess. Asset-specific exploitability observations describe prerequisites or reachability; they do not change global vulnerability intelligence.

The risk detail keeps automated factors and priority separate from analyst overrides. Reviews, priority/severity/confidence/exposure/exploitability overrides, rejection and deferral require an attributed reason. Recorrelation preserves decisions and history. Clear an override explicitly to return to the automated recommendation.

Create cases, link assets and risks, add notes and move cases through investigation, remediation, verification and closure. Timeline and audit views show what changed and retain previous/new values.

## Remediate and verify

Create a task with action, owner, priority and due date. A fixed-version recommendation must exist in the advisory metadata. A status of REMEDIATED means work was reported; it is not proof of a fix.

Two verification routes exist:

- Import genuinely newer affected-version evidence that demonstrates the installation is no longer in a supported affected range, then correlate. The original affected match and new inventory evidence are retained in a before/after verification.
- Explicit analyst verification, with an identified actor, reason and evidence record, such as a documented vendor backport. This is clearly labeled analyst verification rather than an automated version conclusion.

For the nginx fixture, import version `1.26.2` for WEB-01 and correlate. This is a supported **fixture** version, not real patch advice. Reintroducing the affected fixture version reopens the risk instead of keeping stale verification.

Acceptance requires an approver, reason, future timezone-aware expiry and compensating controls. Accepted, deferred, rejected and verified risks remain visible in historical records but are excluded from active queues. Expired acceptance reopens the risk. Acceptance is never a permanent hide operation.

## Reports and trends

Generate a technical or executive report. Each is an immutable snapshot including retained historical risks. Download actual PDF or Markdown, complete structured JSON, or a risk/asset/vulnerability/remediation CSV. Spreadsheet formula prefixes in CSV cells are escaped.

Dashboard trends come only from real application snapshots. A new workspace has no invented trend. An empty historical chart is expected until assessments have run.

## Settings and graphs

Risk weights and bounded path settings change actual calculations. Changes produce a new rules-version fingerprint and new assessment history. Non-CVE lifecycle/configuration rule toggles affect rule output. Unknown context stays visible as uncertainty.

Graphs support pan, zoom, filtering and selection. Selecting a relationship shows its source data and evidence. A truncation notice means only a bounded subgraph is displayed; refine filters or inspect records through paginated tables. Removing a relationship recomputes potential paths.
