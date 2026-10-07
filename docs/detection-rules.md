# Evidence-backed detection rules

RiskScope's broader domain includes non-CVE lifecycle, configuration and asset-governance findings. Rules operate only on supplied observations; no scanner, package execution or external intelligence call is involved.

All automated detection rule keys begin `auto:`. Parent-API manually created findings use `rule_key="manual"`: their contextual priority is calculated without overwriting their title, supplied severity, confidence, evidence, recommendation, or analyst lifecycle decisions. Other custom rule keys remain untouched.

## Manual non-CVE priority

Explicit manual findings start with severity points: `CRITICAL=80`, `HIGH=60`, `MEDIUM=35`, `LOW=15`, `INFORMATIONAL=0`. This is **analyst-supplied severity**, not an inferred CVSS score.

Correlation adds the configured asset-exposure, business-criticality and production contributions documented in [risk-model.md](risk-model.md), rounds to two decimals, and clamps the result to 0–100. Business data classification provides the same restricted/confidential floor as for vulnerability findings. Staging contributes one third of the production weight. No exploitation, affected-service or path points are inferred for a manual finding.

For example, a manually recorded HIGH finding on an internet-facing lab asset with unknown criticality receives `60 + 16 = 76 / HIGH` under default settings. Setting the exposure weight to zero changes its automated score to 60. Unknown context is explicitly noted.

Manual scoring runs regardless of the automatic configuration/lifecycle rule toggles. Factors, source evidence, automated/effective history, and audit events are persisted. Accepted, deferred, false-positive and verified statuses remain unchanged; effective analyst overrides remain separate from the automated calculation.

## Rules

| Rule key | Required evidence | Category | Base points | Recommendation |
|---|---|---|---:|---|
| `auto:missing-owner` | Active asset inventory with empty owner | ASSET_RISK | 15 | Assign an accountable owner |
| `auto:unknown-criticality` | Active asset inventory explicitly lacking known criticality | ASSET_RISK | 20 | Classify business criticality with the owner |
| `auto:internet-admin:<service-id>` | Running service explicitly named SSH/OpenSSH, Telnet, RDP/Remote Desktop, VNC or WinRM on its corresponding conventional port; explicit internet/external service exposure and service/exposure evidence | EXPOSURE | 35 | Restrict administrative access and require strong authentication |
| `auto:unencrypted-service:<service-id>` | Running service with explicit name `telnet`, `ftp` or `http` on a corresponding conventional port 23, 21 or 80, plus service evidence | CONFIGURATION | 25 | Verify protocol and require encrypted transport |
| `auto:end-of-life:<installation-id>` | Installation of software with supplied `END_OF_LIFE` lifecycle and supporting lifecycle evidence | SOFTWARE_LIFECYCLE | 25 | Replace/upgrade according to supplier lifecycle guidance |

The unencrypted-service rule is deliberately described as **potential**. A port/name observation cannot prove the absence of encryption, a TLS terminator, or compensating controls. Only `RUNNING` services are eligible: `STOPPED`, `REMOVED`, and unknown states contribute no service points and trigger no current service rules. Retirement retains the service and its observations as history; service-scoped exposure is never promoted to an asset-wide exposure observation.

There are no inferred unsupported-OS dates, guessed support deadlines, presumed weak segmentation, or fabricated vendor fixed versions. Such findings can instead be created explicitly by an analyst with evidence.

## Scores and lifecycle

Each rule adds its base points to the configured criticality contribution and production contribution (full production weight for `PRODUCTION`, otherwise zero). Exposure and configuration service rules additionally add the configured exposure contribution using that service's latest explicit exposure. Multipliers are documented in [risk-model.md](risk-model.md).

Lifecycle findings are capped at **59**, so end-of-life status alone cannot automatically produce a HIGH or CRITICAL finding. Automated rule severity is the base-point priority; effective priority includes context. Unknown exploitability remains explicit. Each rule has relational factors, reasoning, evidence and history just like a vulnerability risk.

`configuration_rules` controls the first four rules; `lifecycle_rules` controls unsupported software. Both default to true.

If a rule is disabled or its condition is no longer observed, its active finding is deferred with an audit explanation, **not automatically verified or deleted**. The historical finding remains available. Accepted, deferred, false-positive and verified analyst dispositions are preserved; detecting the condition again does not silently discard an analyst's decision. Use the analyst workflow to reopen/review such a finding.

## Applicability and intelligence guardrails

* Product matching is conservative and does not guess versions from names.
* Unknown comparison semantics remain `NEEDS_REVIEW`.
* Explicit vendor/ecosystem conflicts do not match.
* Global known exploitation and public exploit availability are independent nullable facts.
* A package in an SBOM can establish presence, not exposed-service association or exploitability.
* Only an actual service installation foreign key links that service to the affected installation.
* An IP address, shared network zone or high CVSS score does not establish internet exposure.
* Recommendations use source metadata or the deterministic rules above. No invented CVE, advisory, exploit, fixed version or exploitation claim is presented as real.

The complete synthetic fixtures label all demonstration facts as fictional. Tests assert exact contributions and ranking, not merely a final “high” label.
