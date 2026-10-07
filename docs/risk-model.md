# Risk model

RiskScope is an offline, evidence-driven prioritization workstation, **not a scanner or an exploit validator**. A score is a deterministic prioritization aid, not a probability of compromise. Observations, automated interpretations, and analyst decisions remain separate.

## Applicability before priority

Candidates are indexed by conservatively normalized product name. Different explicit vendors or ecosystems do not match. Missing vendor identity produces a potential association, not a confirmed finding. Case and whitespace are normalized; the only special product aliases are `Nginx`, `nginx web server`, and numeric `nginx/<version>`, which map to `nginx`. A version is **never extracted** from the product name.

Version schemes:

| Declared scheme | Supported comparison |
|---|---|
| `generic`, `numeric`, `numeric-dotted` | Numeric dotted versions and comma-separated `>=`, `>`, `<=`, `<`, `==`, `=`, `!=` comparisons. Bare numeric versions mean equality. Trailing zero segments compare equally. |
| `semver` | Stable, three-part numeric SemVer only, with the same explicit comparisons. No leading zeros. Prereleases, build metadata, wildcards, caret/tilde and OR syntax require review. |
| `pep440`, `python` | `packaging.version.Version` and `SpecifierSet`, **only when the installation ecosystem is explicitly `python`**. Python prerelease matching follows `packaging` semantics. |
| Anything else | Unknown; no lexical fallback or inferred ecosystem. |

Missing versions, vendor suffixes in generic versions, unsupported ranges, and ambiguous identities retain `NEEDS_REVIEW` or `POTENTIAL`. A supported true range establishes applicability; otherwise **one unknown alternative prevents a collection of ranges from being called unaffected**.

Each match records its automated state (`CONFIRMED`, `POTENTIAL`, `NEEDS_REVIEW`, or `REJECTED`), affected tri-state, method, observed version, rule text, confidence, and evidence IDs. An analyst's `analyst_state` and reason are separate and survive correlation.

## Exact score

The vulnerability score is the sum below, rounded to two decimal places and clamped to 0–100. The defaults come from `SettingsInput`; saved settings use the `risk` key (`risk_engine` is also accepted when `risk` is absent). Every factor includes its value, points, reasoning and evidence IDs.

Applicability gates the score: once valid verification and supported version evidence establish that the advisory no longer applies, every current contribution becomes zero and an explicit `VERIFIED_NOT_AFFECTED` factor explains the suppression. The current priority is INFORMATIONAL, while prior scored assessments remain in history. An analyst-only verification of a still-affected version does not rewrite the automated assessment.

| Factor | Default weight | Contribution |
|---|---:|---|
| `cvss` | 3 | CVSS score × weight; unknown contributes zero with uncertainty |
| `known_exploitation` | 18 | Full weight only when source explicitly says true |
| `exploit_available` | 6 | Full weight only when source explicitly says true |
| `exposure` | 16 | Weight × asset exposure multiplier below |
| `criticality` | 14 | Weight × maximum of asset criticality and data-classification multiplier |
| `production` | 6 | Production: full weight; staging: one third; other/unknown: zero |
| `service` | 4 | Weight × strongest **running, explicitly installation-linked** service multiplier |
| `privileges` | 3 | Required privileges NONE: full; LOW: half; HIGH/UNKNOWN: zero |
| `complexity` | 3 | Attack complexity LOW: full; HIGH/UNKNOWN: zero |
| `path` | 6 | Full weight if at least one current potential path reaches another critical asset; never multiplied by number of paths |

Asset exposure multipliers: `INTERNET_FACING=1`, `EXTERNALLY_REACHABLE=.75`, `INTERNAL_ONLY=.15`, `RESTRICTED=.05`, `ISOLATED=0`, `UNKNOWN=0`.

Criticality multipliers: `CRITICAL=1`, `HIGH=.75`, `MEDIUM=.4`, `LOW=.1`, `UNKNOWN=0`. Business data classification contributes a floor of `.75` for `RESTRICTED`, `.5` for `CONFIDENTIAL`, and zero otherwise. Both supporting observations are visible.

Service multipliers: internet-facing `1`, externally reachable `.75`, internal `.25`, restricted `.1`, isolated/unknown `0`. Unassociated, STOPPED, REMOVED, and unknown-state services contribute nothing. Retained service exposure observations remain historical after retirement and never become asset-wide observations. Asset exposure is **not copied onto a service**. For eligible running services, the latest service-level exposure observation wins over the service inventory field; asset-level exposure works the same way. IP addresses never imply exposure.

Privilege/complexity observations specific to an asset and vulnerability take precedence when explicitly known; otherwise vulnerability metadata is used. Asset reachability, exploit maturity, user interaction and source-listed fixed versions are visible zero-point factors. A `BLOCKED` asset-specific reachability observation suppresses path starts, but does not rewrite the global known-exploitation flag.

Priority thresholds:

| Score | Priority |
|---:|---|
| ≥80 | CRITICAL |
| ≥60 | HIGH |
| ≥35 | MEDIUM |
| ≥15 | LOW |
| <15 | INFORMATIONAL |

CVSS severity remains separate: ≥9 critical, ≥7 high, ≥4 medium, positive scores below 4 low, zero informational, missing unknown. Unknown intelligence never becomes “no known exploit.” `NO_KNOWN_EXPLOIT` is used only when both exploitation and exploit-availability flags are explicitly false.

`remediation_available` reports only source-listed versions and recommendations, not invented patch guidance. Unknown inputs contribute no unsupported points and produce uncertainty text; a low score with unknown evidence is **not an assurance of safety**.

## Reproducible synthetic comparison

**All ExampleCorp assets, software relationships, CVSS values, exploitation flags, fixed versions and advisories are fictional test data. They do not assert a real vulnerability in nginx or another product.**

The bundled `SYNTH-EXAMPLE-001` has synthetic CVSS 9.8 and synthetic known exploitation on **both** WEB-01 and WEB-02:

* WEB-01: critical production, internet-facing, associated HTTPS service, potential route via APP-01 to DB-01. Contributions `29.4 + 18 + 6 + 16 + 14 + 6 + 4 + 3 + 3 + 6 = 105.4`, clamped to **100 / CRITICAL**.
* WEB-02: low-criticality development, internal-only, no associated exposed service or path. Contributions `29.4 + 18 + 6 + 2.4 + 1.4 + 0 + 0 + 3 + 3 + 0 = 63.2 / HIGH`.
* WEB-01 / `SYNTH-EXPOSED-075`: CVSS 7.5, known exploitation, unknown public exploit, no linked service. **88.5 / CRITICAL**.
* LAPTOP-01 / `SYNTH-LAB-098`: CVSS 9.8, explicit synthetic false exploitation flags, isolated low-criticality lab. **36.8 / MEDIUM**.

The lower-CVSS exposed finding outranks the high-CVSS isolated finding. The ordering is explained by actual factors, not different global intelligence for the same vulnerability.

## Assessments, decisions, and history

Correlation keeps current JSON factors and relational `RiskFactor` rows, plus an `AssessmentHistory` snapshot containing `automated`, `effective`, and `assessed_at`. The rules version is `1.1:<16-character SHA-256 prefix of sorted settings JSON>`. Setting changes therefore produce different reproducibility identifiers.

Analyst priority, severity, confidence, exposure and exploitability overrides apply to the effective result; current assessment columns retain the automated values, with `analyst_override` kept separately. Historical snapshots include both interpretations, and snapshot counts apply the effective priority. Analyst explanations, rejected matches, accepted risks, false positives and deferred risks are not reset by correlation. User-created non-CVE findings are not deleted: `rule_key="manual"` receives documented [severity-and-context scoring](detection-rules.md#manual-non-cve-priority) while preserving the supplied finding metadata and lifecycle choices.

Active risk statuses are **OPEN, ASSIGNED, IN_PROGRESS, REMEDIATED**. REMEDIATED remains active until verified. VERIFIED, RISK_ACCEPTED, FALSE_POSITIVE and DEFERRED are excluded. Expired acceptance records are marked expired and audited. Only the latest acceptance (creation time, then ID) controls reopening of a still-accepted risk and its still-accepted remediation tasks: an older expiry cannot reopen a currently valid acceptance, and an older future expiry cannot extend a newer acceptance that has expired.

Snapshots persist counts at actual application execution time; no backdated demo trend is generated. Priority counts and open counts use the same active statuses. The remediated metric includes REMEDIATED and VERIFIED. Overdue counts distinct active risks having an overdue risk due date or active remediation due date, not a duplicate count of their tasks. New-risk counts derive from records created since the previous persisted snapshot.

Dashboard, filters, snapshots and reports share one overdue predicate. A date-only deadline remains due through that UTC calendar day; an explicit timestamp is overdue after that instant. Multiple overdue tasks for one active risk count once. Historical/inactive risks never contribute to this queue.

## Verification and reintroduction

Changing a status to REMEDIATED is **not verification**. Automatic version verification requires:

1. A previously positively affected match.
2. A changed version in a fresh SOFTWARE_INVENTORY or SBOM evidence record whose observed version agrees with the installation; software-inventory evidence must also identify the asset. Unrelated notes, older observations, or inconsistent evidence cannot auto-verify.
3. Every applicable range evaluated as false, with no unknown identity/range alternative.
4. Supported source-listed fixed-version metadata that is itself outside the affected range, and a supported comparison showing the new version is at least that fixed version.

The synthetic fixture's exact fixed version is `1.26.2`, not `1.26.x`. A vendor-suffixed or wildcard version requires review. A source-metadata change alone does not verify remediation.

The engine creates `RemediationVerification` with before/after versions, supporting evidence, and method `VERSION_EVIDENCE`, audits the transition, stores `verified_version`, and updates active remediation tasks. A later fresh observation of a different affected version reopens a verified risk and its verified/remediated tasks. Reimporting the same analyst-verified version does not reopen it. Explicit analyst verification is a separate API workflow.

A fresh, different version with unsupported/unknown applicability also reopens review, without claiming it is affected. Verification of a previous version is not evidence that an unrecognized new build is safe.

## Operational bounds

Correlation preloads indexed entity maps and groups affected ranges by canonical product; it does not test every installation against every vulnerability. Match/risk inserts and assessment factors/history/audit events use bounded 200-record batches, not per-factor writes. Large assessment JSON fields are deferred while building maps and released after each persisted assessment batch. Snapshots read only the columns needed for counts. Reassessment audit before-values capture the prior score, priority, status, confidence, exposure, exploitability, evidence and rules version; complete prior factors remain in immutable assessment history.

Graph discovery has independent edge, depth, result-count and expansion limits. All service functions use the caller's SQLAlchemy transaction and never commit.
