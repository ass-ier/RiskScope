# Data model

All entities have numeric IDs and created/updated UTC timestamps. Inventory and observations include source, confidence, evidence and import-job references. The checked-in Alembic revision creates the actual tables, foreign keys, uniqueness constraints and indexes.

| Area | Entities and important links |
|---|---|
| Inventory | Asset -> NetworkZone; BusinessContext -> Asset; AssetRelationship -> source/target Asset; SoftwareInstallation -> Asset + Software; Service -> Asset + optional Installation |
| SBOM | SBOM -> Asset; SBOMComponent -> SBOM + Installation; Dependency -> source/target Component, SBOM, Evidence |
| Intelligence | Vulnerability; AffectedRange -> Vulnerability; VulnerabilityReference -> Vulnerability; local ProviderCache metadata |
| Observations | ExposureObservation -> Asset + optional Service; ExploitabilityObservation -> Asset + Vulnerability; Evidence -> optional ImportJob |
| Correlation | VulnerabilityMatch -> Installation + Vulnerability + Range; unique installation/advisory pair; observed version/rule/method/confidence/evidence and separate analyst state |
| Assessment | RiskAssessment -> Asset + optional Vulnerability/Match; RiskFactor and AssessmentHistory -> Risk; AttackPath -> Risk + entry/target Assets, ordered relationship/evidence IDs |
| Workflow | Remediation, RemediationVerification, RiskAcceptance -> Risk; acceptance expiry is not deletion; verification retains before/after and attributed evidence |
| Investigation | Case; CaseAsset; CaseRisk; AnalystNote linked to case, risk or asset |
| History | TimelineEvent, AuditEvent (before/after/reason/actor), RiskSnapshot (actual assessment counts), ImportJob, ImportRecord, immutable Report |

JSON is used for structured factor snapshots, imported hashes/licenses, path sequences and audit payloads, not in place of relational entity links. A report includes complete structured copies of the underlying entities as they existed when generated.

Global vulnerability exploitation intelligence belongs to the Vulnerability. Asset-specific reachability and exploitability evidence belongs to observations. Both WEB-01 and WEB-02 see the same synthetic advisory's known-exploitation flag; their priorities differ because of environment, exposure, business criticality, services and supported potential paths.

## History and deletion

Relationships can be removed and paths recomputed. The removal audit retains the original relationship. Inventory is normally retired or edited rather than deleted, preserving evidence and links. Analyst rejection, acceptance, deferral and verification retain risk history. A supported new version observation can verify a formerly affected version; genuine reintroduction reopens it.
