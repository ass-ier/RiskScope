import { categories, exposures, priorities, riskStatuses } from './format'

export interface ResourceConfig {
  title: string
  singular: string
  description: string
  columns: string[]
  filters?: Record<string, string[]>
  writable?: boolean
}

export const resources: Record<string, ResourceConfig> = {
  assets: {
    title: 'Assets', singular: 'asset', writable: true,
    description: 'Inventory, network exposure and business context. Exposure is observed, never inferred from an IP address.',
    columns: ['hostname', 'ip', 'environment', 'criticality', 'exposure', 'owner', 'status'],
    filters: { environment: ['PRODUCTION', 'STAGING', 'DEVELOPMENT', 'TEST', 'LAB', 'UNKNOWN'], criticality: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'], exposure: exposures, status: ['ACTIVE', 'INACTIVE', 'RETIRED', 'UNKNOWN'] },
  },
  software: {
    title: 'Software', singular: 'product', writable: true,
    description: 'Canonical products and their observed installations. Original names and normalization confidence are preserved.',
    columns: ['canonical_name', 'vendor', 'ecosystem', 'lifecycle', 'source', 'confidence'],
    filters: { lifecycle: ['SUPPORTED', 'END_OF_LIFE', 'UNKNOWN'] },
  },
  vulnerabilities: {
    title: 'Vulnerabilities', singular: 'vulnerability', writable: true,
    description: 'Global advisory intelligence. Environmental priority is assessed separately for each affected asset.',
    columns: ['identifier', 'title', 'cvss_score', 'known_exploited', 'exploit_available', 'source'],
    filters: { known_exploited: ['true', 'false'], exploit_available: ['true', 'false'] },
  },
  risk: {
    title: 'Risk register', singular: 'risk',
    description: 'Prioritize by context, inspect the evidence, then record a decision. Select up to five risks to compare.',
    columns: ['title', 'asset_id', 'vulnerability_id', 'severity', 'priority', 'score', 'exposure', 'exploitability', 'criticality', 'owner', 'status', 'due_date'],
    filters: { priority: priorities, status: riskStatuses, category: categories, exposure: exposures, exploitability: ['KNOWN_EXPLOITED', 'EXPLOIT_AVAILABLE', 'NO_KNOWN_EXPLOIT', 'UNKNOWN'], active: ['true', 'false'], overdue: ['true'], internet_exposed: ['true', 'false'], known_exploited: ['true', 'false'] },
  },
  'attack-paths': {
    title: 'Attack paths', singular: 'potential path',
    description: 'Potential progression through observed relationships, not proof of successful exploitation.',
    columns: ['id', 'source_asset_id', 'target_asset_id', 'risk_id', 'confidence', 'reasoning'],
  },
  sbom: {
    title: 'SBOM', singular: 'software bill of materials',
    description: 'Imported application dependencies, provenance and direct or transitive components.',
    columns: ['name', 'asset_id', 'format', 'source', 'created_at'],
  },
  imports: {
    title: 'Imports', singular: 'import',
    description: 'Bring local inventories and advisories into the workstation. Every row retains its provenance.',
    columns: ['filename', 'kind', 'status', 'processed', 'imported', 'skipped', 'rejected', 'created_at'],
  },
  remediation: {
    title: 'Remediation', singular: 'remediation task', writable: true,
    description: 'Assign actions and deadlines. Marking a task remediated is not verification; verify from its linked risk.',
    columns: ['action', 'risk_id', 'fixed_version', 'owner', 'priority', 'due_date', 'status'],
    filters: { status: riskStatuses, priority: priorities },
  },
  cases: {
    title: 'Cases', singular: 'case', writable: true,
    description: 'Keep related assets, risks, analyst notes and response work together.',
    columns: ['title', 'owner', 'status', 'created_at', 'updated_at'],
    filters: { status: ['OPEN', 'INVESTIGATING', 'REMEDIATION', 'VERIFICATION', 'CLOSED'] },
  },
  reports: { title: 'Reports', singular: 'report', description: 'Persistent point-in-time snapshots for technical investigation and executive review.', columns: ['title', 'perspective', 'created_at'] },
  timeline: { title: 'Timeline', singular: 'event', description: 'An attributable history of inventory, assessment, review and remediation.', columns: ['created_at', 'action', 'summary', 'actor', 'asset_id', 'risk_id'] },
  audit: { title: 'Audit trail', singular: 'audit event', description: 'Inspect the previous and new values for every meaningful change.', columns: ['created_at', 'action', 'object_type', 'object_id', 'actor', 'reason'] },
  evidence: { title: 'Evidence', singular: 'evidence record', writable: true, description: 'Source observations and analyst records, separate from automated conclusions.', columns: ['summary', 'type', 'source', 'confidence', 'actor', 'created_at'] },
  zones: { title: 'Network zones', singular: 'network zone', writable: true, description: 'Recorded boundaries, subnets and network context.', columns: ['name', 'subnet', 'vlan', 'gateway', 'source'] },
  'business-context': { title: 'Business context', singular: 'business context', writable: true, description: 'Business ownership, function, classification and regulatory importance.', columns: ['asset_id', 'business_owner', 'application', 'data_classification', 'regulatory_importance'] },
  relationships: { title: 'Relationships', singular: 'relationship', writable: true, description: 'Evidence-backed asset connections used in potential path analysis.', columns: ['source_asset_id', 'type', 'target_asset_id', 'description', 'evidence_id'] },
  installations: { title: 'Installations', singular: 'installation', writable: true, description: 'Observed software, original names and versions on each asset. Update a version, then correlate to evaluate fixes.', columns: ['asset_id', 'software_id', 'original_name', 'version', 'normalization_method', 'normalization_confidence', 'evidence_id'] },
  services: { title: 'Services', singular: 'service', writable: true, description: 'Known services and recorded reachability. RiskScope does not scan hosts.', columns: ['name', 'asset_id', 'port', 'protocol', 'exposure', 'status', 'evidence_id'] },
  'affected-ranges': { title: 'Affected versions & fixes', singular: 'affected range', writable: true, description: 'Explicit product ranges and known fixed versions from advisory evidence.', columns: ['product', 'vendor', 'version_scheme', 'affected', 'fixed_versions', 'evidence_id'] },
  references: { title: 'Advisory references', singular: 'reference', writable: true, description: 'Recorded advisory, patch and source links.', columns: ['label', 'url'] },
  'exposure-observations': { title: 'Exposure observations', singular: 'exposure observation', writable: true, description: 'Asset-specific network observations with source evidence.', columns: ['asset_id', 'service_id', 'exposure', 'note', 'source', 'evidence_id'] },
  'exploitability-observations': { title: 'Exploitability observations', singular: 'exploitability observation', writable: true, description: 'Asset-specific reachability, privilege and complexity evidence; not global exploitation intelligence.', columns: ['asset_id', 'vulnerability_id', 'reachability', 'privileges', 'complexity', 'note', 'evidence_id'] },
  matches: { title: 'Vulnerability matches', singular: 'match', description: 'Recorded correlation rules, observed versions and analyst match decisions.', columns: ['installation_id', 'vulnerability_id', 'observed_version', 'rule', 'method', 'confidence', 'state'] },
  components: { title: 'Components', singular: 'component', description: 'Direct and transitive package inventory. Presence alone does not demonstrate exploitability.', columns: ['name', 'version', 'vendor', 'direct', 'purl', 'licenses'] },
  dependencies: { title: 'Dependency relationships', singular: 'dependency', description: 'Relationships explicitly recorded in the SBOM.', columns: ['source_component_id', 'target_component_id', 'evidence_id'] },
  'case-assets': { title: 'Linked assets', singular: 'asset link', writable: true, description: 'Assets included in this investigation.', columns: ['asset_id', 'created_at'] },
  'case-risks': { title: 'Linked risks', singular: 'risk link', writable: true, description: 'Risks included in this investigation.', columns: ['risk_id', 'created_at'] },
  notes: { title: 'Analyst notes', singular: 'note', writable: true, description: 'Attributed observations and investigation decisions.', columns: ['text', 'actor', 'evidence_id', 'created_at'] },
  'risk-factors': { title: 'Risk factors', singular: 'risk factor', description: 'Deterministic contributions to the automated assessment.', columns: ['name', 'value', 'contribution', 'reasoning'] },
  'assessment-history': { title: 'Assessment history', singular: 'assessment snapshot', description: 'Previous automated assessments retained for reproducibility.', columns: ['risk_id', 'created_at', 'snapshot'] },
  'import-records': { title: 'Import rows', singular: 'import row', description: 'Row-level validation and imported record provenance.', columns: ['row_number', 'status', 'object_type', 'object_id', 'error'] },
  verifications: { title: 'Verification history', singular: 'verification', description: 'Explicit analyst or evidence-backed version-change verification records.', columns: ['created_at', 'method', 'actor', 'reason', 'evidence_id'] },
  acceptances: { title: 'Risk acceptance history', singular: 'risk acceptance', description: 'Time-bounded decisions with compensating controls. Accepted risks are retained.', columns: ['approver', 'reason', 'expires_at', 'compensating_controls', 'expired'] },
  snapshots: { title: 'Posture snapshots', singular: 'posture snapshot', description: 'Actual risk history captured by the application; no interpolated observations.', columns: ['created_at', 'open_risk', 'remediated', 'new_risks', 'overdue'] },
  providers: { title: 'Intelligence sources', singular: 'provider', description: 'Local sources and optional provider cache metadata. External adapters are disabled unless implemented and configured.', columns: ['source', 'version', 'downloaded_at', 'enabled'] },
}

export const foreignResources: Record<string, string> = {
  asset_id: 'assets', source_asset_id: 'assets', target_asset_id: 'assets',
  software_id: 'software', vulnerability_id: 'vulnerabilities', evidence_id: 'evidence',
  installation_id: 'installations', service_id: 'services', risk_id: 'risk', match_id: 'matches',
  zone_id: 'zones', case_id: 'cases', sbom_id: 'sbom', import_job_id: 'imports',
  source_component_id: 'components', target_component_id: 'components', range_id: 'affected-ranges',
}

export const navigation = [
  { title: 'Workspace', items: [['/', 'Dashboard', 'dashboard'], ['/risk', 'Risk register', 'risk'], ['/attack-paths', 'Attack paths', 'graph']] },
  { title: 'Inventory & intelligence', items: [['/assets', 'Assets', 'asset'], ['/software', 'Software', 'software'], ['/vulnerabilities', 'Vulnerabilities', 'risk'], ['/sbom', 'SBOM', 'graph'], ['/imports', 'Imports', 'import']] },
  { title: 'Analyst operations', items: [['/remediation', 'Remediation', 'check'], ['/cases', 'Cases', 'case'], ['/reports', 'Reports', 'report'], ['/timeline', 'Timeline', 'clock'], ['/settings', 'Settings', 'settings']] },
]
