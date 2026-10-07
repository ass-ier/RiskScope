import { lazy, Suspense, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useResource } from '../lib/api'
import { humanize, recordName, text } from '../lib/format'
import { resources } from '../lib/resources'
import type { Data } from '../types'
import { ResourceEditor } from '../components/Forms'
import { RecordLink } from '../components/Lookup'
import { DeleteRecord, RecordConnections, RecordView } from '../components/RecordView'
import { ResourceTable } from '../components/ResourceTable'
import { ErrorNotice, PageHeader, Pill, Section, Skeleton } from '../components/UI'
import { CorrelateButton } from '../components/WorkstationActions'

const Graph = lazy(() => import('../components/Graph'))

function GraphSection({ assetId, sbomId }: { assetId?: number; sbomId?: number }) {
  return <Section title={sbomId ? 'Component dependency graph' : 'Potential relationship graph'}><Suspense fallback={<Skeleton rows={6} />}><Graph assetId={assetId} sbomId={sbomId} /></Suspense></Section>
}

export function InventoryList({ resource }: { resource: string }) {
  const config = resources[resource]
  const [params, setParams] = useSearchParams()
  const [creating, setCreating] = useState(params.get('new') === 'true')
  const navigate = useNavigate()
  if (!config) return <NotFound />
  return <><PageHeader title={config.title} description={config.description} actions={<>{resource === 'risk' ? <><Link className="button" to="/risk/new">Record non-CVE risk</Link><CorrelateButton /></> : config.writable && <button className="button primary" onClick={() => setCreating(!creating)}>{creating ? 'Close form' : `Add ${config.singular}`}</button>}{['assets', 'software', 'vulnerabilities', 'sbom'].includes(resource) && <Link className="button" to="/imports">Import {resource === 'sbom' ? 'SBOM' : 'file'}</Link>}</>} />{resource === 'risk' && <div className="view-shortcuts"><span>Focus:</span><Link to="/risk?active=true">Active risks</Link><Link to="/risk?exposure=INTERNET_FACING&active=true">Internet-facing</Link><Link to="/risk?exploitability=KNOWN_EXPLOITED&active=true">Known exploited</Link><Link to="/risk?overdue=true">Overdue</Link><Link to="/risk">All, including historical</Link></div>}{creating && config.writable && <ResourceEditor resource={resource} onDone={record => navigate(`/${resource}/${record.id}`)} onCancel={() => { setCreating(false); if (params.has('new')) setParams(previous => { const next = new URLSearchParams(previous); next.delete('new'); return next }) }} />}<ResourceTable key={resource} resource={resource} primary emptyAction={config.writable ? <button className="button primary" onClick={() => setCreating(true)}>Add {config.singular}</button> : undefined} /></>
}

function AssetDetail({ record, tab }: { record: Data; tab: string }) {
  return <>
    {tab === 'overview' && <><div className="record-banner"><Pill value={record.environment} /><Pill value={record.criticality} /><Pill value={record.exposure} /><span>{text(record.ip)} · Owner: {text(record.owner)}</span></div><RecordView resource="assets" record={record} editable /><ResourceTable resource="business-context" title="Business context" filters={{ asset_id: record.id }} create /></>}
    {tab === 'inventory' && <><ResourceTable resource="installations" title="Installed software" filters={{ asset_id: record.id }} create /><ResourceTable resource="services" title="Known services" filters={{ asset_id: record.id }} create /><ResourceTable resource="sbom" title="Associated SBOMs" filters={{ asset_id: record.id }} /></>}
    {tab === 'risk' && <><ResourceTable resource="risk" title="Contributing risks & vulnerabilities" filters={{ asset_id: record.id }} columns={['title', 'vulnerability_id', 'severity', 'priority', 'score', 'exposure', 'status']} /><ResourceTable resource="remediation" title="Asset remediation" filters={{ asset_id: record.id }} /></>}
    {tab === 'network' && <>{record.zone_id ? <Section title="Network zone"><RecordLink resource="zones" id={record.zone_id} /></Section> : null}<ResourceTable resource="relationships" title="Outgoing relationships" filters={{ source_asset_id: record.id }} create /><ResourceTable resource="relationships" title="Incoming relationships" filters={{ target_asset_id: record.id }} create /><ResourceTable resource="attack-paths" title="Potential paths involving this asset" filters={{ asset_id: record.id }} /><GraphSection assetId={record.id} /></>}
    {tab === 'evidence' && <><ResourceTable resource="exposure-observations" title="Exposure observations" filters={{ asset_id: record.id }} create /><ResourceTable resource="exploitability-observations" title="Exploitability observations" filters={{ asset_id: record.id }} create />{record.evidence_id ? <ResourceTable resource="evidence" title="Inventory evidence" filters={{ ids: Number(record.evidence_id) }} /> : <Section title="Inventory evidence"><p className="muted">No inventory evidence is linked to this asset. Create evidence, then edit the asset to associate it.</p><Link to="/evidence?new=true">Create evidence →</Link></Section>}<ResourceTable resource="notes" title="Analyst notes" filters={{ asset_id: record.id }} create /></>}
    {tab === 'history' && <><ResourceTable resource="timeline" title="Asset timeline" filters={{ asset_id: record.id }} /><ResourceTable resource="audit" title="Asset change history" filters={{ object_type: 'asset', object_id: record.id }} /></>}
  </>
}

function SoftwareDetail({ record, tab }: { record: Data; tab: string }) {
  return <>
    {tab === 'overview' && <><RecordView resource="software" record={record} editable /><Section title="Normalization & lifecycle"><p>Canonical names represent normalized products. Original inventory names, observed versions, normalization methods and confidence remain on each installation. End-of-life status is an evidence-backed risk factor, not an automatic critical finding.</p></Section><ResourceTable resource="installations" title="Observed versions & affected assets" filters={{ software_id: record.id }} create /></>}
    {tab === 'risk' && <><ResourceTable resource="affected-ranges" title="Known advisory ranges & fixes" filters={{ product: text(record.canonical_name, '') }} /><ResourceTable resource="matches" title="Vulnerability matches" filters={{ software_id: record.id }} /><ResourceTable resource="risk" title="Environmental risk contribution" filters={{ software_id: record.id }} /></>}
    {tab === 'dependencies' && <><Section title="Dependency investigation"><p>Open an installation to see its SBOM components, then follow the associated software bill of materials for direct and transitive dependency relationships.</p><Link className="button" to="/sbom">Explore SBOMs</Link></Section><ResourceTable resource="components" title="SBOM components for this product" filters={{ software_id: record.id }} /></>}
    {tab === 'evidence' && <>{record.evidence_id ? <ResourceTable resource="evidence" title="Product provenance" filters={{ ids: Number(record.evidence_id) }} /> : <Section title="Product provenance"><p>No evidence is linked to this canonical product. Review the source evidence on its installations.</p></Section>}<ResourceTable resource="audit" title="Product changes" filters={{ object_type: 'software', object_id: record.id }} /></>}
  </>
}

function VulnerabilityDetail({ record, tab }: { record: Data; tab: string }) {
  return <>
    {record.synthetic === true && <p className="notice info">Synthetic advisory. This record demonstrates contextual prioritization and is not a factual claim about a real product vulnerability.</p>}
    {tab === 'overview' && <><RecordView resource="vulnerabilities" record={record} editable /><ResourceTable resource="affected-ranges" title="Affected versions & known fixes" filters={{ vulnerability_id: record.id }} create /><ResourceTable resource="references" title="Advisory references" filters={{ vulnerability_id: record.id }} create /></>}
    {tab === 'risk' && <><ResourceTable resource="risk" title="Affected assets & environmental priority" filters={{ vulnerability_id: record.id }} /><ResourceTable resource="matches" title="Version matches" filters={{ vulnerability_id: record.id }} /><ResourceTable resource="attack-paths" title="Associated potential paths" filters={{ vulnerability_id: record.id }} /><ResourceTable resource="remediation" title="Remediation across assets" filters={{ vulnerability_id: record.id }} /></>}
    {tab === 'evidence' && <><Section title="Global intelligence versus asset observations"><p>Known exploitation, public exploit availability and CVSS are advisory-level evidence. Reachability, privileges and environmental complexity below belong to a specific asset. Unknown does not mean no.</p></Section><ResourceTable resource="exploitability-observations" title="Asset-specific exploitability" filters={{ vulnerability_id: record.id }} create />{record.evidence_id ? <ResourceTable resource="evidence" title="Advisory evidence" filters={{ ids: Number(record.evidence_id) }} /> : null}<ResourceTable resource="audit" title="Advisory change history" filters={{ object_type: 'vulnerability', object_id: record.id }} /></>}
  </>
}

function SBOMDetail({ record, tab }: { record: Data; tab: string }) {
  return <>
    {tab === 'overview' && <><RecordView resource="sbom" record={record} /><ResourceTable resource="components" title="Direct & transitive components" filters={{ sbom_id: record.id }} /></>}
    {tab === 'dependencies' && <><GraphSection sbomId={record.id} /><ResourceTable resource="dependencies" title="Recorded dependency edges" filters={{ sbom_id: record.id }} /></>}
    {tab === 'risk' && <ResourceTable resource="risk" title="SBOM-backed risk" filters={{ sbom_id: record.id }} />}
  </>
}

function CaseDetail({ record, tab }: { record: Data; tab: string }) {
  return <>
    {tab === 'overview' && <><RecordView resource="cases" record={record} editable /><ResourceTable resource="case-risks" title="Risks in this investigation" filters={{ case_id: record.id }} create /><ResourceTable resource="case-assets" title="Assets in this investigation" filters={{ case_id: record.id }} create /></>}
    {tab === 'notes' && <ResourceTable resource="notes" title="Case notes" filters={{ case_id: record.id }} create />}
    {tab === 'remediation' && <ResourceTable resource="remediation" title="Remediation for linked risks" filters={{ case_id: record.id }} />}
    {tab === 'history' && <ResourceTable resource="audit" title="Case history" filters={{ object_type: 'case_record', object_id: record.id }} />}
  </>
}

const tabSets: Record<string, string[][]> = {
  assets: [['overview', 'Overview & business'], ['inventory', 'Software & services'], ['risk', 'Risk & remediation'], ['network', 'Network & paths'], ['evidence', 'Evidence & notes'], ['history', 'Timeline']],
  software: [['overview', 'Product & installations'], ['risk', 'Vulnerabilities & risk'], ['dependencies', 'Dependencies'], ['evidence', 'Provenance']],
  vulnerabilities: [['overview', 'Advisory & versions'], ['risk', 'Affected assets & risk'], ['evidence', 'Evidence & observations']],
  sbom: [['overview', 'Overview & components'], ['dependencies', 'Dependency graph'], ['risk', 'Associated risks']],
  cases: [['overview', 'Overview & linked records'], ['notes', 'Analyst notes'], ['remediation', 'Remediation'], ['history', 'History']],
}

export function InventoryDetail({ resource }: { resource: string }) {
  const { id } = useParams()
  const query = useResource(resource, id)
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const config = resources[resource]
  const tabs = tabSets[resource]
  const requestedTab = params.get('tab') || 'overview'
  const tab = tabs?.some(([key]) => key === requestedTab) ? requestedTab : 'overview'
  if (!config) return <NotFound />
  if (query.isLoading) return <Skeleton rows={8} />
  if (query.error) return <ErrorNotice error={query.error} retry={() => { void query.refetch() }} />
  if (!query.data) return null
  const record = query.data
  return <><PageHeader title={recordName(record)} description={`${humanize(config.singular)} #${record.id} · ${config.description}`} back={{ to: `/${resource}`, label: config.title }} actions={['assets', 'software', 'vulnerabilities', 'installations'].includes(resource) && <CorrelateButton />} />{tabs && <nav className="tabs" aria-label={`${config.singular} detail sections`}>{tabs.map(([value, title]) => <button key={value} aria-current={value === tab ? 'page' : undefined} onClick={() => setParams({ tab: value })}>{title}</button>)}</nav>}
    {resource === 'assets' ? <AssetDetail record={record} tab={tab} /> : resource === 'software' ? <SoftwareDetail record={record} tab={tab} /> : resource === 'vulnerabilities' ? <VulnerabilityDetail record={record} tab={tab} /> : resource === 'sbom' ? <SBOMDetail record={record} tab={tab} /> : resource === 'cases' ? <CaseDetail record={record} tab={tab} /> : <><RecordView resource={resource} record={record} editable={config.writable} /><RecordConnections record={record} />
      {resource === 'installations' && <><ResourceTable resource="matches" title="Version matches" filters={{ installation_id: record.id }} /><ResourceTable resource="components" title="SBOM component associations" filters={{ installation_id: record.id }} /><Section title="Verify an upgrade"><p>Save the newly observed version with supporting evidence, then correlate. The engine checks whether this installation remains affected and records an evidence-backed verification when appropriate.</p><CorrelateButton /></Section></>}
      {resource === 'components' && record.sbom_id ? <Section title="Dependency graph"><RecordLink resource="sbom" id={record.sbom_id} /><p>Open this SBOM’s dependency graph to inspect direct and transitive relationships.</p></Section> : null}
      {resource === 'remediation' && <Section title="Dedicated risk decisions"><p>Task completion is not verification. Open the linked risk to review, accept, defer, reject or verify with evidence.</p><RecordLink resource="risk" id={record.risk_id} /></Section>}
      {resource === 'evidence' && record.import_job_id ? <ResourceTable resource="import-records" title="Source import records" filters={{ import_job_id: Number(record.import_job_id) }} /> : null}
      {resource === 'attack-paths' && <><Section title="Potential progression"><p>{text(record.reasoning)}</p><div className="path-chain">{Array.isArray(record.asset_ids) && record.asset_ids.map((assetId, index) => <span key={`${assetId}-${index}`}>{index > 0 && <span aria-hidden="true"> → </span>}<RecordLink resource="assets" id={assetId} /></span>)}</div><p className="notice info">This is potential progression through recorded relationships. It is not a confirmed exploit chain.</p></Section><GraphSection assetId={Number(record.source_asset_id)} /></>}
      <DeleteRecord resource={resource} id={record.id} onDeleted={() => navigate(`/${resource}`)} /></>}
  </>
}

export function AttackPaths() {
  const [params, setParams] = useSearchParams()
  const view = params.get('view') || 'graph'
  return <><PageHeader title="Attack paths & surface" description="Explore observed relationships and potential progression toward business-critical assets. Bounds and uncertainty remain visible." actions={<CorrelateButton />} /><div className="view-shortcuts"><Link to="/assets?exposure=INTERNET_FACING">Internet-facing assets</Link><Link to="/assets?exposure=INTERNAL_ONLY">Internal assets</Link><Link to="/assets?criticality=CRITICAL">Critical assets</Link><Link to="/risk?active=true">Vulnerable assets & risks</Link><Link to="/relationships">Manage relationships</Link></div><nav className="tabs" aria-label="Attack path views"><button aria-current={view === 'graph' ? 'page' : undefined} onClick={() => setParams({ view: 'graph' })}>Relationship graph</button><button aria-current={view === 'paths' ? 'page' : undefined} onClick={() => setParams({ view: 'paths' })}>Potential path register</button></nav>{view === 'graph' ? <Suspense fallback={<Skeleton rows={8} />}><Graph /></Suspense> : <ResourceTable resource="attack-paths" primary />}</>
}

export function Timeline() {
  const [params, setParams] = useSearchParams()
  const audit = params.get('view') === 'audit'
  return <><PageHeader title="Timeline & audit" description="Trace evidence ingestion, correlation, analyst judgment and remediation. Open an event to inspect its linked records and before/after state." /><nav className="tabs" aria-label="History views"><button aria-current={!audit ? 'page' : undefined} onClick={() => setParams({ view: 'timeline' })}>Activity timeline</button><button aria-current={audit ? 'page' : undefined} onClick={() => setParams({ view: 'audit' })}>Audit before & after</button></nav><ResourceTable key={audit ? 'audit' : 'timeline'} resource={audit ? 'audit' : 'timeline'} primary /></>
}

export function NotFound() {
  return <><PageHeader title="Page not found" description="This route is not part of the workstation. Your saved records have not been changed." /><Link className="button primary" to="/">Return to security posture</Link></>
}
