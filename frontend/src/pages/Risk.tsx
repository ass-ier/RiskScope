import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api, useResource } from '../lib/api'
import { categories, exposures, humanize, priorities, priority, text } from '../lib/format'
import type { Data, Risk, Schema } from '../types'
import { ActionForm, ResourceEditor } from '../components/Forms'
import { Lookup, RecordLink } from '../components/Lookup'
import { ResourceTable } from '../components/ResourceTable'
import { Empty, ErrorNotice, Facts, PageHeader, Pill, Section, Skeleton, Structured } from '../components/UI'
import { RecordView } from '../components/RecordView'

const string = { type: 'string' } satisfies Schema
const reason = { type: 'string', minLength: 1 } satisfies Schema
const actor = { type: 'string', minLength: 1, default: 'Local analyst' } satisfies Schema
const optionalEnum = (values: string[]): Schema => ({ anyOf: [{ type: 'string', enum: values }, { type: 'null' }], default: null })
const reviewSchema: Schema = {
  required: ['actor', 'reason'],
  properties: {
    actor, reason,
    match_state: optionalEnum(['CONFIRMED', 'POTENTIAL', 'REJECTED', 'NEEDS_REVIEW']),
    status: optionalEnum(['OPEN', 'IN_PROGRESS', 'REMEDIATED', 'FALSE_POSITIVE', 'DEFERRED']),
    priority: optionalEnum(priorities), severity: optionalEnum(priorities),
    confidence: optionalEnum(['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']),
    exposure: optionalEnum(exposures),
    exploitability: optionalEnum(['KNOWN_EXPLOITED', 'EXPLOIT_AVAILABLE', 'NO_KNOWN_EXPLOIT', 'UNKNOWN']),
    clear_overrides: { type: 'boolean', default: false, description: 'Clear prior analyst overrides and restore the automated assessment. Leave override fields unchanged when clearing.' },
  },
}
const acceptSchema: Schema = {
  required: ['reason', 'approver', 'expires_at', 'compensating_controls'],
  properties: { reason, approver: reason, expires_at: string, compensating_controls: reason },
}
const verifySchema: Schema = {
  required: ['actor', 'reason', 'evidence_id'],
  properties: { actor, reason, evidence_id: { type: 'integer' } },
}
const newRiskSchema: Schema = {
  required: ['asset_id', 'title', 'category', 'severity', 'confidence', 'evidence_id', 'recommendation', 'reason', 'actor'],
  properties: {
    asset_id: { type: 'integer' }, title: reason,
    category: { type: 'string', enum: categories.filter(v => v !== 'VULNERABILITY'), default: 'CONFIGURATION' },
    severity: { type: 'string', enum: priorities, default: 'MEDIUM' },
    confidence: { type: 'string', enum: ['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'], default: 'UNKNOWN' },
    evidence_id: { type: 'integer' }, recommendation: reason, actor, reason,
  },
}

function EvidencePanel({ ids }: { ids: number[] }) {
  return ids.length ? <ResourceTable resource="evidence" title="Source evidence" description="Original observations and their provenance. Evidence is not the automated assessment." filters={{ ids: ids.join(',') }} columns={['summary', 'type', 'source', 'confidence', 'created_at']} /> : <Section title="Source evidence"><Empty title="No evidence linked">Record supporting observations before treating this assessment as confirmed.</Empty></Section>
}

function MatchContext({ matchId }: { matchId: number }) {
  const match = useResource('matches', matchId)
  const installation = useResource('installations', match.data?.installation_id as number | undefined)
  return <><Section title="Observed software & matching rule" description="The installed version and the exact automated matching decision. Presence does not imply exploitability.">
    {match.isLoading ? <Skeleton /> : match.error ? <ErrorNotice error={match.error} retry={() => { void match.refetch() }} /> : match.data && <><Facts data={match.data} fields={['observed_version', 'rule', 'method', 'confidence', 'state', 'analyst_state', 'analyst_reason', 'affected']} /><p><RecordLink resource="installations" id={match.data.installation_id} /> · <Link to={`/matches/${matchId}`}>Full correlation record</Link></p></>}
  </Section>{installation.data && <RecordView resource="installations" record={installation.data} fields={['original_name', 'version', 'package_identifier', 'architecture', 'installation_source', 'normalization_method', 'normalization_confidence', 'first_seen', 'last_seen']} editable />}</>
}

function RiskDecisions({ risk }: { risk: Risk }) {
  const [action, setAction] = useState('review')
  const [completed, setCompleted] = useState(false)
  const choices = [['review', 'Review'], ['remediate', 'Remediate'], ['accept', 'Accept risk'], ['verify', 'Verify']]
  return <Section title="Analyst decision" description="Every decision requires attribution and a reason." className="decision-section">
    <div className="segmented" aria-label="Analyst action">{choices.map(([value, label]) => <button key={value} className={value === action ? 'selected' : ''} aria-pressed={value === action} onClick={() => { setAction(value); setCompleted(false) }}>{label}</button>)}</div>
    {completed && <p className="notice success" role="status">Saved to the local audit history. Automated results remain intact.</p>}
    {action === 'review' && <><p className="muted">Leave fields blank to keep their current values. Match rejection and false-positive decisions do not erase the observed evidence.</p><ActionForm key={`review-${risk.id}`} path={`/risk/${risk.id}/review`} schema={reviewSchema} submitLabel="Save analyst review" onDone={() => setCompleted(true)} /></>}
    {action === 'accept' && <><p className="notice warning">Acceptance is temporary, not remediation. The risk remains visible and reopens when the acceptance expires.</p><ActionForm path={`/risk/${risk.id}/accept`} schema={acceptSchema} submitLabel="Record risk acceptance" onDone={() => setCompleted(true)} /></>}
    {action === 'verify' && <><p className="notice info">Verify only after reviewing evidence of the fix. A status change alone is not proof of remediation. You can also update the installation version and run correlation for an evidence-backed check.</p><p><Link to="/evidence?new=true">Record remediation evidence →</Link></p><ActionForm path={`/risk/${risk.id}/verify`} schema={verifySchema} initial={{ method: 'ANALYST' }} submitLabel="Verify with evidence" onDone={() => setCompleted(true)}><label className="check-label verification-confirm"><input type="checkbox" required />I reviewed the selected evidence and explicitly confirm remediation of this risk.</label></ActionForm></>}
    {action === 'remediate' && <ResourceEditor resource="remediation" presets={{ risk_id: risk.id }} onDone={() => { setCompleted(true); setAction('review') }} onCancel={() => setAction('review')} />}
  </Section>
}

export function RiskDetail() {
  const { id } = useParams()
  const riskQuery = useResource<Risk>('risk', id)
  const risk = riskQuery.data
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab') || 'assessment'
  const asset = useResource('assets', risk?.asset_id)
  const vulnerability = useResource('vulnerabilities', risk?.vulnerability_id)
  if (riskQuery.isLoading) return <Skeleton rows={9} />
  if (riskQuery.error) return <ErrorNotice error={riskQuery.error} retry={() => { void riskQuery.refetch() }} />
  if (!risk) return null
  const tabs = [['assessment', 'Assessment & evidence'], ['context', 'Observed context'], ['remediation', 'Remediation'], ['history', 'History & decisions'], ['notes', 'Analyst notes']]
  return <>
    <PageHeader title={risk.title} description={`Risk #${risk.id} · ${humanize(String(risk.category))} · Rules ${text(risk.rules_version)}`} back={{ to: '/risk', label: 'Risk register' }} actions={<><Pill value={risk.status} /><Link className="button" to={`/risk/compare?ids=${risk.id}`}>Compare risk</Link></>} />
    <div className="risk-summary"><div><span>Effective priority</span><strong><Pill value={priority(risk)} /></strong></div><div><span>Automated priority</span><strong><Pill value={risk.priority} /></strong></div><div><span>Automated score</span><strong className="numeric">{risk.score.toFixed(1)}<small> / 100</small></strong></div><div><span>Affected asset</span><strong><RecordLink resource="assets" id={risk.asset_id} label={asset.data?.hostname} /></strong></div><div><span>Vulnerability</span><strong>{risk.vulnerability_id ? <RecordLink resource="vulnerabilities" id={risk.vulnerability_id} label={vulnerability.data?.identifier} /> : 'Non-CVE risk'}</strong></div></div>
    <nav className="tabs" aria-label="Risk detail sections">{tabs.map(([value, label]) => <button key={value} aria-current={tab === value ? 'page' : undefined} onClick={() => setParams({ tab: value })}>{label}</button>)}</nav>
    {tab === 'assessment' && <div className="risk-detail-split"><div><Section title="Automated assessment" description="Deterministic reasoning from recorded evidence, separate from analyst judgment."><ol className="reasoning-list">{risk.reasoning.map((reason, i) => <li key={i}>{reason}</li>)}</ol>{!risk.reasoning.length && <p className="muted">No automated reasoning recorded.</p>}<div className="table-scroll" tabIndex={0} role="region" aria-label="Automated risk factors"><table className="factor-table"><thead><tr><th>Factor</th><th>Observed value</th><th>Contribution</th><th>Evidence & reasoning</th></tr></thead><tbody>{risk.factors.map((factor, i) => <tr key={`${factor.name}-${i}`}><th scope="row">{humanize(factor.name)}</th><td>{text(factor.value)}</td><td className="numeric">{factor.contribution >= 0 ? '+' : ''}{factor.contribution.toFixed(1)}</td><td><p>{factor.reasoning}</p><div className="inline-links">{factor.evidence_ids.map(id => <Link key={id} to={`/evidence/${id}`}>Evidence #{id}</Link>)}</div></td></tr>)}</tbody></table></div></Section>
      <Section title="Uncertainty & recommended action">{risk.uncertainties.length ? <div className="notice warning"><h3>What is not established</h3><ul>{risk.uncertainties.map((value, i) => <li key={i}>{value}</li>)}</ul></div> : <p className="muted">No additional uncertainties were recorded by this assessment. This does not guarantee exploitability or absence of risk.</p>}<h3>Recommended action</h3><p>{risk.recommendation || 'No remediation recommendation recorded. Consult the source advisory or document an analyst action.'}</p></Section>
      <EvidencePanel ids={risk.evidence_ids} />
      <Section title="Current analyst assessment" description="Human decisions do not overwrite the underlying automated score.">{Object.keys(risk.analyst_override).length ? <Structured value={risk.analyst_override} /> : <p className="muted">No analyst overrides. Effective fields follow the automated assessment.</p>}{risk.analyst_reason && <blockquote>{risk.analyst_reason}</blockquote>}</Section>
    </div><aside><RiskDecisions risk={risk} /></aside></div>}
    {tab === 'context' && <><div className="two-column"><Section title="Asset context">{asset.isLoading ? <Skeleton /> : asset.error ? <ErrorNotice error={asset.error} /> : asset.data && <Facts data={asset.data} fields={['hostname', 'environment', 'criticality', 'exposure', 'owner', 'business_unit', 'ip', 'source']} />}</Section><Section title="Global advisory intelligence" description="These are vulnerability-level facts, not asset-specific exploitability observations.">{vulnerability.data ? <><Facts data={vulnerability.data} fields={['identifier', 'cvss_score', 'known_exploited', 'exploit_available', 'exploit_maturity', 'source']} />{vulnerability.data.synthetic === true && <p className="notice info">Synthetic advisory for demonstration only.</p>}</> : <p className="muted">No vulnerability advisory is associated with this risk.</p>}</Section></div>{risk.match_id && <MatchContext matchId={risk.match_id} />}<ResourceTable resource="exposure-observations" filters={{ asset_id: risk.asset_id }} title="Asset exposure observations" create /><ResourceTable resource="exploitability-observations" filters={{ asset_id: risk.asset_id, vulnerability_id: risk.vulnerability_id }} title="Asset-specific exploitability" create={!!risk.vulnerability_id} /><ResourceTable resource="attack-paths" filters={{ risk_id: risk.id }} title="Potential attack paths" /></>}
    {tab === 'remediation' && <><ResourceTable resource="remediation" filters={{ risk_id: risk.id }} title="Remediation tasks" create /><ResourceTable resource="verifications" filters={{ risk_id: risk.id }} title="Verification evidence" /><ResourceTable resource="acceptances" filters={{ risk_id: risk.id }} title="Time-bounded acceptances" /><RiskDecisions risk={risk} /></>}
    {tab === 'history' && <><ResourceTable resource="assessment-history" filters={{ risk_id: risk.id }} title="Automated assessment history" /><ResourceTable resource="timeline" filters={{ risk_id: risk.id }} title="Risk timeline" /><ResourceTable resource="audit" filters={{ object_type: 'risk_assessment', object_id: risk.id }} title="Analyst audit trail" /></>}
    {tab === 'notes' && <ResourceTable resource="notes" filters={{ risk_id: risk.id }} title="Attributed analyst notes" create />}
  </>
}

export function NewRisk() {
  const navigate = useNavigate()
  return <><PageHeader title="Record a non-CVE risk" description="Document lifecycle, exposure, configuration or business-context risk with supporting evidence. This does not invent a vulnerability advisory." back={{ to: '/risk', label: 'Risk register' }} /><div className="form-page"><ActionForm path="/risk" schema={newRiskSchema} submitLabel="Create evidence-backed risk" onDone={record => navigate(`/risk/${record.id}`)} /></div></>
}

export function RiskComparison() {
  const [params, setParams] = useSearchParams()
  const ids = [...new Set((params.get('ids') || '').split(',').map(Number).filter(id => id > 0 && Number.isInteger(id)))].slice(0, 5)
  const [candidate, setCandidate] = useState<number | null>(null)
  const query = useQuery({ queryKey: ['risk-compare', ids.join(',')], queryFn: ({ signal }) => api<{ items: Risk[]; explanation: string[] }>(`/risk/compare?ids=${ids.join(',')}`, { signal }), enabled: ids.length >= 2 })
  const rows = ['asset_id', 'vulnerability_id', 'severity', 'priority', 'score', 'exposure', 'exploitability', 'confidence', 'status']
  return <><PageHeader title="Compare risk context" description="A higher global severity does not necessarily create the highest environmental priority." back={{ to: '/risk', label: 'Select risks in the register' }} /><div className="comparison-tools"><div><p>{ids.length} of 5 risks selected. Select at least two environmental assessments.</p><div className="inline-links">{ids.map(id => <button key={id} className="text-button" onClick={() => setParams({ ids: ids.filter(value => value !== id).join(',') })}>Remove risk #{id}</button>)}</div></div><form className="comparison-add" onSubmit={event => { event.preventDefault(); if (candidate && !ids.includes(candidate) && ids.length < 5) { setParams({ ids: [...ids, candidate].join(',') }); setCandidate(null) } }}><Lookup resource="risk" label="Risk to compare" value={candidate} onChange={setCandidate} required /><button className="button small" disabled={ids.length >= 5 || !candidate || ids.includes(candidate)}>Add risk</button></form></div>{ids.length < 2 ? <Empty title="Choose at least two risks to compare" action={<Link to="/risk" className="button primary">Open risk register</Link>}>Use the search selector above or the checkboxes in the risk register. Compare up to five environmental assessments.</Empty> : query.isLoading ? <Skeleton rows={8} /> : query.error ? <ErrorNotice error={query.error} retry={() => { void query.refetch() }} /> : query.data && <><Section title="Why these risks are prioritized differently"><ul className="reasoning-list">{query.data.explanation.map((explanation, i) => <li key={i}>{explanation}</li>)}</ul></Section><div className="table-scroll comparison-table" role="region" aria-label="Risk comparison" tabIndex={0}><table><thead><tr><th>Context</th>{query.data.items.map(risk => <th key={risk.id}><Link to={`/risk/${risk.id}`}>{risk.title}</Link><button className="text-button" onClick={() => setParams({ ids: ids.filter(id => id !== risk.id).join(',') })}>Remove #{risk.id}</button></th>)}</tr></thead><tbody>{rows.map(field => <tr key={field}><th scope="row">{humanize(field)}</th>{query.data.items.map(risk => <td key={risk.id}>{field === 'asset_id' || field === 'vulnerability_id' ? <RecordLink resource={field === 'asset_id' ? 'assets' : 'vulnerabilities'} id={risk[field]} /> : field === 'priority' ? <><Pill value={priority(risk)} /><small className="block">Automated: {humanize(risk.priority)}</small></> : text(risk.analyst_override[field] ?? risk[field])}</td>)}</tr>)}<tr><th scope="row">Factors & contribution</th>{query.data.items.map(risk => <td key={risk.id}><ul className="compact-list">{risk.factors.map((factor, i) => <li key={i}><strong>{humanize(factor.name)}: {factor.value}</strong><span>+{factor.contribution.toFixed(1)} · {factor.reasoning}</span></li>)}</ul></td>)}</tr><tr><th scope="row">Uncertainties</th>{query.data.items.map(risk => <td key={risk.id}><Structured value={risk.uncertainties} /></td>)}</tr><tr><th scope="row">Evidence</th>{query.data.items.map(risk => <td key={risk.id}><div className="inline-links">{risk.evidence_ids.map(id => <Link to={`/evidence/${id}`} key={id}>Evidence #{id}</Link>)}</div></td>)}</tr></tbody></table></div></>}</>
}

export function RiskRecordOverview({ data }: { data: Data }) {
  return <RecordView resource="risk" record={data} />
}
