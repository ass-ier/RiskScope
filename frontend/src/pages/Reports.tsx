import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, queryString, useResource } from '../lib/api'
import { date, humanize, number, text } from '../lib/format'
import type { Data, Dashboard, Page, Schema, Settings } from '../types'
import { ActionForm } from '../components/Forms'
import { ResourceTable, Cell } from '../components/ResourceTable'
import { Empty, ErrorNotice, Facts, PageHeader, Section, Skeleton, Structured } from '../components/UI'
import { foreignResources, resources } from '../lib/resources'
import { DownloadLink } from '../components/DownloadLink'
import { useWorkspace } from '../components/Workspace'

interface ReportSummary {
  dashboard: Dashboard
  generated_at: string
  scope: string
  disclaimer: string
  settings: Settings
}

const reportSchema: Schema = {
  required: ['title', 'perspective'],
  properties: {
    title: { type: 'string', minLength: 1, default: 'RiskScope assessment' },
    perspective: { type: 'string', enum: ['technical', 'executive'], default: 'technical' },
  },
}

export function Reports() {
  const { runtime } = useWorkspace()
  const navigate = useNavigate()
  const [creating, setCreating] = useState(false)
  return <><PageHeader title="Reports" description={runtime.mode === 'hosted' ? 'Capture and download assessments before your temporary session ends. Hosted reports are not permanent backups.' : 'Preserve a point-in-time assessment, then export the same persistent snapshot for engineering or management.'} actions={<button className="button primary" onClick={() => setCreating(!creating)}>{creating ? 'Close report form' : 'Create report snapshot'}</button>} />{creating && <div className="form-page"><ActionForm path="/reports" schema={reportSchema} submitLabel="Create report snapshot" onDone={report => navigate(`/reports/${report.id}`)} /></div>}<div className="report-perspectives"><div><h2>Technical perspective</h2><p>Assets, software, versions, matches, exposure, contextual risk factors, evidence, paths, remediation and verification.</p></div><div><h2>Executive perspective</h2><p>Security posture, priority risks, critical assets, internet exposure, known exploitation, progress and recorded trends.</p></div></div><ResourceTable resource="reports" primary emptyAction={<button className="button primary" onClick={() => setCreating(true)}>Create the first report</button>} /></>
}

function SnapshotCell({ row, resource, field }: { row: Data; resource: string; field: string }) {
  if (foreignResources[field]) {
    const id = row[field]
    if (typeof id !== 'number') return <span className="muted">Not recorded</span>
    const capturedName = row[field.replace(/_id$/, '_name')] || (field === 'vulnerability_id' ? row.vulnerability_identifier : undefined)
    return <Link to={`/${foreignResources[field]}/${id}`} title="Open the current record, which may differ from this snapshot">{text(capturedName, `${humanize(field)} #${id}`)}</Link>
  }
  return <Cell row={row} resource={resource} field={field} />
}

function SnapshotTable({ reportId, resource }: { reportId: number; resource: string }) {
  const [page, setPage] = useState(1)
  const pageSize = 25
  const query = useQuery({
    queryKey: ['report-records', reportId, resource, page],
    queryFn: ({ signal }) => api<Page>(`/reports/${reportId}/records/${resource}${queryString({ page, page_size: pageSize })}`, { signal }),
    gcTime: 0,
  })
  const fields = resources[resource]?.columns.slice(0, 7) || ['id', 'created_at']
  if (query.isLoading) return <Skeleton />
  if (query.error) return <ErrorNotice error={query.error} retry={() => { void query.refetch() }} />
  if (!query.data?.items.length) return <Empty title="No records in this snapshot">Records created later do not alter a saved report. Choose another captured dataset or create a new report to include newer assessments.</Empty>
  return <><div className="table-scroll" tabIndex={0} role="region" aria-label={`${resource} snapshot records`}><table><thead><tr>{fields.map(key => <th key={key} scope="col">{humanize(key)}</th>)}<th scope="col">Captured detail</th></tr></thead><tbody>{query.data.items.map(row => <tr key={row.id}>{fields.map(field => <td key={field}><SnapshotCell row={row} resource={resource} field={field} /></td>)}<td><details className="cell-details"><summary>Inspect snapshot #{row.id}</summary><Structured value={row} /></details></td></tr>)}</tbody></table></div><div className="table-footer"><span>{number((page - 1) * pageSize + 1)}–{number(Math.min(page * pageSize, query.data.total))} of {number(query.data.total)} captured records{query.isFetching && ' · Updating…'}</span><div className="button-row"><button className="button small" disabled={page === 1 || query.isFetching} onClick={() => setPage(v => v - 1)}>Previous</button><span>Page {page}</span><button className="button small" disabled={page * pageSize >= query.data.total || query.isFetching} onClick={() => setPage(v => v + 1)}>Next</button></div></div></>
}

function SnapshotSummary({ reportId }: { reportId: number }) {
  const query = useQuery({
    queryKey: ['report-summary', reportId],
    queryFn: ({ signal }) => api<ReportSummary>(`/reports/${reportId}/summary`, { signal }),
  })
  if (query.isLoading) return <Skeleton />
  if (query.error) return <ErrorNotice error={query.error} retry={() => { void query.refetch() }} />
  if (!query.data) return null
  const summary = query.data
  return <><Facts data={{ generated_at: summary.generated_at, scope: summary.scope }} fields={['generated_at', 'scope']} /><dl className="snapshot-totals">{Object.entries(summary.dashboard.totals).map(([key, value]) => <div key={key}><dt>{humanize(key)}</dt><dd>{number(value)}</dd></div>)}</dl><p className="notice info">{summary.disclaimer}</p><details className="details-block"><summary>Captured assessment settings</summary><Structured value={summary.settings} /></details></>
}

export function ReportDetail() {
  const { id } = useParams()
  const query = useResource('reports', id)
  const [dataset, setDataset] = useState('risk')
  if (query.isLoading) return <Skeleton />
  if (query.error) return <ErrorNotice error={query.error} retry={() => { void query.refetch() }} />
  if (!query.data) return null
  const report = query.data
  return <><PageHeader title={text(report.title)} description={`${humanize(String(report.perspective))} snapshot · Created ${date(report.created_at, true)}. Downloads use this saved assessment, not live browser state.`} back={{ to: '/reports', label: 'Reports' }} /><Section title="Export saved report"><div className="export-formats">{['pdf', 'markdown', 'json'].map(format => <DownloadLink key={format} path={`/reports/${id}/export?format=${format}`}>Download {format === 'markdown' ? 'Markdown' : format.toUpperCase()}</DownloadLink>)}</div><h3>Dataset exports</h3><div className="export-formats">{['risk', 'assets', 'vulnerabilities', 'remediation'].map(value => <DownloadLink key={value} className="button small" path={`/reports/${id}/export?format=csv&dataset=${value}`}>{value === 'risk' ? 'Risk register' : value === 'assets' ? 'Asset inventory' : value === 'vulnerabilities' ? 'Vulnerability inventory' : 'Remediation tracker'} · CSV</DownloadLink>)}</div></Section><Section title="Snapshot overview"><SnapshotSummary reportId={report.id} /><p className="muted">Only the captured summary and the selected 25-record page are fetched. Links in the preview open current records, which may have changed since this snapshot; the displayed values remain captured evidence.</p><Link to="/reports">Create a new snapshot for current data →</Link></Section><Section title="Captured records" description="Inspect immutable snapshot rows one server-paginated dataset at a time."><div className="table-tools"><label htmlFor="report-dataset">Captured dataset<select id="report-dataset" value={dataset} onChange={event => setDataset(event.target.value)}>{Object.entries(resources).filter(([key]) => key !== 'reports').map(([key, config]) => <option value={key} key={key}>{config.title}</option>)}</select></label></div><SnapshotTable key={`${report.id}-${dataset}`} reportId={report.id} resource={dataset} /></Section></>
}
