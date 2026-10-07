import { useRef, useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, useApiAction, useResource } from '../lib/api'
import { humanize, number, text } from '../lib/format'
import { Lookup } from '../components/Lookup'
import { ResourceTable } from '../components/ResourceTable'
import { DemoButton } from '../components/WorkstationActions'
import { ErrorNotice, Facts, PageHeader, Pill, Section, Skeleton, useNotice } from '../components/UI'
import type { Data } from '../types'
import { DownloadLink } from '../components/DownloadLink'
import { useWorkspace } from '../components/Workspace'

const examples: Record<string, string> = {
  assets: 'hostname,ip,os,environment,criticality,owner\nWEB-01,10.0.1.10,Linux,PRODUCTION,CRITICAL,Infrastructure',
  software: 'hostname,product,vendor,version\nWEB-01,ExampleWeb,ExampleCorp,1.0.0',
  relationships: 'source_asset_id,target_asset_id,type\n1,2,CONNECTS_TO',
  vulnerabilities: '[{"identifier":"EXAMPLE-ADVISORY-001","title":"Synthetic advisory","synthetic":true,"cvss_score":7.5,"source":"Local fixture"}]',
  sbom: '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","bom-ref":"example-lib","name":"example-lib","version":"1.0.0"}]}',
}

function ImportResult({ job }: { job: Data }) {
  return <div className="import-result"><div className="section-heading"><h3>{text(job.filename)} <Pill value={job.status} /></h3><Link className="text-link" to={`/imports/${job.id}`}>Inspect import #{job.id} →</Link></div><dl className="import-counts">{['processed', 'imported', 'skipped', 'rejected'].map(key => <div key={key}><dt>{humanize(key)}</dt><dd>{number(job[key])}</dd></div>)}</dl>{Array.isArray(job.warnings) && job.warnings.length > 0 && <div className="notice warning"><h4>Import warnings</h4><ul>{job.warnings.map((warning, i) => <li key={i}>{text(warning)}</li>)}</ul></div>}<DownloadLink className="button small" path={`/imports/${job.id}/errors.csv`}>Download row error report (CSV)</DownloadLink></div>
}

function SampleFiles() {
  const query = useQuery({
    queryKey: ['examples'],
    queryFn: ({ signal }) => api<{ filename: string; label: string; kind: string }[]>('/examples', { signal }),
  })
  return <Section title="Download synthetic test data"><p>These files are fictional examples, not real vulnerability intelligence. All supported sample formats are included.</p>
    {query.isLoading ? <Skeleton rows={3} /> : query.error ? <ErrorNotice error={query.error} /> :
      <div className="sample-downloads">{query.data?.map(file => <DownloadLink key={file.filename} className="button small" path={`/examples/${encodeURIComponent(file.filename)}`}>{file.label}</DownloadLink>)}</div>}
  </Section>
}

export function Imports() {
  const session = useWorkspace()
  const hosted = session.runtime.mode === 'hosted'
  const demoWorkspace = hosted && session.workspace === 'demo'
  const maxBytes = session.runtime.max_upload_bytes
  const [consent, setConsent] = useState(false)
  const [kind, setKind] = useState('assets')
  const [assetId, setAssetId] = useState<number | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const [job, setJob] = useState<Data | null>(null)
  const [error, setError] = useState<Error | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const upload = useApiAction(`/imports/${kind}`)
  const notice = useNotice()
  async function submit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    if (!file) return setError(new Error('Choose a CSV, JSON or SBOM file to import.'))
    if (file.size > maxBytes) return setError(new Error(`This file exceeds the ${maxBytes / 1024 / 1024} MiB upload limit. Split the inventory into smaller files and try again.`))
    if (hosted && !consent) return setError(new Error('Acknowledge temporary server processing before uploading.'))
    if (kind === 'sbom' && !assetId) return setError(new Error('Choose the asset that owns this SBOM.'))
    const data = new FormData()
    data.append('file', file)
    if (assetId && kind === 'sbom') data.append('asset_id', String(assetId))
    try {
      const result = await upload.mutateAsync(data)
      setJob(result)
      setFile(null)
      if (fileInput.current) fileInput.current.value = ''
      notice('Import processed. Review imported, skipped and rejected rows before correlating.')
    } catch (e) { setError(e instanceof Error ? e : new Error('Import failed.')) }
  }
  return <>
    <PageHeader title="Imports" description={hosted ? 'Upload evidence into your isolated temporary workspace. Files are processed on the server, never executed.' : 'Bring evidence into the local workstation. Files are parsed and validated, never executed.'} />
    <div className="import-layout">
      <Section title="Import local evidence" description="Create assets first, then add their software and SBOMs. Add advisory evidence before running correlation.">
        {demoWorkspace ? <div className="notice info"><h3>Keep your uploads separate from the demo</h3><p>ExampleCorp contains fictional inventory and advisories. Switch to My uploads for an empty, temporary workspace that belongs to this session.</p><button className="button primary" disabled={session.busy} onClick={() => { void session.switchWorkspace('uploads') }}>Switch to My uploads</button></div> :
          <form onSubmit={submit} className="import-form">
            <label htmlFor="import-kind">Record type</label>
            <select id="import-kind" value={kind} disabled={upload.isPending} onChange={event => { setKind(event.target.value); setError(null) }}>{['assets', 'software', 'vulnerabilities', 'sbom', 'relationships'].map(value => <option key={value} value={value}>{value === 'sbom' ? 'SBOM · CycloneDX / SPDX' : humanize(value)}</option>)}</select>
            {kind === 'sbom' && <Lookup resource="assets" label="Owning asset" value={assetId} onChange={setAssetId} required disabled={upload.isPending} />}
            <label htmlFor="import-file">Local file *</label>
            <input id="import-file" type="file" ref={fileInput} accept={kind === 'sbom' ? '.json,.xml' : kind === 'vulnerabilities' ? '.json' : '.csv,.json'} required disabled={upload.isPending} onChange={event => { setFile(event.target.files?.[0] || null); setConsent(false) }} />
            <p className="field-help">{kind === 'sbom' ? 'CycloneDX JSON/XML and SPDX JSON. Package scripts are never executed.' : kind === 'vulnerabilities' ? 'JSON advisory snapshots. Include affected ranges and known fixes when supported by source evidence.' : 'CSV or JSON with one record per row or array item. Existing records are normalized and duplicate handling is reported.'} Maximum upload size: {maxBytes / 1024 / 1024} MiB.</p>
            {hosted && <div className="notice warning"><strong>Temporary uploads — not a storage service</strong><p>Your file is sent to the hosted API and its parsed records are stored only for this session. Server sleep/restart, expiration or reset removes access. Export results before leaving; do not upload secrets or sensitive organizational data.</p><label className="check-label"><input type="checkbox" checked={consent} onChange={event => setConsent(event.target.checked)} required />I understand that my data is processed on the server and is temporary.</label></div>}
            <ErrorNotice error={error} />
            <button className="button primary" disabled={upload.isPending}>{upload.isPending ? 'Validating & importing…' : 'Validate & import file'}</button>
          </form>}
        {job && <ImportResult job={job} />}
      </Section>
      <aside>
        <Section title="File format guide"><p>Use documented field names and explicit source information. Unknown values remain unknown; IP addresses do not imply exposure.</p><details className="details-block" open><summary>{humanize(kind)} example</summary><pre className="example-code">{examples[kind]}</pre></details><div className="import-order"><h3>Recommended order</h3><ol><li>Assets and business context</li><li>Software inventory and SBOMs</li><li>Vulnerability feed snapshots</li><li>Network relationships and observations</li><li>Correlate and inspect resulting risks</li></ol></div></Section>
        <SampleFiles />
        <Section title="Explore a synthetic environment"><p>Explore the complete ExampleCorp sample environment. All example advisories are labeled synthetic.</p><DemoButton /></Section>
      </aside>
    </div>
    <ResourceTable resource="imports" title="Import history" />
  </>
}

export function ImportDetail() {
  const { id } = useParams()
  const query = useResource('imports', id)
  const navigate = useNavigate()
  if (query.isLoading) return <Skeleton />
  if (query.error) return <ErrorNotice error={query.error} retry={() => { void query.refetch() }} />
  if (!query.data) return null
  return <><PageHeader title={text(query.data.filename)} description={`Import #${id} · Every imported or rejected row is retained for provenance.`} back={{ to: '/imports', label: 'Imports' }} actions={<button className="button" onClick={() => navigate('/risk')}>Inspect resulting risks</button>} /><Section title="Validation outcome"><ImportResult job={query.data} /><Facts data={query.data} fields={['kind', 'created_at', 'digest']} /></Section><ResourceTable resource="import-records" filters={{ import_job_id: id }} title="Row-level validation" /><ResourceTable resource="evidence" filters={{ import_job_id: id }} title="Evidence generated by this import" /></>
}
