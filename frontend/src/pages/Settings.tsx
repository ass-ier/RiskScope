import { useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, useApiAction } from '../lib/api'
import { humanize } from '../lib/format'
import type { Settings as SettingsData } from '../types'
import { ErrorNotice, PageHeader, Section, Skeleton, useNotice } from '../components/UI'
import { ResourceTable } from '../components/ResourceTable'

const weightDetails: Record<string, string> = {
  cvss: 'Contribution per recorded CVSS point.',
  known_exploitation: 'Trustworthy intelligence reporting exploitation.',
  exploit_available: 'Recorded public exploit availability.',
  exposure: 'Evidence-backed reachability in this environment.',
  criticality: 'Business importance of the affected asset.',
  production: 'Production environment modifier.',
  service: 'Associated exposed service.',
  privileges: 'Privilege requirements from available evidence.',
  complexity: 'Attack complexity from available evidence.',
  path: 'Position in an evidence-backed potential path.',
}
const maximumWeights: Record<string, number> = { cvss: 10, known_exploitation: 30, exploit_available: 20, exposure: 30, criticality: 30, production: 20, service: 20, privileges: 10, complexity: 10, path: 20 }

function SettingsEditor({ initial }: { initial: SettingsData }) {
  const [values, setValues] = useState(initial)
  const action = useApiAction('/settings', 'PUT')
  const notice = useNotice()
  async function submit(event: FormEvent) {
    event.preventDefault()
    action.mutate({ ...values }, { onSuccess: () => notice('Settings saved. Risk assessments were recalculated with the new configuration.') })
  }
  return <form onSubmit={submit}><div className="settings-layout"><Section title="Deterministic risk weights" description="Adjust the contribution of evidence-backed factors. The automated score is reproducible and each factor remains inspectable."><div className="table-scroll"><table className="weights-table"><thead><tr><th>Factor</th><th>How it contributes</th><th>Weight</th></tr></thead><tbody>{Object.entries(values.weights).map(([key, value]) => <tr key={key}><th scope="row"><label htmlFor={`weight-${key}`}>{humanize(key)}</label></th><td>{weightDetails[key] || 'Configured contribution to the automated assessment.'}</td><td><input id={`weight-${key}`} type="number" min={0} max={maximumWeights[key] ?? 30} step="0.1" value={value} required onChange={event => setValues(v => ({ ...v, weights: { ...v.weights, [key]: Number(event.target.value) } }))} /></td></tr>)}</tbody></table></div></Section><div><Section title="Bounded graph analysis"><div className="settings-fields">{(['max_path_depth', 'max_paths', 'max_graph_edges'] as const).map(key => <label key={key} htmlFor={key}>{humanize(key)}<input id={key} type="number" min={key === 'max_graph_edges' ? 10 : 1} max={key === 'max_path_depth' ? 6 : key === 'max_paths' ? 500 : 1000} value={values[key]} required onChange={event => setValues(v => ({ ...v, [key]: Number(event.target.value) }))} /></label>)}</div><p className="field-help">Limits keep local analysis responsive. Graphs disclose truncation; bounded analysis is not complete path discovery.</p></Section><Section title="Contextual rules"><label className="check-label"><input type="checkbox" checked={values.lifecycle_rules} onChange={event => setValues(v => ({ ...v, lifecycle_rules: event.target.checked }))} />Software lifecycle findings</label><label className="check-label"><input type="checkbox" checked={values.configuration_rules} onChange={event => setValues(v => ({ ...v, configuration_rules: event.target.checked }))} />Configuration and asset-context findings</label><p className="field-help">These create non-CVE risks only from recorded observations. End of life does not automatically mean critical priority.</p></Section></div></div><ErrorNotice error={action.error} /><div className="save-settings"><p>Saving updates configuration and recalculates risk using the backend engine.</p><button className="button primary" disabled={action.isPending}>{action.isPending ? 'Saving & recalculating…' : 'Save settings & recalculate'}</button></div></form>
}

export function Settings() {
  const query = useQuery({ queryKey: ['settings'], queryFn: ({ signal }) => api<SettingsData>('/settings', { signal }) })
  return <><PageHeader title="Settings" description="Local, deterministic assessment configuration. No external service is required to use the workstation." />{query.isLoading ? <Skeleton rows={8} /> : query.error ? <ErrorNotice error={query.error} retry={() => { void query.refetch() }} /> : query.data && <SettingsEditor key={JSON.stringify(query.data)} initial={query.data} />}<ResourceTable resource="providers" title="Intelligence providers & local cache" description="Source, version and download metadata are recorded by the backend. Optional external integrations are disabled; this screen does not simulate a connection." /><Section title="Local operating boundaries"><p>RiskScope prioritizes risk from imported and manually recorded evidence. It does not scan hosts, exploit systems, execute packages or deploy patches. Reported uncertainty must be considered during analyst review.</p></Section></>
}
