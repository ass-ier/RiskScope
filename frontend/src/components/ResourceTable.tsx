import { useId, useState, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useRecords, useResource } from '../lib/api'
import { date, humanize, number, priority, text } from '../lib/format'
import { foreignResources, resources } from '../lib/resources'
import type { Data, Params, Values } from '../types'
import { Empty, ErrorNotice, Icon, Pill, Skeleton, Structured } from './UI'
import { RecordLink, useDebounced } from './Lookup'
import { ResourceEditor } from './Forms'

function AssetCriticality({ id }: { id: unknown }) {
  const asset = useResource('assets', typeof id === 'number' ? id : undefined)
  return <Pill value={asset.data?.criticality} />
}

export function Cell({ row, field, resource }: { row: Data; field: string; resource: string }) {
  const override = row.analyst_override as Values | undefined
  const value = ['severity', 'confidence', 'exposure', 'exploitability'].includes(field) ? override?.[field] ?? row[field] : row[field]
  if (field === 'priority') return <div className="cell-stack"><Pill value={priority(row)} />{Object.keys((row.analyst_override || {}) as Values).length > 0 && <small>Analyst reviewed</small>}</div>
  if (field === 'criticality' && resource === 'risk') return <AssetCriticality id={row.asset_id} />
  if (foreignResources[field]) return <RecordLink resource={foreignResources[field]} id={value} label={row[field.replace(/_id$/, '_name')] || (field === 'vulnerability_id' ? row.vulnerability_identifier : undefined)} />
  if (field === 'evidence_ids' && Array.isArray(value)) return <div className="inline-links">{value.map(id => <Link key={String(id)} to={`/evidence/${id}`}>Evidence #{String(id)}</Link>)}</div>
  if (['status', 'state', 'confidence', 'criticality', 'exposure', 'severity', 'lifecycle', 'reachability', 'exploitability', 'normalization_confidence'].includes(field)) return <Pill value={value} />
  if (field === 'known_exploited' || field === 'exploit_available') return <Pill value={value === true ? 'HIGH' : 'UNKNOWN'}>{value === null || value === undefined ? 'Unknown' : value ? 'Yes' : 'No known'}</Pill>
  if (field.endsWith('_at') || field.endsWith('_date') || field === 'first_seen' || field === 'last_seen') return <span className="nowrap">{date(value, field === 'created_at')}</span>
  if (field === 'direct') return <Pill value="UNKNOWN">{value === null || value === undefined ? 'Unspecified' : value ? 'Direct' : 'Transitive'}</Pill>
  if (field === 'url') return typeof value === 'string' && /^https?:\/\//.test(value) ? <a href={value} target="_blank" rel="noreferrer">{value}</a> : <span>{text(value)}</span>
  if (['snapshot', 'before', 'after', 'content', 'raw', 'factors'].includes(field) || (value && typeof value === 'object' && !Array.isArray(value))) return <details className="cell-details"><summary>Inspect {humanize(field).toLowerCase()}</summary><Structured value={value} /></details>
  if (field === 'score' || field === 'contribution' || field === 'cvss_score') return <span className="numeric">{value === null || value === undefined ? 'Unknown' : Number(value).toFixed(1)}</span>
  return <span className={['summary', 'reasoning', 'description', 'text', 'action', 'title', 'reason'].includes(field) ? 'cell-prose' : ''}>{text(value)}</span>
}

export function ResourceTable({ resource, filters = {}, columns, title, description, create = false, presets = {}, primary = false, emptyAction, pageSize = 25 }: {
  resource: string; filters?: Params; columns?: string[]; title?: string; description?: string;
  create?: boolean; presets?: Values; primary?: boolean; emptyAction?: ReactNode; pageSize?: number
}) {
  const config = resources[resource]
  const uid = useId()
  const [searchParams, setSearchParams] = useSearchParams()
  const [localSearch, setLocalSearch] = useState('')
  const [localPage, setLocalPage] = useState(1)
  const defaultSort = resource === 'risk' ? 'score' : 'id'
  const [localSort, setLocalSort] = useState(defaultSort)
  const [localOrder, setLocalOrder] = useState('desc')
  const [localFilters, setLocalFilters] = useState<Params>({})
  const [editing, setEditing] = useState(false)
  const [selected, setSelected] = useState<number[]>([])
  const search = primary ? searchParams.get('search') || '' : localSearch
  const page = primary ? Math.max(1, Number(searchParams.get('page')) || 1) : localPage
  const sort = primary ? searchParams.get('sort') || defaultSort : localSort
  const order = primary ? searchParams.get('order') || 'desc' : localOrder
  const term = useDebounced(search)
  const activeFilters: Params = primary ? Object.fromEntries(Object.keys(config?.filters || {}).map(key => [key, searchParams.get(key)])) : localFilters
  const records = useRecords(resource, { ...activeFilters, ...filters, search: term, page, page_size: pageSize, sort, order })
  const fields = columns || config?.columns || ['id', 'created_at']
  function setParam(key: string, value: string) {
    if (primary) setSearchParams(previous => {
      const next = new URLSearchParams(previous)
      if (value) next.set(key, value); else next.delete(key)
      if (key !== 'page') next.delete('page')
      return next
    }, { replace: true })
    else {
      if (key !== 'page') setLocalPage(1)
      if (key === 'search') setLocalSearch(value)
      else if (key === 'page') setLocalPage(Number(value))
      else if (key === 'sort') setLocalSort(value)
      else if (key === 'order') setLocalOrder(value)
      else setLocalFilters(v => ({ ...v, [key]: value }))
    }
  }
  const hasFilters = !!search || Object.values(activeFilters).some(Boolean)
  return <section className={`resource-section ${primary ? 'primary-table' : ''}`} aria-label={title || config?.title || resource}>
    {(title || create) && <div className="section-heading"><div><h2>{title || config?.title}</h2>{description && <p>{description}</p>}</div>{create && <button type="button" className="button small" onClick={() => setEditing(!editing)} aria-expanded={editing}><Icon name={editing ? 'close' : 'plus'} />{editing ? 'Close form' : `Add ${config?.singular || 'record'}`}</button>}</div>}
    {editing && <ResourceEditor resource={resource} presets={{ ...filters, ...presets }} onDone={() => setEditing(false)} onCancel={() => setEditing(false)} />}
    <div className="table-tools">
      <div className="search-field"><Icon name="search" /><input type="search" maxLength={200} aria-label={`Search ${title || config?.title || resource}`} placeholder={`Search ${(config?.title || resource).toLowerCase()}…`} value={search} onChange={event => setParam('search', event.target.value)} /></div>
      <div className="table-filter-fields">{Object.entries(config?.filters || {}).filter(([key]) => !(key in filters)).map(([key, options]) => <label className="compact-field" key={key} htmlFor={`${uid}-${key}`}><span>{humanize(key)}</span><select id={`${uid}-${key}`} value={String(activeFilters[key] || '')} onChange={event => setParam(key, event.target.value)}><option value="">All</option>{options.map(value => <option key={value} value={value}>{value === 'true' ? 'Yes' : value === 'false' ? 'No' : humanize(value)}</option>)}</select></label>)}</div>
      <label className="compact-field" htmlFor={`${uid}-sort`}><span>Sort by</span><select id={`${uid}-sort`} value={sort} onChange={event => setParam('sort', event.target.value)}>{Array.from(new Set([defaultSort, ...fields])).filter(f => !['snapshot', 'before', 'after', 'content', 'raw', 'tags', 'fixed_versions', 'licenses', 'hashes', 'evidence_ids', 'factors', 'criticality'].includes(f) || (f === 'criticality' && resource === 'assets')).map(key => <option key={key} value={key}>{humanize(key)}</option>)}</select></label>
      <button className="button small order-button" aria-label={`Sort ${order === 'asc' ? 'descending' : 'ascending'}`} onClick={() => setParam('order', order === 'asc' ? 'desc' : 'asc')}>{order === 'asc' ? '↑ Asc' : '↓ Desc'}</button>
    </div>
    {resource === 'risk' && selected.length > 0 && <div className="selection-bar"><strong>{selected.length} selected</strong><Link className="button small primary" to={`/risk/compare?ids=${selected.join(',')}`}>Compare risk context</Link><button className="text-button" onClick={() => setSelected([])}>Clear selection</button><span>Up to five risks</span></div>}
    {records.isLoading ? <Skeleton rows={5} /> : records.error ? <ErrorNotice error={records.error} retry={() => { void records.refetch() }} /> : !records.data?.items.length ? <Empty title={hasFilters ? 'No records match these filters' : `No ${(config?.title || 'records').toLowerCase()} yet`} action={hasFilters ? <button className="button" onClick={() => { if (primary) setSearchParams({}); else { setLocalSearch(''); setLocalFilters({}); setLocalPage(1) } }}>Clear filters</button> : emptyAction || (create ? <button className="button primary" onClick={() => setEditing(true)}>Add {config?.singular}</button> : <Link className="button" to="/imports">Import local evidence</Link>)}>{hasFilters ? 'Try a broader search or remove a filter. Existing records have not been changed.' : description || config?.description}</Empty> : <>
      <div className="table-scroll" tabIndex={0} role="region" aria-label={`${title || config?.title || resource} table; scroll for more columns`}><table>
        <thead><tr>{resource === 'risk' && <th className="select-column"><span className="sr-only">Compare</span></th>}{fields.map(field => <th key={field} scope="col">{field === 'priority' && resource === 'risk' ? 'Effective priority' : humanize(field)}</th>)}<th scope="col"><span className="sr-only">Record details</span></th></tr></thead>
        <tbody>{records.data.items.map(row => <tr key={row.id}>{resource === 'risk' && <td><input type="checkbox" aria-label={`Compare risk #${row.id}`} checked={selected.includes(row.id)} disabled={!selected.includes(row.id) && selected.length >= 5} onChange={event => setSelected(ids => event.target.checked ? [...ids, row.id] : ids.filter(id => id !== row.id))} /></td>}{fields.map((field, index) => <td key={field}>{index === 0 && !foreignResources[field] && !['snapshot', 'before', 'after', 'content'].includes(field) ? <Link className="record-title" to={`/${resource}/${row.id}`}><Cell row={row} field={field} resource={resource} /></Link> : <Cell row={row} field={field} resource={resource} />}</td>)}<td><Link className="row-open" aria-label={`Open ${config?.singular || 'record'} #${row.id}`} to={`/${resource}/${row.id}`}><Icon name="arrow" /></Link></td></tr>)}</tbody>
      </table></div>
      <div className="table-footer"><span>{number((page - 1) * pageSize + 1)}–{number(Math.min(page * pageSize, records.data.total))} of {number(records.data.total)} records{records.isFetching && <span className="muted"> · Updating…</span>}</span><div className="button-row"><button className="button small" disabled={page <= 1 || records.isFetching} onClick={() => setParam('page', String(page - 1))}>Previous</button><span>Page {page}</span><button className="button small" disabled={page * pageSize >= records.data.total || records.isFetching} onClick={() => setParam('page', String(page + 1))}>Next</button></div></div>
    </>}
  </section>
}
