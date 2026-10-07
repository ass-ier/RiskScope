import { useId, useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useRecords, useResource } from '../lib/api'
import { humanize, recordName, text } from '../lib/format'
import type { Data } from '../types'
import { ErrorNotice } from './UI'

export function useDebounced<T>(value: T, delay = 250): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay)
    return () => window.clearTimeout(timer)
  }, [value, delay])
  return debounced
}

export function RecordLink({ resource, id, label }: { resource: string; id: unknown; label?: unknown }) {
  const key = typeof id === 'number' || typeof id === 'string' ? id : undefined
  const query = useResource(resource, label ? undefined : key)
  if (!key) return <span className="muted">Not recorded</span>
  return <Link to={`/${resource}/${key}`} title={`${humanize(resource)} #${key}`}>{label ? text(label) : query.data ? recordName(query.data) : `${humanize(resource)} #${key}`}</Link>
}

export function Lookup({ resource, value, onChange, label, required = false, disabled = false }: {
  resource: string; value: unknown; onChange: (value: number | null) => void; label: string; required?: boolean; disabled?: boolean
}) {
  const id = useId()
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const term = useDebounced(search)
  const records = useRecords(resource, { search: term, page, page_size: 10 }, !disabled)
  const selected = useResource<Data>(resource, value ? String(value) : undefined)
  const options = records.data?.items || []
  return <div className="lookup">
    <label htmlFor={`${id}-search`}>{label}{required && <span aria-hidden="true"> *</span>}</label>
    {!disabled && <input id={`${id}-search`} type="search" maxLength={200} placeholder={`Search ${humanize(resource).toLowerCase()}…`} value={search} onChange={event => { setSearch(event.target.value); setPage(1) }} aria-label={`Search ${label.toLowerCase()} options`} />}
    <select id={`${id}-select`} aria-label={label} value={value ? String(value) : ''} required={required} disabled={disabled} onChange={event => onChange(event.target.value ? Number(event.target.value) : null)}>
      <option value="">{records.isLoading ? 'Loading options…' : `Select ${label.toLowerCase()}`}</option>
      {value && !options.some(row => row.id === Number(value)) ? <option value={String(value)}>{selected.data ? recordName(selected.data) : `${label} #${value}`}</option> : null}
      {options.map(row => <option key={row.id} value={row.id}>{recordName(row)}{row.version ? ` · ${text(row.version)}` : ''} · #{row.id}</option>)}
    </select>
    {records.error && <ErrorNotice error={records.error} retry={() => { void records.refetch() }} />}
    {!disabled && records.data && <div className="lookup-footer"><span>{records.data.total} matching {records.data.total === 1 ? 'record' : 'records'}</span><div><button type="button" aria-label={`Previous ${label.toLowerCase()} options`} disabled={page === 1} onClick={() => setPage(p => p - 1)}>←</button><span>{page}</span><button type="button" aria-label={`Next ${label.toLowerCase()} options`} disabled={page * 10 >= records.data.total} onClick={() => setPage(p => p + 1)}>→</button></div></div>}
  </div>
}
