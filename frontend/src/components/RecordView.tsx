import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, queryString } from '../lib/api'
import { humanize } from '../lib/format'
import { foreignResources, resources } from '../lib/resources'
import type { Data } from '../types'
import { useQueryClient } from '@tanstack/react-query'
import { ResourceEditor } from './Forms'
import { Cell } from './ResourceTable'
import { ErrorNotice, Section, Structured, useNotice } from './UI'

export function RecordView({ resource, record, fields, editable = false }: { resource: string; record: Data; fields?: string[]; editable?: boolean }) {
  const [editing, setEditing] = useState(false)
  const display = fields || Object.keys(record).filter(key => !['id', 'snapshot', 'before', 'after', 'content', 'raw', 'factors', 'reasoning', 'evidence_ids', 'analyst_override'].includes(key))
  return <Section title="Record overview" actions={editable && <button className="button small" onClick={() => setEditing(!editing)}>{editing ? 'Close editor' : 'Edit record'}</button>}>
    {editing ? <ResourceEditor resource={resource} initial={record} onDone={() => setEditing(false)} onCancel={() => setEditing(false)} /> : <dl className="record-facts">{display.map(field => <div key={field} className={['description', 'summary', 'reason', 'text', 'recommendation', 'reasoning'].includes(field) ? 'wide' : ''}><dt>{humanize(field)}</dt><dd><Cell resource={resource} row={record} field={field} /></dd></div>)}</dl>}
    {['content', 'raw', 'snapshot'].map(field => record[field] ? <details key={field} className="details-block"><summary>{humanize(field)} · structured record</summary><Structured value={record[field]} /></details> : null)}
    {record.before || record.after ? <div className="audit-diff"><section><h3>Before</h3><Structured value={record.before} /></section><section><h3>After</h3><Structured value={record.after} /></section></div> : null}
    {Array.isArray(record.evidence_ids) && <div className="inline-links">{record.evidence_ids.map(id => <Link key={String(id)} to={`/evidence/${id}`}>Evidence #{String(id)}</Link>)}</div>}
  </Section>
}

export function RecordConnections({ record }: { record: Data }) {
  const connections = Object.entries(foreignResources).filter(([field]) => !!record[field])
  if (!connections.length) return null
  return <Section title="Related records"><dl className="record-facts">{connections.map(([field, resource]) => <div key={field}><dt>{humanize(field)}</dt><dd><Cell row={record} resource={resource} field={field} /></dd></div>)}</dl></Section>
}

export function DeleteRecord({ resource, id, onDeleted }: { resource: string; id: number; onDeleted: () => void }) {
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState('')
  const [error, setError] = useState<Error | null>(null)
  const [pending, setPending] = useState(false)
  const client = useQueryClient()
  const notice = useNotice()
  if (!['relationships', 'services'].includes(resource)) return null
  return <section className="delete-section">{!open ? <button className="button danger small" onClick={() => setOpen(true)}>Remove {resources[resource].singular}</button> : <form onSubmit={async event => {
    event.preventDefault()
    setPending(true)
    setError(null)
    try {
      await api(`/${resource}/${id}${queryString({ actor: 'Local analyst', reason })}`, { method: 'DELETE' })
      await client.invalidateQueries()
      notice(`Removed ${resources[resource].singular}. Correlate again to update related risk.`)
      onDeleted()
    } catch (e) { setError(e instanceof Error ? e : new Error('Could not remove record.')) }
    finally { setPending(false) }
  }}><h3>Remove this {resources[resource].singular}?</h3><p>The observation will be removed. Audit history remains. Recalculate to update potential paths.</p><label htmlFor="delete-reason">Reason for removal *</label><input id="delete-reason" value={reason} onChange={event => setReason(event.target.value)} required /><ErrorNotice error={error} /><div className="button-row"><button className="button danger" disabled={pending}>{pending ? 'Removing…' : 'Confirm removal'}</button><button className="button" type="button" onClick={() => setOpen(false)}>Cancel</button></div></form>}</section>
}
