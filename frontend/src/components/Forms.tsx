import { useId, useState, type FormEvent } from 'react'
import { useApiAction, useMetadata, queryString } from '../lib/api'
import { humanize, recordName } from '../lib/format'
import { foreignResources, resources } from '../lib/resources'
import type { Data, Schema, Values } from '../types'
import { ErrorNotice, Skeleton, useNotice } from './UI'
import { Lookup } from './Lookup'

export function resolvedSchema(schema: Schema): Schema {
  return schema.anyOf ? { ...schema, ...schema.anyOf.find(option => option.type !== 'null') } : schema
}

export function schemaDefaults(schema: Schema, initial: Values = {}, presets: Values = {}): Values {
  const output: Values = {}
  Object.entries(schema.properties || {}).forEach(([key, spec]) => {
    if (key in initial) output[key] = initial[key]
    else if (spec.default !== undefined) output[key] = spec.default
    else if (resolvedSchema(spec).type === 'array') output[key] = []
    else if (resolvedSchema(spec).type === 'object') output[key] = {}
  })
  return { ...output, ...presets }
}

export function Field({ name, schema: raw, value, onChange, required = false, disabled = false }: {
  name: string; schema: Schema; value: unknown; onChange: (value: unknown) => void; required?: boolean; disabled?: boolean
}) {
  const id = useId()
  const schema = resolvedSchema(raw)
  const nullable = raw.anyOf?.some(option => option.type === 'null')
  const label = humanize(name)
  if (foreignResources[name]) return <Lookup resource={foreignResources[name]} value={value} onChange={onChange} label={label} required={required} disabled={disabled} />
  const base = { id, name, required, disabled, 'aria-describedby': schema.description ? `${id}-help` : undefined }
  let control
  if (schema.enum) {
    const options = name === 'status' && schema.enum.includes('RISK_ACCEPTED') ? ['OPEN', 'ASSIGNED', 'IN_PROGRESS', 'REMEDIATED'] : schema.enum
    control = <select {...base} value={value === null || value === undefined ? '' : String(value)} onChange={event => onChange(event.target.value || null)}><option value="">{nullable ? 'No override / not recorded' : 'Select an option'}</option>{value && !options.includes(String(value)) ? <option value={String(value)} disabled>{humanize(String(value))} · dedicated risk action</option> : null}{options.map(option => <option key={String(option)} value={String(option)}>{humanize(String(option))}</option>)}</select>
  } else if (schema.type === 'boolean') {
    control = <select {...base} value={value === undefined || value === null ? '' : String(value)} onChange={event => onChange(event.target.value === '' ? null : event.target.value === 'true')}><option value="">{nullable ? 'Unknown' : 'Select an option'}</option><option value="true">Yes</option><option value="false">No</option></select>
  } else if (schema.type === 'array') {
    control = <input {...base} type="text" placeholder="Separate values with commas" value={Array.isArray(value) ? value.join(', ') : String(value || '')} onChange={event => onChange(event.target.value.split(',').map(v => v.trim()))} />
  } else if (schema.type === 'object') {
    control = <textarea {...base} rows={4} spellCheck={false} value={typeof value === 'string' ? value : JSON.stringify(value || {}, null, 2)} onChange={event => onChange(event.target.value)} placeholder="{}" />
  } else if (schema.type === 'integer' || schema.type === 'number') {
    control = <input {...base} type="number" min={schema.minimum} max={schema.maximum} step={schema.type === 'integer' ? 1 : 'any'} value={value === null || value === undefined ? '' : String(value)} onChange={event => onChange(event.target.value === '' ? null : Number(event.target.value))} />
  } else if (['description', 'summary', 'reason', 'recommendation', 'action', 'text', 'note', 'compensating_controls', 'business_function', 'regulatory_importance'].includes(name)) {
    control = <textarea {...base} rows={3} minLength={schema.minLength} maxLength={schema.maxLength} value={String(value || '')} onChange={event => onChange(event.target.value)} />
  } else {
    const type = name === 'url' ? 'url' : name === 'due_date' ? 'date' : name === 'expires_at' ? 'datetime-local' : 'text'
    control = <input {...base} type={type} minLength={schema.minLength} maxLength={schema.maxLength} value={String(value || '').slice(0, type === 'date' ? 10 : type === 'datetime-local' ? 16 : undefined)} onChange={event => onChange(event.target.value || (nullable ? null : ''))} />
  }
  return <div className={`field ${schema.type === 'object' || ['description', 'summary', 'reason', 'recommendation', 'text', 'action', 'note', 'compensating_controls'].includes(name) ? 'field-wide' : ''}`}><label htmlFor={id}>{label}{required && <span aria-hidden="true"> *</span>}{schema.type === 'object' && ' (JSON object)'}</label>{control}{schema.description && <small id={`${id}-help`}>{schema.description}</small>}</div>
}

export function cleanValues(values: Values, schema: Schema): Values {
  const output = { ...values }
  Object.entries(schema.properties || {}).forEach(([key, spec]) => {
    const type = resolvedSchema(spec).type
    if (type === 'object' && typeof output[key] === 'string') {
      const parsed: unknown = JSON.parse(output[key] as string)
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`${humanize(key)} must be a JSON object.`)
      output[key] = parsed
    }
    if (type === 'array' && Array.isArray(output[key])) output[key] = (output[key] as unknown[]).filter(v => v !== '')
    if (output[key] === null && !spec.anyOf?.some(x => x.type === 'null')) delete output[key]
  })
  return output
}

export function ResourceEditor({ resource, initial, presets = {}, onDone, onCancel }: { resource: string; initial?: Data; presets?: Values; onDone: (record: Data) => void; onCancel: () => void }) {
  const metadata = useMetadata()
  if (metadata.isLoading) return <Skeleton />
  if (metadata.error) return <ErrorNotice error={metadata.error} retry={() => { void metadata.refetch() }} />
  const schema = metadata.data?.[resource]?.schema
  if (!schema || !metadata.data?.[resource].writable) return <ErrorNotice error={new Error('This resource is read-only. Use its dedicated workflow to make changes.')} />
  return <EditorBody key={`${resource}-${initial?.id || 'new'}`} resource={resource} initial={initial} presets={presets} schema={schema} onDone={onDone} onCancel={onCancel} />
}

function EditorBody({ resource, initial, presets, schema, onDone, onCancel }: { resource: string; initial?: Data; presets: Values; schema: Schema; onDone: (record: Data) => void; onCancel: () => void }) {
  const [values, setValues] = useState(() => schemaDefaults(schema, initial, presets))
  const [actor, setActor] = useState('Local analyst')
  const [reason, setReason] = useState('')
  const [localError, setLocalError] = useState<Error | null>(null)
  const action = useApiAction(`/${resource}${initial ? `/${initial.id}` : ''}${queryString({ actor, reason })}`, initial ? 'PATCH' : 'POST')
  const notice = useNotice()
  const fields = Object.entries(schema.properties || {})
  const provenance = ['source', 'confidence', 'evidence_id', 'content', 'actor']
  const renderField = ([key, field]: [string, Schema]) => <Field key={key} name={key} schema={field} value={values[key]} onChange={value => setValues(v => ({ ...v, [key]: value }))} required={schema.required?.includes(key)} disabled={key in presets} />
  async function submit(event: FormEvent) {
    event.preventDefault()
    setLocalError(null)
    try {
      const record = await action.mutateAsync(cleanValues(values, schema))
      notice(`${initial ? 'Updated' : 'Created'} ${resources[resource]?.singular || resource}: ${recordName(record)}.`)
      onDone(record)
    } catch (error) { setLocalError(error instanceof Error ? error : new Error('Save failed.')) }
  }
  return <form className="editor" onSubmit={submit}>
    <div className="editor-heading"><h3>{initial ? 'Edit' : 'New'} {resources[resource]?.singular || resource}</h3><p>Saved to your local database. Required fields are marked *.</p></div>
    <div className="form-grid">{fields.filter(([key]) => !provenance.includes(key)).map(renderField)}</div>
    {fields.some(([key]) => provenance.includes(key)) && <fieldset><legend>Source & evidence</legend><div className="form-grid">{fields.filter(([key]) => provenance.includes(key)).map(renderField)}</div></fieldset>}
    {resource === 'remediation' && <p className="notice info">To accept, reject, defer or verify a risk, open the linked risk and use its dedicated analyst action. Verification requires evidence.</p>}
    <fieldset><legend>Change attribution</legend><div className="form-grid"><Field name="actor" schema={{ type: 'string', maxLength: 200 }} value={actor} onChange={v => setActor(String(v))} required /><Field name="reason" schema={{ type: 'string', minLength: 1 }} value={reason} onChange={v => setReason(String(v))} required /></div></fieldset>
    <ErrorNotice error={localError} />
    <div className="button-row"><button type="submit" className="button primary" disabled={action.isPending}>{action.isPending ? 'Saving…' : initial ? 'Save changes' : `Create ${resources[resource]?.singular || 'record'}`}</button><button type="button" className="button" onClick={onCancel} disabled={action.isPending}>Cancel</button></div>
  </form>
}

export function ActionForm({ path, schema, title, submitLabel, initial = {}, onDone, method = 'POST', children }: {
  path: string; schema: Schema; title?: string; submitLabel: string; initial?: Values; onDone?: (record: Data) => void; method?: string; children?: React.ReactNode
}) {
  const [values, setValues] = useState(() => schemaDefaults(schema, initial))
  const [localError, setLocalError] = useState<Error | null>(null)
  const action = useApiAction(path, method)
  const notice = useNotice()
  async function submit(event: FormEvent) {
    event.preventDefault()
    setLocalError(null)
    try {
      const input = cleanValues({ ...initial, ...values }, schema)
      if (input.expires_at) input.expires_at = new Date(String(input.expires_at)).toISOString()
      const record = await action.mutateAsync(input)
      notice(`${submitLabel} completed and recorded.`)
      onDone?.(record)
    } catch (error) { setLocalError(error instanceof Error ? error : new Error('Save failed.')) }
  }
  return <form className="editor" onSubmit={submit}>{title && <h3>{title}</h3>}<div className="form-grid">{Object.entries(schema.properties || {}).map(([name, field]) => <Field key={name} name={name} schema={field} value={values[name]} onChange={value => setValues(v => ({ ...v, [name]: value }))} required={schema.required?.includes(name)} />)}</div>{children}<ErrorNotice error={localError} /><button type="submit" className="button primary" disabled={action.isPending}>{action.isPending ? 'Saving…' : submitLabel}</button></form>
}
