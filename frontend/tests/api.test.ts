import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError, queryString } from '../src/lib/api'
import { cleanValues, resolvedSchema, schemaDefaults } from '../src/components/Forms'
import { priority, text } from '../src/lib/format'

afterEach(() => vi.unstubAllGlobals())

describe('API contract', () => {
  it('preserves false filters, encodes search and omits absent values', () => {
    expect(queryString({ search: 'WEB 01', active: false, page: 2, empty: '', absent: null })).toBe('?search=WEB+01&active=false&page=2')
  })
  it('sends JSON and returns persisted API data', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('{"id":42}'))
    vi.stubGlobal('fetch', fetch)
    expect(await api('/assets', { method: 'POST', body: '{"hostname":"WEB-01"}' })).toEqual({ id: 42 })
    expect(fetch).toHaveBeenCalledWith('/api/assets', expect.objectContaining({ headers: { 'Content-Type': 'application/json' } }))
  })
  it('does not set multipart content type manually', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('{"id":1}'))
    vi.stubGlobal('fetch', fetch)
    const body = new FormData()
    await api('/imports/assets', { method: 'POST', body })
    expect(fetch).toHaveBeenCalledWith('/api/imports/assets', expect.objectContaining({ body, headers: {} }))
  })
  it('renders validation field errors and HTTP status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: [{ loc: ['body', 'hostname'], msg: 'Field required' }] }), { status: 422 })))
    await expect(api('/assets')).rejects.toMatchObject({ message: 'hostname: Field required', status: 422 })
  })
  it('explains local backend connection failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))
    await expect(api('/assets')).rejects.toThrow('Cannot reach the local API')
    expect(new ApiError('No', 404).status).toBe(404)
  })
})

describe('schema field conversion', () => {
  it('retains unknown null rather than inventing false', () => {
    const schema = { properties: { known_exploited: { anyOf: [{ type: 'boolean' }, { type: 'null' }], default: null } } }
    expect(schemaDefaults(schema)).toEqual({ known_exploited: null })
    expect(resolvedSchema(schema.properties.known_exploited).type).toBe('boolean')
    expect(cleanValues({ known_exploited: null }, schema)).toEqual({ known_exploited: null })
  })
  it('parses object evidence and cleans comma arrays without accepting scalar JSON', () => {
    const schema = { properties: { content: { type: 'object' }, tags: { type: 'array' } } }
    expect(cleanValues({ content: '{"version":"2.0"}', tags: ['web', ''] }, schema)).toEqual({ content: { version: '2.0' }, tags: ['web'] })
    expect(() => cleanValues({ content: '[]' }, schema)).toThrow('must be a JSON object')
  })
  it('distinguishes analyst and automated priority', () => {
    expect(priority({ priority: 'HIGH', analyst_override: { priority: 'CRITICAL' } })).toBe('CRITICAL')
    expect(priority({ priority: 'HIGH' })).toBe('HIGH')
    expect(text(null)).toBe('Not recorded')
    expect(text(false)).toBe('No')
  })
})
