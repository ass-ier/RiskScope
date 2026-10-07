import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError, configureSession, queryString } from '../src/lib/api'
import { cleanValues, resolvedSchema, schemaDefaults } from '../src/components/Forms'
import { priority, text } from '../src/lib/format'

afterEach(() => { configureSession(null); vi.unstubAllGlobals() })

describe('API contract', () => {
  it('preserves false filters, encodes search and omits absent values', () => {
    expect(queryString({ search: 'WEB 01', active: false, page: 2, empty: '', absent: null })).toBe('?search=WEB+01&active=false&page=2')
  })
  it('sends JSON and returns persisted API data', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('{"id":42}'))
    vi.stubGlobal('fetch', fetch)
    expect(await api('/assets', { method: 'POST', body: '{"hostname":"WEB-01"}' })).toEqual({ id: 42 })
    expect(fetch).toHaveBeenCalledWith('/api/assets', expect.objectContaining({ credentials: 'omit', cache: 'no-store' }))
    expect(new Headers(fetch.mock.calls[0][1].headers).get('Content-Type')).toBe('application/json')
  })
  it('does not set multipart content type manually', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('{"id":1}'))
    vi.stubGlobal('fetch', fetch)
    const body = new FormData()
    await api('/imports/assets', { method: 'POST', body })
    expect(fetch).toHaveBeenCalledWith('/api/imports/assets', expect.objectContaining({ body }))
    expect(new Headers(fetch.mock.calls[0][1].headers).has('Content-Type')).toBe(false)
  })
  it('renders validation field errors and HTTP status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: [{ loc: ['body', 'hostname'], msg: 'Field required' }] }), { status: 422 })))
    await expect(api('/assets')).rejects.toMatchObject({ message: 'hostname: Field required', status: 422 })
  })
  it('explains local backend connection failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))
    await expect(api('/assets')).rejects.toThrow('Cannot reach the RiskScope API')
    expect(new ApiError('No', 404).status).toBe(404)
  })
  it('scopes anonymous requests without cookies or URL tokens', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('{"id":42}'))
    vi.stubGlobal('fetch', fetch)
    configureSession('test-capability', 'uploads')
    await api('/assets')
    const [url, request] = fetch.mock.calls[0]
    expect(url).toBe('/api/assets')
    expect(request.credentials).toBe('omit')
    expect(request.headers.get('Authorization')).toBe('Bearer test-capability')
    expect(request.headers.get('X-RiskScope-Workspace')).toBe('uploads')
  })
  it('does not expire a new session when an old request finishes late', async () => {
    let complete: (response: Response) => void = () => { throw new Error('Request was not started') }
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(resolve => { complete = resolve })))
    const expired = vi.fn()
    window.addEventListener('riskscope:session-expired', expired)
    configureSession('old-capability', 'uploads')
    const pending = api('/assets')
    configureSession('new-capability', 'demo')
    complete(new Response('{"detail":"Old session expired"}', { status: 410 }))
    await expect(pending).rejects.toMatchObject({ status: 410 })
    expect(expired).not.toHaveBeenCalled()
    window.removeEventListener('riskscope:session-expired', expired)
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
