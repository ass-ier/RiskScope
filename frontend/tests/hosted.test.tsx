import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { configureSession } from '../src/lib/api'
import { mockApi, renderPage, response } from './helpers'
import { DownloadLink } from '../src/components/DownloadLink'

const token = 'x'.repeat(43)
const key = `riskscope.guest:${window.location.origin}`
const runtime = {
  mode: 'hosted', max_upload_bytes: 2 * 1024 * 1024, idle_seconds: 3600,
  maximum_lifetime_seconds: 14400, workspace_bytes: 32 * 1024 * 1024, max_correlations: 5000,
}
const info = { expires_at: '2026-10-08T01:00:00Z', maximum_expires_at: '2026-10-08T04:00:00Z', remaining_seconds: 3600 }

function hostedApi(handler?: (url: URL, init?: RequestInit) => Response | undefined) {
  return mockApi((url, init) => {
    const custom = handler?.(url, init)
    if (custom) return custom
    if (url.pathname === '/api/runtime') return response(runtime)
    if (url.pathname === '/api/session') return init?.method === 'DELETE'
      ? new Response(null, { status: 204 })
      : response(init?.method === 'POST' ? { ...info, token } : info)
    return undefined
  })
}

beforeEach(() => { sessionStorage.clear(); configureSession(null) })
afterEach(() => { sessionStorage.clear(); configureSession(null); vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('anonymous temporary workspaces', () => {
  it('opens the complete demo without sign-in and explains temporary server storage', async () => {
    const fetch = hostedApi()
    renderPage('/')
    expect(await screen.findByText('Temporary session · No sign-in')).toBeInTheDocument()
    expect(screen.getByLabelText('Workspace')).toHaveValue('demo')
    expect(screen.queryByText('Evidence stays in your environment')).not.toBeInTheDocument()
    await userEvent.click(screen.getByText('When is my data removed?'))
    expect(screen.getByText(/Closing a tab does not immediately erase server data/)).toBeInTheDocument()
    expect(screen.getByText(/No backups/)).toBeInTheDocument()
    expect(fetch.mock.calls.filter(([url, init]) => String(url) === '/api/session' && init?.method === 'POST')).toHaveLength(1)
  })

  it('keeps imports separate and requires an explicit temporary-upload acknowledgement', async () => {
    const fetch = hostedApi((url, init) => url.pathname === '/api/imports/assets' && init?.method === 'POST'
      ? response({ id: 9, filename: 'assets.csv', processed: 1, imported: 1, skipped: 0, rejected: 0, warnings: [], status: 'COMPLETED' })
      : undefined)
    renderPage('/imports')
    await userEvent.click(await screen.findByRole('button', { name: 'Switch to My uploads' }))
    const file = await screen.findByLabelText('Local file *')
    await userEvent.upload(file, new File(['hostname\nMY-ASSET'], 'assets.csv', { type: 'text/csv' }))
    const submit = screen.getByRole('button', { name: 'Validate & import file' })
    fireEvent.submit(submit.closest('form')!)
    expect(await screen.findByRole('alert')).toHaveTextContent('Acknowledge temporary server processing')
    expect(fetch.mock.calls.some(([url]) => String(url) === '/api/imports/assets')).toBe(false)
    await userEvent.click(screen.getByRole('checkbox', { name: /processed on the server and is temporary/ }))
    fireEvent.submit(submit.closest('form')!)
    await waitFor(() => expect(fetch.mock.calls.some(([url]) => String(url) === '/api/imports/assets')).toBe(true))
    const call = fetch.mock.calls.find(([url]) => String(url) === '/api/imports/assets')
    expect(new Headers(call?.[1]?.headers).get('Authorization')).toBe(`Bearer ${token}`)
    expect(new Headers(call?.[1]?.headers).get('X-RiskScope-Workspace')).toBe('uploads')
    expect(new Headers(call?.[1]?.headers).has('Content-Type')).toBe(false)
  })

  it('restores a valid tab session without creating another one', async () => {
    sessionStorage.setItem(key, JSON.stringify({ token, workspace: 'uploads' }))
    const fetch = hostedApi()
    renderPage('/assets')
    await screen.findByRole('heading', { name: 'Assets' })
    expect(screen.getByLabelText('Workspace')).toHaveValue('uploads')
    expect(fetch.mock.calls.some(([url, init]) => String(url) === '/api/session' && init?.method === 'POST')).toBe(false)
  })

  it('does not silently replace an expired session or expose stale records', async () => {
    sessionStorage.setItem(key, JSON.stringify({ token, workspace: 'uploads' }))
    const fetch = hostedApi((url, init) => url.pathname === '/api/session' && init?.method !== 'POST'
      ? response({ detail: 'Your temporary session expired or the server restarted.' }, 410)
      : undefined)
    renderPage('/assets')
    expect(await screen.findByRole('heading', { name: 'Temporary session ended' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Assets' })).not.toBeInTheDocument()
    expect(fetch.mock.calls.some(([url, init]) => String(url) === '/api/session' && init?.method === 'POST')).toBe(false)
    expect(sessionStorage.getItem(key)).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Start empty workspace' }))
    expect(await screen.findByText('Temporary uploads — not a storage service')).toBeInTheDocument()
  })

  it('requires confirmation before ending and deletes the saved capability', async () => {
    const fetch = hostedApi()
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    renderPage('/')
    await userEvent.click(await screen.findByRole('button', { name: 'End session' }))
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false)
    confirm.mockReturnValue(true)
    await userEvent.click(screen.getByRole('button', { name: 'End session' }))
    expect(await screen.findByRole('heading', { name: 'Temporary session ended' })).toBeInTheDocument()
    expect(sessionStorage.getItem(key)).toBeNull()
  })

  it('clears displayed records when the server-reported deadline arrives', async () => {
    sessionStorage.setItem(key, JSON.stringify({ token, workspace: 'uploads' }))
    const fetch = hostedApi(url => url.pathname === '/api/session'
      ? response({ ...info, remaining_seconds: 1 }) : undefined)
    renderPage('/assets')
    await screen.findByRole('link', { name: 'WEB-01' })
    expect(await screen.findByRole('heading', { name: 'Temporary session ended' }, { timeout: 2500 })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'WEB-01' })).not.toBeInTheDocument()
    expect(sessionStorage.getItem(key)).toBeNull()
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })

  it('downloads reports using the session header rather than exposing a token in the URL', async () => {
    const fetch = hostedApi(url => url.pathname === '/api/reports/1/export'
      ? new Response('%PDF-test', { headers: { 'Content-Disposition': 'attachment; filename="report.pdf"' } })
      : undefined)
    const NativeURL = URL
    vi.stubGlobal('URL', class extends NativeURL {
      static createObjectURL = vi.fn(() => 'blob:download-test')
      static revokeObjectURL = vi.fn()
    })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    renderPage('/', <DownloadLink path="/reports/1/export?format=pdf">Download test report</DownloadLink>)
    await userEvent.click(await screen.findByRole('link', { name: 'Download test report' }))
    await waitFor(() => expect(click).toHaveBeenCalled())
    const call = fetch.mock.calls.find(([url]) => String(url) === '/api/reports/1/export?format=pdf')
    expect(new Headers(call?.[1]?.headers).get('Authorization')).toBe(`Bearer ${token}`)
    expect(call?.[1]?.credentials).toBe('omit')
  })
})
