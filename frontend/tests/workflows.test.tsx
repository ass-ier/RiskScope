import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ResourceEditor } from '../src/components/Forms'
import { mockApi, renderPage, response, risk } from './helpers'

vi.mock('../src/components/Graph', () => ({ default: () => <div>Graph</div> }))
afterEach(() => vi.unstubAllGlobals())

describe('persistent analyst interactions', () => {
  it('creates an asset through the validated schema with change attribution', async () => {
    const fetch = mockApi()
    renderPage('/assets')
    await userEvent.click(screen.getByRole('button', { name: 'Add asset' }))
    await userEvent.type(await screen.findByRole('textbox', { name: /Hostname/ }), 'NEW-ASSET')
    await userEvent.type(screen.getByRole('textbox', { name: /Reason/ }), 'Inventory verified by infrastructure team')
    await userEvent.click(screen.getByRole('button', { name: 'Create asset' }))
    await waitFor(() => {
      const request = fetch.mock.calls.find(([url, init]) => String(url).includes('/api/assets?actor=') && init?.method === 'POST')
      expect(request).toBeDefined()
      expect(JSON.parse(String(request?.[1]?.body))).toMatchObject({ hostname: 'NEW-ASSET', exposure: 'UNKNOWN', evidence_id: null })
      expect(String(request?.[0])).toContain('reason=Inventory+verified')
    })
  })

  it('keeps an unsuccessful editor open and displays field validation', async () => {
    mockApi((url, init) => url.pathname === '/api/assets' && init?.method === 'POST' ? response({ detail: 'Hostname already exists' }, 409) : undefined)
    renderPage('/assets')
    await userEvent.click(screen.getByRole('button', { name: 'Add asset' }))
    await userEvent.type(await screen.findByRole('textbox', { name: /Hostname/ }), 'WEB-01')
    await userEvent.type(screen.getByRole('textbox', { name: /Reason/ }), 'Retried inventory')
    await userEvent.click(screen.getByRole('button', { name: 'Create asset' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Hostname already exists')
    expect(screen.getByRole('textbox', { name: /Hostname/ })).toHaveValue('WEB-01')
  })

  it('shows automated and analyst priorities separately and persists review', async () => {
    const fetch = mockApi()
    renderPage('/risk/1')
    await screen.findByRole('heading', { name: 'Synthetic vulnerable ExampleWeb' })
    expect(screen.getByText('Automated priority')).toBeInTheDocument()
    expect(screen.getByText('Effective priority')).toBeInTheDocument()
    expect(screen.getByText('Authentication service.')).toBeInTheDocument()
    await userEvent.type(screen.getByRole('textbox', { name: /Reason/ }), 'Backported vendor patch is present')
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Match state' }), 'REJECTED')
    await userEvent.click(screen.getByRole('button', { name: 'Save analyst review' }))
    await waitFor(() => {
      const call = fetch.mock.calls.find(([url]) => String(url) === '/api/risk/1/review')
      expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({ actor: 'Local analyst', reason: 'Backported vendor patch is present', match_state: 'REJECTED' })
    })
  })

  it('requires explicit confirmation and evidence for analyst verification', async () => {
    const fetch = mockApi(url => url.pathname === '/api/risk/1' ? response({ ...risk, status: 'REMEDIATED' }) : undefined)
    renderPage('/risk/1')
    await screen.findByRole('heading', { name: 'Synthetic vulnerable ExampleWeb' })
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }))
    await screen.findByRole('option', { name: /Validated remediation observation/ })
    await userEvent.type(screen.getByRole('textbox', { name: /Reason/ }), 'Reviewed updated software inventory')
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Evidence' }), '1')
    await userEvent.click(screen.getByRole('button', { name: 'Verify with evidence' }))
    expect(fetch.mock.calls.some(([url]) => String(url).endsWith('/verify'))).toBe(false)
    await userEvent.click(screen.getByRole('checkbox', { name: /I reviewed the selected evidence/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Verify with evidence' }))
    await waitFor(() => {
      const call = fetch.mock.calls.find(([url]) => String(url) === '/api/risk/1/verify')
      expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({ evidence_id: 1, method: 'ANALYST', actor: 'Local analyst' })
    })
  })

  it('does not offer bypass statuses on a remediation task', async () => {
    mockApi()
    renderPage('/', <ResourceEditor resource="remediation" presets={{ risk_id: 1 }} onDone={() => {}} onCancel={() => {}} />)
    const select = await screen.findByRole('combobox', { name: 'Status' })
    expect(within(select).queryByRole('option', { name: 'Verified' })).not.toBeInTheDocument()
    expect(within(select).queryByRole('option', { name: 'Risk accepted' })).not.toBeInTheDocument()
    expect(within(select).getByRole('option', { name: 'Remediated' })).toBeInTheDocument()
  })

  it('uploads multipart evidence and shows all import counts and warnings', async () => {
    const fetch = mockApi((url, init) => url.pathname === '/api/imports/assets' && init?.method === 'POST' ? response({ id: 7, filename: 'inventory.csv', processed: 4, imported: 2, skipped: 1, rejected: 1, status: 'COMPLETED', warnings: ['One duplicate hostname was skipped.'] }) : undefined)
    renderPage('/imports')
    await userEvent.upload(screen.getByLabelText('Local file *'), new File(['hostname\nWEB-01'], 'inventory.csv', { type: 'text/csv' }))
    expect((screen.getByLabelText('Local file *') as HTMLInputElement).files).toHaveLength(1)
    // JSDOM does not update native file-input constraint validity after a simulated upload.
    fireEvent.submit(screen.getByRole('button', { name: 'Validate & import file' }).closest('form')!)
    await waitFor(() => expect(fetch.mock.calls.some(([url]) => String(url) === '/api/imports/assets')).toBe(true))
    expect(await screen.findByText('One duplicate hostname was skipped.')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Download row error report (CSV)' })).toHaveAttribute('href', '/api/imports/7/errors.csv')
    const call = fetch.mock.calls.find(([url]) => String(url) === '/api/imports/assets')
    expect(call?.[1]?.body).toBeInstanceOf(FormData)
    expect(call?.[1]?.headers).toEqual({})
  })

  it('selects risks and uses the comparison API route', async () => {
    mockApi(url => url.pathname === '/api/risk' ? response({ items: [risk, { ...risk, id: 2, title: 'Internal example risk' }], total: 2, page: 1, page_size: 25 }) : undefined)
    renderPage('/risk')
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Compare risk #1' }))
    await userEvent.click(screen.getByRole('checkbox', { name: 'Compare risk #2' }))
    await userEvent.click(screen.getByRole('link', { name: 'Compare risk context' }))
    expect(await screen.findByText('Known exposure increases environmental priority.')).toBeInTheDocument()
  })
})
