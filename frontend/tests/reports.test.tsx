import { afterEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { mockApi, renderPage, response, risk, asset } from './helpers'

afterEach(() => vi.unstubAllGlobals())

describe('bounded immutable report previews', () => {
  it('loads summary-only report detail, captured summary and one snapshot page', async () => {
    const fetch = mockApi()
    renderPage('/reports/1')
    expect(await screen.findByText('Captured evidence is not a security guarantee.')).toBeInTheDocument()
    expect(await screen.findByText('Synthetic vulnerable ExampleWeb', { selector: '.cell-prose' })).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledWith('/api/reports/1', expect.anything())
    expect(fetch).toHaveBeenCalledWith('/api/reports/1/summary', expect.anything())
    expect(fetch).toHaveBeenCalledWith('/api/reports/1/records/risk?page=1&page_size=25', expect.anything())
    expect(fetch.mock.calls.every(([url]) => String(url).startsWith('/api/reports/1'))).toBe(true)
    await userEvent.click(screen.getByText('Captured assessment settings'))
    expect(screen.getByText('Known exploitation')).toBeInTheDocument()
  })

  it('requests the next immutable page instead of slicing a full browser dataset', async () => {
    const fetch = mockApi(url => {
      if (url.pathname === '/api/reports/1/records/risk') {
        const page = Number(url.searchParams.get('page'))
        return response({ items: [{ ...risk, id: page, title: page === 1 ? 'Captured first page' : 'Captured second page' }], total: 26, page, page_size: 25 })
      }
      return undefined
    })
    renderPage('/reports/1')
    await screen.findByText('Captured first page', { selector: '.cell-prose' })
    expect(screen.getByText('1–25 of 26 captured records')).toBeInTheDocument()
    expect(fetch.mock.calls.some(([url]) => String(url).includes('page=2'))).toBe(false)
    await userEvent.click(screen.getByRole('button', { name: 'Next' }))
    expect(await screen.findByText('Captured second page', { selector: '.cell-prose' })).toBeInTheDocument()
    expect(screen.queryByText('Captured first page')).not.toBeInTheDocument()
    expect(fetch).toHaveBeenCalledWith('/api/reports/1/records/risk?page=2&page_size=25', expect.anything())
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
    await userEvent.selectOptions(screen.getByLabelText('Captured dataset'), 'assets')
    expect(await screen.findByRole('cell', { name: 'WEB-01' })).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledWith('/api/reports/1/records/assets?page=1&page_size=25', expect.anything())
    expect(screen.getByText('Page 1')).toBeInTheDocument()
  })

  it('preserves captured relation labels without fetching current inventory', async () => {
    const fetch = mockApi(url => url.pathname === '/api/reports/1/records/risk' ? response({
      items: [{ ...risk, asset_name: 'WEB-01 at capture', vulnerability_identifier: 'EXAMPLE-001 at capture' }],
      total: 1, page: 1, page_size: 25,
    }) : undefined)
    renderPage('/reports/1')
    expect(await screen.findByRole('link', { name: 'WEB-01 at capture' })).toHaveAttribute('href', '/assets/1')
    expect(screen.getByRole('link', { name: 'EXAMPLE-001 at capture' })).toHaveAttribute('href', '/vulnerabilities/1')
    expect(fetch.mock.calls.some(([url]) => String(url).startsWith('/api/assets') || String(url).startsWith('/api/vulnerabilities'))).toBe(false)
  })

  it('offers supporting captured datasets and handles page failures without losing exports', async () => {
    let failing = true
    const fetch = mockApi(url => url.pathname === '/api/reports/1/records/evidence' ? failing
      ? response({ detail: 'Snapshot page unavailable' }, 503)
      : response({ items: [], total: 0, page: 1, page_size: 25 }) : undefined)
    renderPage('/reports/1')
    const datasets = await screen.findByLabelText('Captured dataset')
    expect(screen.getByRole('option', { name: 'Verification history' })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: 'Reports' })).not.toBeInTheDocument()
    await userEvent.selectOptions(datasets, 'evidence')
    expect(await screen.findByRole('alert')).toHaveTextContent('Snapshot page unavailable')
    expect(screen.getByRole('link', { name: 'Download JSON' })).toHaveAttribute('href', '/api/reports/1/export?format=json')
    failing = false
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }))
    expect(await screen.findByText('No records in this snapshot')).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledWith('/api/reports/1/records/evidence?page=1&page_size=25', expect.anything())
  })

  it('isolates summary failures while keeping snapshot records available', async () => {
    mockApi(url => url.pathname === '/api/reports/1/summary' ? response({ detail: 'Captured summary unavailable' }, 503) : undefined)
    renderPage('/reports/1')
    expect(await screen.findByRole('alert')).toHaveTextContent('Captured summary unavailable')
    expect(await screen.findByText('Synthetic vulnerable ExampleWeb', { selector: '.cell-prose' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Download PDF' })).toBeInTheDocument()
  })

  it('does not retain every previously visited snapshot page in the query cache', async () => {
    mockApi(url => url.pathname.startsWith('/api/reports/1/records/') ? response({
      items: [asset], total: 51, page: Number(url.searchParams.get('page')), page_size: 25,
    }) : undefined)
    const { client } = renderPage('/reports/1')
    await screen.findByRole('button', { name: 'Next' })
    await userEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(screen.getByText('Page 2')).toBeInTheDocument())
    await waitFor(() => expect(client.getQueryCache().findAll({ queryKey: ['report-records'] })).toHaveLength(1))
  })
})
