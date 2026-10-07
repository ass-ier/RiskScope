import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { mockApi, renderPage, response, asset, dashboard } from './helpers'

vi.mock('../src/components/Graph', () => ({ default: () => <div>Bounded interactive relationship graph</div> }))
afterEach(() => vi.unstubAllGlobals())
beforeEach(() => mockApi())

describe('workstation route coverage', () => {
  it.each([
    ['/', 'Security posture'], ['/assets', 'Assets'], ['/assets/1', 'WEB-01'],
    ['/software', 'Software'], ['/software/1', 'ExampleWeb'],
    ['/vulnerabilities', 'Vulnerabilities'], ['/vulnerabilities/1', 'EXAMPLE-001'],
    ['/risk', 'Risk register'], ['/risk/1', 'Synthetic vulnerable ExampleWeb'],
    ['/risk/compare?ids=1', 'Compare risk context'], ['/risk/new', 'Record a non-CVE risk'],
    ['/attack-paths', 'Attack paths & surface'], ['/sbom', 'SBOM'], ['/sbom/1', 'Application SBOM'],
    ['/imports', 'Imports'], ['/imports/1', 'assets.csv'], ['/remediation', 'Remediation'],
    ['/cases', 'Cases'], ['/cases/1', 'Critical perimeter investigation'],
    ['/reports', 'Reports'], ['/reports/1', 'Quarterly posture'], ['/timeline', 'Timeline & audit'], ['/settings', 'Settings'],
  ])('renders %s with real query-connected content', async (path, title) => {
    renderPage(path)
    expect(await screen.findByRole('heading', { name: title, level: 1 })).toBeInTheDocument()
    if (path !== '/attack-paths') await waitFor(() => expect(fetch).toHaveBeenCalled())
  })

  it('guides an empty environment without inventing trends', async () => {
    mockApi(url => url.pathname === '/api/dashboard' ? response({ ...dashboard, totals: { assets: 0 } }) : undefined)
    renderPage()
    expect(await screen.findByText('Start with the environment, not the score.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Load synthetic demo' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Import local inventory' })).toHaveAttribute('href', '/imports')
  })

  it('shows server failure and offers a working retry', async () => {
    let failing = true
    mockApi(url => url.pathname === '/api/assets' && failing ? response({ detail: 'Database unavailable' }, 503) : undefined)
    renderPage('/assets')
    expect(await screen.findByRole('alert')).toHaveTextContent('Database unavailable')
    failing = false
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }))
    expect(await screen.findByRole('link', { name: 'WEB-01' })).toBeInTheDocument()
  })

  it('filters and paginates on the server instead of loading every record', async () => {
    const fetch = mockApi(url => url.pathname === '/api/assets' ? response({ items: [asset], total: 120, page: Number(url.searchParams.get('page')), page_size: 25 }) : undefined)
    renderPage('/assets')
    await screen.findByRole('link', { name: 'WEB-01' })
    await userEvent.selectOptions(screen.getByLabelText('Criticality'), 'CRITICAL')
    await waitFor(() => expect(fetch).toHaveBeenCalledWith(expect.stringContaining('criticality=CRITICAL'), expect.anything()))
    await userEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(fetch).toHaveBeenCalledWith(expect.stringContaining('page=2&page_size=25'), expect.anything()))
    await userEvent.type(screen.getByRole('searchbox', { name: 'Search Assets' }), 'WEB')
    await waitFor(() => expect(fetch).toHaveBeenCalledWith(expect.stringContaining('search=WEB&page=1'), expect.anything()))
  })

  it('keeps saved reports tied to server snapshot download endpoints', async () => {
    renderPage('/reports/1')
    await screen.findByRole('heading', { name: 'Quarterly posture' })
    expect(screen.getByRole('link', { name: 'Download PDF' })).toHaveAttribute('href', '/api/reports/1/export?format=pdf')
    expect(screen.getByRole('link', { name: 'Risk register · CSV' })).toHaveAttribute('href', '/api/reports/1/export?format=csv&dataset=risk')
    expect(screen.getByRole('link', { name: 'Asset inventory · CSV' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Vulnerability inventory · CSV' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Remediation tracker · CSV' })).toBeInTheDocument()
  })

  it('opens responsive navigation and closes it with Escape', async () => {
    renderPage('/assets')
    const menu = await screen.findByRole('button', { name: 'Open navigation' })
    await userEvent.click(menu)
    expect(screen.getByRole('button', { name: 'Close navigation', expanded: true })).toBeInTheDocument()
    await userEvent.keyboard('{Escape}')
    expect(screen.getByRole('button', { name: 'Open navigation' })).toHaveFocus()
  })
})
