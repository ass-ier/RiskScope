import { afterEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Graph from '../src/components/Graph'
import { mockApi, renderPage, response } from './helpers'

const graph = vi.hoisted(() => ({
  on: vi.fn(), destroy: vi.fn(), resize: vi.fn(), fit: vi.fn(), center: vi.fn(),
  zoom: vi.fn(() => 1), elements: vi.fn(() => ({ unselect: vi.fn() })),
  getElementById: vi.fn(() => ({ select: vi.fn() })),
}))
vi.mock('cytoscape', () => ({ default: vi.fn(() => graph) }))
afterEach(() => vi.unstubAllGlobals())

const data = {
  nodes: [
    { id: 'asset-1', label: 'WEB-01', kind: 'asset', data: { id: 1, hostname: 'WEB-01', evidence_id: 1 } },
    { id: 'risk-7', label: 'Synthetic contextual risk', kind: 'vulnerability', data: { id: 7, vulnerability_id: 1, evidence_ids: [1] } },
    { id: 'software-9', label: 'ExampleWeb 1.0', kind: 'software', data: { id: 9, software_id: 1, evidence_id: 1 } },
  ],
  edges: [{ id: 'affected-7', source: 'asset-1', target: 'risk-7', label: 'AFFECTED_BY', data: { evidence_ids: [1], source: 'Synthetic relationship snapshot' } }],
  truncated: true, limits: { assets: 100 },
}

describe('bounded graph investigation', () => {
  it('discloses truncation, supports zoom and keyboard node/edge inspection', async () => {
    mockApi(url => url.pathname === '/api/graph' ? response(data) : undefined)
    renderPage('/attack-paths', <Graph />)
    expect(await screen.findByText(/This graph is bounded and has been truncated/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Zoom in' }))
    expect(graph.zoom).toHaveBeenCalledWith(1.3)
    await userEvent.click(screen.getByRole('button', { name: 'Fit graph' }))
    expect(graph.fit).toHaveBeenCalledWith(undefined, 40)
    await userEvent.selectOptions(screen.getByLabelText('Node or relationship'), 'risk-7')
    expect(screen.getByRole('link', { name: 'Open full record →' })).toHaveAttribute('href', '/risk/7')
    expect(screen.getByRole('link', { name: 'Evidence #1' })).toHaveAttribute('href', '/evidence/1')
    await userEvent.selectOptions(screen.getByLabelText('Node or relationship'), 'software-9')
    expect(screen.getByRole('link', { name: 'Open full record →' })).toHaveAttribute('href', '/installations/9')
    await userEvent.selectOptions(screen.getByLabelText('Node or relationship'), 'affected-7')
    expect(screen.getByRole('heading', { name: 'AFFECTED_BY' })).toBeInTheDocument()
    expect(screen.getByText('asset-1')).toBeInTheDocument()
    expect(screen.getByText('Synthetic relationship snapshot')).toBeInTheDocument()
  })

  it('requests filtered graph data from the backend', async () => {
    const fetch = mockApi(url => url.pathname === '/api/graph' ? response(data) : undefined)
    renderPage('/attack-paths', <Graph />)
    await screen.findByLabelText('Node or relationship')
    await userEvent.click(screen.getByLabelText('Known exploitation'))
    await waitFor(() => expect(fetch).toHaveBeenCalledWith(expect.stringContaining('known_exploited=true'), expect.anything()))
  })
})
