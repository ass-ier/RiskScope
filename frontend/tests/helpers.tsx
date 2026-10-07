import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { vi } from 'vitest'
import type { Data, Metadata, Values } from '../src/types'
import App from '../src/App'
import { WorkspaceProvider } from '../src/components/Workspace'

export const asset: Data = {
  id: 1, hostname: 'WEB-01', ip: '10.0.1.10', environment: 'PRODUCTION', criticality: 'CRITICAL',
  exposure: 'INTERNET_FACING', owner: 'Infrastructure', status: 'ACTIVE', source: 'inventory.csv',
  confidence: 'HIGH', evidence_id: 1,
}
export const risk: Data = {
  id: 1, title: 'Synthetic vulnerable ExampleWeb', category: 'VULNERABILITY',
  asset_id: 1, vulnerability_id: 1, match_id: null, score: 87, priority: 'HIGH', status: 'OPEN',
  severity: 'HIGH', confidence: 'HIGH', exposure: 'INTERNET_FACING', exploitability: 'KNOWN_EXPLOITED',
  factors: [{ name: 'exposure', value: 'INTERNET_FACING', contribution: 16, evidence_ids: [1], reasoning: 'Observed externally reachable service.' }],
  reasoning: ['The affected software runs on a critical production asset.'], uncertainties: ['Reachability requires confirmation.'],
  evidence_ids: [1], analyst_override: { priority: 'CRITICAL' }, analyst_reason: 'Authentication service.',
  recommendation: 'Apply the recorded vendor fix.', rules_version: '1.0',
}
export const evidence: Data = { id: 1, summary: 'Validated remediation observation', source: 'Manual', type: 'REMEDIATION_EVIDENCE', confidence: 'HIGH', actor: 'Local analyst', content: {} }
export const vulnerability: Data = { id: 1, identifier: 'EXAMPLE-001', title: 'Synthetic advisory', cvss_score: 9.8, known_exploited: true, exploit_available: null, source: 'Synthetic fixture', synthetic: true }
export const metadata: Metadata = {
  assets: {
    writable: true,
    schema: {
      type: 'object', required: ['hostname'],
      properties: {
        hostname: { type: 'string', minLength: 1 }, ip: { type: 'string', default: '' },
        environment: { type: 'string', enum: ['PRODUCTION', 'LAB', 'UNKNOWN'], default: 'UNKNOWN' },
        criticality: { type: 'string', enum: ['CRITICAL', 'LOW', 'UNKNOWN'], default: 'UNKNOWN' },
        exposure: { type: 'string', enum: ['INTERNET_FACING', 'INTERNAL_ONLY', 'UNKNOWN'], default: 'UNKNOWN' },
        source: { type: 'string', default: 'Manual' },
        evidence_id: { anyOf: [{ type: 'integer' }, { type: 'null' }], default: null },
      },
    },
  },
  remediation: {
    writable: true,
    schema: {
      required: ['risk_id', 'action'], properties: {
        risk_id: { type: 'integer' }, action: { type: 'string', minLength: 1 }, owner: { type: 'string', default: '' },
        due_date: { anyOf: [{ type: 'string' }, { type: 'null' }], default: null },
        status: { type: 'string', enum: ['OPEN', 'ASSIGNED', 'IN_PROGRESS', 'REMEDIATED', 'VERIFIED', 'RISK_ACCEPTED', 'FALSE_POSITIVE', 'DEFERRED'], default: 'OPEN' },
      },
    },
  },
}
export const settings = { weights: { cvss: 3, known_exploitation: 18, exploit_available: 6, exposure: 16, criticality: 14, production: 6, service: 4, privileges: 3, complexity: 3, path: 6 }, max_path_depth: 4, max_paths: 200, max_graph_edges: 500, lifecycle_rules: true, configuration_rules: true }
export const dashboard = { totals: { assets: 1, software: 1, installations: 1, vulnerabilities: 1, risks: 1, active_risks: 1 }, priorities: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 }, internet_exposed: 1, known_exploited: 1, overdue: 0, top_risks: [], top_assets: [], top_vulnerabilities: [], remediation: {}, trend: [] }

export const records: Record<string, Data[]> = {
  assets: [asset], risk: [risk], evidence: [evidence], vulnerabilities: [vulnerability],
  software: [{ id: 1, canonical_name: 'ExampleWeb', vendor: 'ExampleCorp', ecosystem: 'generic', lifecycle: 'SUPPORTED' }],
  cases: [{ id: 1, title: 'Critical perimeter investigation', status: 'OPEN', owner: 'Analyst' }],
  sbom: [{ id: 1, name: 'Application SBOM', asset_id: 1, format: 'CycloneDX' }],
  imports: [{ id: 1, filename: 'assets.csv', kind: 'assets', status: 'COMPLETED', imported: 1, rejected: 0, processed: 1, skipped: 0, warnings: [] }],
  reports: [{ id: 1, title: 'Quarterly posture', perspective: 'technical', created_at: '2026-10-07T12:00:00Z', updated_at: '2026-10-07T12:00:00Z' }],
}

export function response(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

export function mockApi(handler?: (url: URL, init?: RequestInit) => Response | undefined) {
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost')
    const custom = handler?.(url, init)
    if (custom) return custom
    const parts = url.pathname.replace('/api/', '').split('/')
    const [resource, id] = parts
    if (resource === 'runtime') return response({ mode: 'local', max_upload_bytes: 10 * 1024 * 1024 })
    if (resource === 'examples') return response([])
    if (resource === 'meta') return response(metadata)
    if (resource === 'dashboard') return response(dashboard)
    if (resource === 'settings') return response(settings)
    if (resource === 'reports' && parts[2] === 'summary') return response({
      dashboard, generated_at: '2026-10-07T12:00:00Z',
      scope: 'All local records, including historical risks',
      disclaimer: 'Captured evidence is not a security guarantee.', settings,
    })
    if (resource === 'reports' && parts[2] === 'records') {
      const items = records[parts[3]] || []
      return response({ items, total: items.length, page: Number(url.searchParams.get('page') || 1), page_size: Number(url.searchParams.get('page_size') || 25) })
    }
    if (resource === 'risk' && id === 'compare') return response({ items: [risk], explanation: ['Known exposure increases environmental priority.'] })
    if (init?.method && init.method !== 'GET') return response({ id: 2, ...JSON.parse(typeof init.body === 'string' ? init.body : '{}') as Values })
    if (id) return response(records[resource]?.find(row => row.id === Number(id)) || { id: Number(id), name: `${resource} ${id}` })
    const items = records[resource] || []
    return response({ items, total: items.length, page: Number(url.searchParams.get('page') || 1), page_size: Number(url.searchParams.get('page_size') || 25) })
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

export function renderPage(path = '/', element?: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } })
  return { client, ...render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}>{element ? <WorkspaceProvider>{element}</WorkspaceProvider> : <App />}</MemoryRouter></QueryClientProvider>) }
}
