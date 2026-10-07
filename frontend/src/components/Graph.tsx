import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import cytoscape, { type Core } from 'cytoscape'
import { Link } from 'react-router-dom'
import { api, queryString } from '../lib/api'
import { humanize, text } from '../lib/format'
import type { GraphData, Values } from '../types'
import { Empty, ErrorNotice, Pill, Skeleton, Structured } from './UI'
import { RecordLink, useDebounced } from './Lookup'

const routes: Record<string, string> = { asset: 'assets', service: 'services', software: 'software', vulnerability: 'vulnerabilities', component: 'components', zone: 'zones', risk: 'risk', sbom: 'sbom' }

export default function Graph({ assetId, sbomId }: { assetId?: number; sbomId?: number }) {
  const container = useRef<HTMLDivElement>(null)
  const cy = useRef<Core | null>(null)
  const [search, setSearch] = useState('')
  const [kind, setKind] = useState('all')
  const [critical, setCritical] = useState(false)
  const [internet, setInternet] = useState(false)
  const [exploited, setExploited] = useState(false)
  const [selection, setSelection] = useState<{ id: string; label: string; kind: string; data: Values } | null>(null)
  const term = useDebounced(search)
  const params = { asset_id: assetId, search: term, kind, critical: critical || undefined, internet: internet || undefined, known_exploited: exploited || undefined, page_size: 100 }
  const query = useQuery({
    queryKey: ['graph', sbomId, params],
    queryFn: ({ signal }) => api<GraphData>(`${sbomId ? `/sbom/${sbomId}/graph` : '/graph'}${queryString(params)}`, { signal }),
  })
  useEffect(() => {
    if (!container.current || !query.data?.nodes.length) return
    const data = query.data
    const graph = cytoscape({
      container: container.current,
      elements: [
        ...data.nodes.map(node => ({ data: { id: node.id, label: node.label, kind: node.kind, metadata: node.data } })),
        ...data.edges.map(edge => ({ data: { ...edge, kind: 'relationship', metadata: edge.data } })),
      ],
      layout: { name: 'cose', animate: false, padding: 40, nodeRepulsion: () => 10000, idealEdgeLength: () => 110, randomize: false },
      minZoom: .15, maxZoom: 3,
      style: [
        { selector: 'node', style: { label: 'data(label)', 'background-color': '#e7eef9', 'border-width': 1.5, 'border-color': '#5874a2', color: '#25344e', 'font-size': 11, 'font-family': 'system-ui, sans-serif', 'text-valign': 'bottom', 'text-margin-y': 8, width: 34, height: 34, 'text-wrap': 'wrap', 'text-max-width': '125px' } },
        { selector: 'node[kind = "asset"]', style: { shape: 'round-rectangle', width: 42, height: 34 } },
        { selector: 'node[kind = "vulnerability"]', style: { shape: 'diamond', 'background-color': '#fff1e7', 'border-color': '#b77940' } },
        { selector: 'node[kind = "internet"]', style: { 'background-color': '#dbeafe', 'border-color': '#2563eb' } },
        { selector: 'node[kind = "service"]', style: { shape: 'hexagon', 'background-color': '#edf5f1', 'border-color': '#528574' } },
        { selector: 'edge', style: { width: 1.3, 'line-color': '#a1aec0', 'target-arrow-color': '#a1aec0', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', label: 'data(label)', 'font-size': 8, color: '#596b82', 'text-rotation': 'autorotate', 'text-background-color': '#f8fafc', 'text-background-opacity': 1, 'text-background-padding': '2px' } },
        { selector: ':selected', style: { 'border-color': '#1d4ed8', 'border-width': 3, 'line-color': '#1d4ed8', 'target-arrow-color': '#1d4ed8' } },
      ],
    })
    cy.current = graph
    graph.on('tap', 'node, edge', event => {
      const target = event.target
      setSelection({ id: target.id(), label: target.data('label'), kind: target.data('kind'), data: { ...(target.data('metadata') || {}), ...(target.isEdge() ? { source_node: target.data('source'), target_node: target.data('target') } : {}) } })
    })
    const observer = new ResizeObserver(() => graph.resize())
    observer.observe(container.current)
    return () => { observer.disconnect(); graph.destroy(); cy.current = null }
  }, [query.data])
  const selected = selection && query.data && (query.data.nodes.some(node => node.id === selection.id) || query.data.edges.some(edge => edge.id === selection.id)) ? selection : null
  const ids = selected?.id.match(/(?:^|[-:])(\d+)$/)
  const selectedResource = selected?.id.startsWith('risk-') ? 'risk' : selected?.kind === 'software' && selected.data.software_id ? 'installations' : selected ? routes[selected.kind] : undefined
  const evidenceIds = [...new Set([...(Array.isArray(selected?.data.evidence_ids) ? selected.data.evidence_ids : []), ...(selected?.data.evidence_id ? [selected.data.evidence_id] : [])])]
  return <div className="graph-workspace">
    {!sbomId && <div className="graph-filters"><label>Search graph<input type="search" maxLength={200} value={search} placeholder="Asset hostname…" onChange={event => setSearch(event.target.value)} /></label><label>Node type<select value={kind} onChange={event => setKind(event.target.value)}>{['all', 'asset', 'service', 'software', 'vulnerability'].map(option => <option key={option} value={option}>{humanize(option)}</option>)}</select></label><label className="check-label"><input type="checkbox" checked={critical} onChange={event => setCritical(event.target.checked)} />Critical assets</label><label className="check-label"><input type="checkbox" checked={internet} onChange={event => setInternet(event.target.checked)} />Internet exposure</label><label className="check-label"><input type="checkbox" checked={exploited} onChange={event => setExploited(event.target.checked)} />Known exploitation</label></div>}
    <p className="notice info">Potential relationships only. A connected graph or vulnerable package does not prove exploitability or successful progression.</p>
    {query.data?.truncated && <p className="notice warning" role="status">This graph is bounded and has been truncated. Narrow the filters to inspect another portion. Limits: {text(query.data.limits)}.</p>}
    {query.isLoading ? <Skeleton rows={7} /> : query.error ? <ErrorNotice error={query.error} retry={() => { void query.refetch() }} /> : !query.data?.nodes.length ? <Empty title="No graph relationships to show">Import relationships or an SBOM, correlate the evidence, or broaden these filters.</Empty> : <div className="graph-split"><div className="graph-stage"><div className="graph-toolbar"><span>{query.data.nodes.length} nodes · {query.data.edges.length} relationships</span><div className="button-row"><button className="button small" aria-label="Zoom out" onClick={() => cy.current?.zoom((cy.current?.zoom() || 1) / 1.3)}>−</button><button className="button small" aria-label="Zoom in" onClick={() => cy.current?.zoom((cy.current?.zoom() || 1) * 1.3)}>+</button><button className="button small" onClick={() => cy.current?.fit(undefined, 40)}>Fit graph</button></div></div><div ref={container} className="cytoscape" role="img" aria-label="Interactive relationship graph. Pan and zoom, or use the accessible node and relationship selector below." /><div className="graph-key"><span>▢ Asset</span><span>◇ Vulnerability</span><span>⬡ Service</span><span>○ Other entity</span></div></div><aside className="graph-inspector"><h3>Inspect the evidence</h3><label htmlFor="graph-selection">Node or relationship</label><select id="graph-selection" value={selected?.id || ''} onChange={event => {
      const node = query.data?.nodes.find(n => n.id === event.target.value)
      const edge = query.data?.edges.find(e => e.id === event.target.value)
      const selection = node || (edge ? { id: edge.id, label: edge.label, kind: 'relationship', data: { ...edge.data, source_node: edge.source, target_node: edge.target } } : null)
      setSelection(selection)
      if (selection) { const target = cy.current?.getElementById(selection.id); cy.current?.elements().unselect(); target?.select(); if (target) cy.current?.center(target) }
    }}><option value="">Select an element</option><optgroup label="Nodes">{query.data.nodes.map(node => <option value={node.id} key={node.id}>{node.label} · {node.kind}</option>)}</optgroup><optgroup label="Relationships">{query.data.edges.map(edge => <option value={edge.id} key={edge.id}>{edge.source} → {edge.target} · {edge.label}</option>)}</optgroup></select>{selected ? <><Pill value={selected.kind} /><h3>{selected.label}</h3>{ids && selectedResource && <Link className="text-link" to={`/${selectedResource}/${ids[1]}`}>Open full record →</Link>}<div className="inline-links">{selected.data.asset_id ? <RecordLink resource="assets" id={selected.data.asset_id} /> : null}{selected.data.software_id ? <RecordLink resource="software" id={selected.data.software_id} /> : null}{selected.data.vulnerability_id ? <RecordLink resource="vulnerabilities" id={selected.data.vulnerability_id} /> : null}</div><Structured value={selected.data} />{evidenceIds.length > 0 && <><h4>Linked evidence</h4><div className="inline-links">{evidenceIds.map(id => <Link key={String(id)} to={`/evidence/${id}`}>Evidence #{String(id)}</Link>)}</div></>}</> : <p className="muted">Select a node or relationship to inspect recorded metadata, source evidence and related records. This selector also provides full keyboard access.</p>}</aside></div>}
  </div>
}
