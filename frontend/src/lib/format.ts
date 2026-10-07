import type { Data, Values } from '../types'

const specialLabels: Record<string, string> = {
  ip: 'IP address', mac: 'MAC address', os: 'Operating system', cvss_score: 'CVSS score',
  cvss_version: 'CVSS version', cvss_vector: 'CVSS vector', cwe: 'CWE', sbom_id: 'SBOM',
  source_asset_id: 'Source asset', target_asset_id: 'Target asset', evidence_id: 'Evidence',
  asset_id: 'Asset', software_id: 'Software', vulnerability_id: 'Vulnerability', risk_id: 'Risk',
  case_id: 'Case', import_job_id: 'Import', installation_id: 'Installation', service_id: 'Service',
  zone_id: 'Network zone', canonical_name: 'Canonical product name', direct: 'Dependency type',
  analyst_override: 'Analyst overrides', purl: 'Package URL', due_date: 'Due date',
  known_exploited: 'Known exploitation', exploit_available: 'Public exploit available',
}

export function humanize(value: string) {
  return specialLabels[value] || value.replaceAll('_', ' ').replaceAll('-', ' ').toLowerCase().replace(/^\w/, c => c.toUpperCase())
}

export function text(value: unknown, empty = 'Not recorded'): string {
  if (value === undefined || value === null || value === '') return empty
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  if (Array.isArray(value)) return value.length ? value.map(v => text(v)).join(', ') : empty
  if (typeof value === 'object') return Object.entries(value).map(([key, v]) => `${humanize(key)}: ${text(v)}`).join(' · ')
  return String(value)
}

export function date(value: unknown, time = false) {
  if (!value) return 'Not recorded'
  const d = new Date(String(value))
  return Number.isNaN(d.getTime()) ? String(value) : new Intl.DateTimeFormat(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', ...(time ? { hour: '2-digit', minute: '2-digit' } as const : {}),
  }).format(d)
}

export function recordName(row: Values) {
  return text(row.hostname || row.identifier || row.canonical_name || row.name || row.title || row.filename || row.summary || row.original_name || row.action || row.text || `Record #${row.id}`)
}

export function priority(row: Values): string {
  const override = row.analyst_override as Values | undefined
  return text(override?.priority ?? row.priority, 'UNKNOWN')
}

export function number(value: unknown) {
  return new Intl.NumberFormat().format(Number(value ?? 0))
}

export function asData(value: unknown): Data {
  return (value && typeof value === 'object' ? value : {}) as Data
}

export const priorities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
export const exposures = ['INTERNET_FACING', 'EXTERNALLY_REACHABLE', 'INTERNAL_ONLY', 'RESTRICTED', 'ISOLATED', 'UNKNOWN']
export const riskStatuses = ['OPEN', 'ASSIGNED', 'IN_PROGRESS', 'REMEDIATED', 'VERIFIED', 'RISK_ACCEPTED', 'FALSE_POSITIVE', 'DEFERRED']
export const categories = ['VULNERABILITY', 'SOFTWARE_LIFECYCLE', 'EXPOSURE', 'CONFIGURATION', 'DEPENDENCY', 'ASSET_RISK', 'NETWORK_RISK', 'IDENTITY_RISK']
