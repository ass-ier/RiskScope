export type Data = Record<string, unknown> & { id: number }
export type Values = Record<string, unknown>
export type Params = Record<string, string | number | boolean | undefined | null>

export interface Page<T = Data> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export interface Schema {
  title?: string
  type?: string
  enum?: (string | number | boolean)[]
  anyOf?: Schema[]
  properties?: Record<string, Schema>
  required?: string[]
  default?: unknown
  items?: Schema
  minimum?: number
  maximum?: number
  minLength?: number
  maxLength?: number
  format?: string
  description?: string
}

export type Metadata = Record<string, { writable: boolean; schema: Schema | null }>

export interface Factor {
  name: string
  value: string
  contribution: number
  evidence_ids: number[]
  reasoning: string
}

export interface Risk extends Data {
  title: string
  asset_id: number
  vulnerability_id: number | null
  match_id: number | null
  score: number
  priority: string
  status: string
  factors: Factor[]
  reasoning: string[]
  uncertainties: string[]
  evidence_ids: number[]
  analyst_override: Record<string, string>
  analyst_reason: string
  recommendation: string
}

export interface Dashboard {
  totals: Record<string, number>
  priorities: Record<string, number>
  internet_exposed: number
  known_exploited: number
  overdue: number
  top_risks: Risk[]
  top_assets: { asset_id: number; hostname: string; score: number; risks: number }[]
  top_vulnerabilities: { vulnerability_id: number; identifier: string; risks: number }[]
  remediation: Record<string, number>
  trend: { created_at: string; counts: Record<string, number>; open_risk: number; remediated: number; new_risks: number; overdue: number }[]
}

export interface GraphData {
  nodes: { id: string; label: string; kind: string; data: Values }[]
  edges: { id: string; source: string; target: string; label: string; data: Values }[]
  truncated: boolean
  limits: Values
}

export interface Settings {
  weights: Record<string, number>
  max_path_depth: number
  max_paths: number
  max_graph_edges: number
  lifecycle_rules: boolean
  configuration_rules: boolean
}
