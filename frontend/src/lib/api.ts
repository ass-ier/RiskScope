import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { Data, Metadata, Page, Params, Values } from '../types'

export const apiBase = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '')
export type WorkspaceName = 'demo' | 'uploads'
let sessionToken: string | null = null
let workspace: WorkspaceName = 'demo'

export function configureSession(token: string | null, selected: WorkspaceName = 'demo') {
  sessionToken = token
  workspace = selected
}

export function apiUrl(path: string) {
  return `${apiBase}/api${path}`
}

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

export function queryString(params: Params = {}) {
  const query = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (value !== '' && value !== undefined && value !== null) query.set(key, String(value))
  })
  return query.size ? `?${query}` : ''
}

function errorText(value: unknown): string {
  if (typeof value === 'string') return value
  if (Array.isArray(value)) return value.map(errorText).join('; ')
  if (value && typeof value === 'object') {
    const detail = value as Values
    if (detail.msg) return `${Array.isArray(detail.loc) ? detail.loc.filter(x => x !== 'body').join(' / ') + ': ' : ''}${String(detail.msg)}`
    if (detail.detail) return errorText(detail.detail)
    if (detail.message) return String(detail.message)
  }
  return 'The request could not be completed.'
}

export async function apiResponse(path: string, options: RequestInit = {}): Promise<Response> {
  let response: Response
  const requestToken = sessionToken
  const headers = new Headers(options.headers)
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  if (requestToken) {
    headers.set('Authorization', `Bearer ${requestToken}`)
    headers.set('X-RiskScope-Workspace', workspace)
  }
  try {
    response = await fetch(apiUrl(path), { ...options, headers, credentials: 'omit', cache: 'no-store' })
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') throw error
    throw new ApiError('Cannot reach the RiskScope API. Start the local backend, or wait for the hosted service to wake up, then retry.', 0)
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    const message = body ? errorText(body) : `Request failed (${response.status}). Please try again.`
    if (requestToken && requestToken === sessionToken && (response.status === 401 || response.status === 410)) {
      window.dispatchEvent(new CustomEvent('riskscope:session-expired', { detail: message }))
    }
    throw new ApiError(message, response.status)
  }
  const ttl = response.headers.get('X-RiskScope-Session-TTL')
  if (requestToken && requestToken === sessionToken && ttl !== null && Number.isFinite(Number(ttl))) {
    window.dispatchEvent(new CustomEvent('riskscope:session-activity', { detail: Number(ttl) }))
  }
  return response
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await apiResponse(path, options)
  if (response.status === 204) return undefined as T
  try {
    return await response.json() as T
  } catch {
    throw new ApiError('The API did not return JSON. The hosted service may be waking up; wait and retry.', response.status)
  }
}

export function useResource<T = Data>(resource: string, id: string | number | undefined | null) {
  return useQuery({
    queryKey: ['record', resource, String(id)],
    queryFn: ({ signal }) => api<T>(`/${resource}/${id}`, { signal }),
    enabled: id !== undefined && id !== null && id !== '',
  })
}

export function useRecords<T = Data>(resource: string, params: Params = {}, enabled = true) {
  return useQuery({
    queryKey: ['list', resource, params],
    queryFn: ({ signal }) => api<Page<T>>(`/${resource}${queryString(params)}`, { signal }),
    enabled,
  })
}

export function useMetadata() {
  return useQuery({
    queryKey: ['metadata'],
    queryFn: ({ signal }) => api<Metadata>('/meta', { signal }),
    staleTime: 5 * 60 * 1000,
  })
}

export function useApiAction<T = Data>(path: string, method = 'POST') {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (values: Values | FormData) => api<T>(path, {
      method,
      body: values instanceof FormData ? values : JSON.stringify(values),
    }),
    onSuccess: () => { void client.invalidateQueries({ predicate: q => q.queryKey[0] !== 'metadata' }) },
  })
}
