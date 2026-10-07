import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { Data, Metadata, Page, Params, Values } from '../types'

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

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/api${path}`, {
      ...options,
      headers: {
        ...(options.body && !(options.body instanceof FormData) ? { 'Content-Type': 'application/json' } : {}),
        ...options.headers,
      },
    })
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') throw error
    throw new ApiError('Cannot reach the local API. Start the RiskScope backend and try again.', 0)
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new ApiError(body ? errorText(body) : `Request failed (${response.status}). Please try again.`, response.status)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
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
