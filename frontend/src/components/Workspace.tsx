import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { useIsMutating, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { ApiError, api, apiBase, configureSession, type WorkspaceName } from '../lib/api'
import { ErrorNotice, Skeleton } from './UI'

export interface Runtime {
  mode: 'local' | 'hosted'
  max_upload_bytes: number
  idle_seconds: number | null
  maximum_lifetime_seconds: number | null
  workspace_bytes: number | null
  max_correlations: number | null
}
interface SessionInfo { expires_at: string; maximum_expires_at: string; remaining_seconds: number }
interface StoredSession { token: string; workspace: WorkspaceName }
interface BootResult { runtime: Runtime; session: StoredSession | null; expired?: string; remainingSeconds?: number }
interface Context {
  runtime: Runtime
  workspace: WorkspaceName
  generation: number
  busy: boolean
  switchWorkspace: (name: WorkspaceName) => Promise<void>
  reset: () => Promise<void>
  end: () => Promise<void>
}
const WorkspaceContext = createContext<Context | null>(null)
const storageKey = `riskscope.guest:${apiBase || window.location.origin}`

function duration(seconds: number | null) {
  const value = seconds || 0
  const unit = value % 3600 === 0 ? 'hour' : value % 60 === 0 ? 'minute' : 'second'
  const count = unit === 'hour' ? value / 3600 : unit === 'minute' ? value / 60 : value
  return `${count} ${unit}${count === 1 ? '' : 's'}`
}

function storedSession(): StoredSession | null {
  const raw = sessionStorage.getItem(storageKey)
  if (!raw) return null
  let value: unknown
  try { value = JSON.parse(raw) } catch { throw new Error('The saved temporary session is invalid. Clear session data for this site and retry.') }
  if (!value || typeof value !== 'object' || !('token' in value) || !('workspace' in value)
    || typeof value.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.token)
    || (value.workspace !== 'demo' && value.workspace !== 'uploads')) {
    throw new Error('The saved temporary session is invalid. Clear session data for this site and retry.')
  }
  return { token: value.token, workspace: value.workspace }
}

export function useWorkspace() {
  const value = useContext(WorkspaceContext)
  if (!value) throw new Error('WorkspaceProvider is required')
  return value
}

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const client = useQueryClient()
  const navigate = useNavigate()
  const mutations = useIsMutating()
  const [runtime, setRuntime] = useState<Runtime | null>(null)
  const [session, setSession] = useState<StoredSession | null>(null)
  const [workspace, setWorkspace] = useState<WorkspaceName>('demo')
  const [generation, setGeneration] = useState(0)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [expired, setExpired] = useState<string | null>(null)
  const [error, setError] = useState<Error | null>(null)
  const [deadline, setDeadline] = useState<number | null>(null)
  const initial = useRef<Promise<BootResult> | null>(null)

  const start = useCallback(async (name: WorkspaceName) => {
    setBusy(true)
    setError(null)
    try {
      await client.cancelQueries()
      configureSession(null)
      sessionStorage.removeItem(storageKey)
      const created = await api<SessionInfo & { token: string }>('/session', { method: 'POST' })
      const next = { token: created.token, workspace: name }
      sessionStorage.setItem(storageKey, JSON.stringify(next))
      configureSession(next.token, name)
      client.clear()
      setSession(next)
      setWorkspace(name)
      setGeneration(value => value + 1)
      setExpired(null)
      setDeadline(performance.now() + created.remaining_seconds * 1000)
      navigate(name === 'uploads' ? '/imports' : '/')
    } catch (cause) {
      setError(cause instanceof Error ? cause : new Error('Could not create a temporary workspace.'))
    } finally { setBusy(false) }
  }, [client, navigate])

  useEffect(() => {
    let active = true
    if (!initial.current) initial.current = (async () => {
      const info = await api<Runtime>('/runtime')
      if (info.mode !== 'local' && info.mode !== 'hosted') throw new Error('The API returned an invalid runtime configuration.')
      if (info.mode === 'local') {
        configureSession(null)
        return { runtime: info, session: null }
      }
      const saved = storedSession()
      if (saved) {
        configureSession(saved.token, saved.workspace)
        try {
          const current = await api<SessionInfo>('/session')
          return { runtime: info, session: saved, remainingSeconds: current.remaining_seconds }
        } catch (cause) {
          if (cause instanceof ApiError && (cause.status === 401 || cause.status === 410)) {
            return { runtime: info, session: null, expired: cause.message }
          }
          throw cause
        }
      }
      const created = await api<SessionInfo & { token: string }>('/session', { method: 'POST' })
      const next: StoredSession = { token: created.token, workspace: 'demo' }
      sessionStorage.setItem(storageKey, JSON.stringify(next))
      configureSession(next.token)
      return { runtime: info, session: next, remainingSeconds: created.remaining_seconds }
    })()
    initial.current.then(result => {
      if (!active) return
      setRuntime(result.runtime)
      setSession(result.session)
      setWorkspace(result.session?.workspace || 'uploads')
      if (result.expired) setExpired(result.expired)
      if (result.remainingSeconds !== undefined) setDeadline(performance.now() + result.remainingSeconds * 1000)
      setLoading(false)
    }).catch(cause => {
      if (!active) return
      setError(cause instanceof Error ? cause : new Error('Could not open the workspace.'))
      setLoading(false)
    })
    return () => { active = false }
  }, [])

  useEffect(() => {
    const listener = (event: Event) => {
      void client.cancelQueries()
      client.clear()
      configureSession(null)
      sessionStorage.removeItem(storageKey)
      setSession(null)
      setDeadline(null)
      setExpired((event as CustomEvent<string>).detail)
    }
    const activity = (event: Event) => setDeadline(performance.now() + (event as CustomEvent<number>).detail * 1000)
    window.addEventListener('riskscope:session-expired', listener)
    window.addEventListener('riskscope:session-activity', activity)
    return () => {
      window.removeEventListener('riskscope:session-expired', listener)
      window.removeEventListener('riskscope:session-activity', activity)
    }
  }, [client])

  useEffect(() => {
    if (deadline === null) return
    const timer = window.setTimeout(() => window.dispatchEvent(new CustomEvent('riskscope:session-expired', {
      detail: 'This temporary session reached its server-reported expiry. Cached records have been cleared.',
    })), Math.max(0, deadline - performance.now()))
    return () => window.clearTimeout(timer)
  }, [deadline])

  async function switchWorkspace(name: WorkspaceName) {
    if (!session || busy || mutations) return
    setBusy(true)
    setError(null)
    try {
      await client.cancelQueries()
      const next = { ...session, workspace: name }
      sessionStorage.setItem(storageKey, JSON.stringify(next))
      configureSession(next.token, name)
      client.clear()
      setSession(next)
      setWorkspace(name)
      navigate(name === 'uploads' ? '/imports' : '/')
    } catch (cause) {
      setError(cause instanceof Error ? cause : new Error('Could not switch workspaces.'))
    } finally { setBusy(false) }
  }

  async function reset() {
    if (!window.confirm(`Delete all changes in ${workspace === 'demo' ? 'the demo' : 'My uploads'} and reset it? Export anything you need first.`)) return
    setBusy(true)
    setError(null)
    try {
      await client.cancelQueries()
      await api('/session/reset', { method: 'POST', body: JSON.stringify({ workspace }) })
      client.clear()
      setGeneration(value => value + 1)
      navigate(workspace === 'uploads' ? '/imports' : '/')
    } catch (cause) { setError(cause instanceof Error ? cause : new Error('Workspace reset failed.')) }
    finally { setBusy(false) }
  }

  async function end() {
    if (!window.confirm('Delete both temporary workspaces and end this session? This cannot be undone.')) return
    setBusy(true)
    setError(null)
    try {
      await client.cancelQueries()
      await api('/session', { method: 'DELETE' })
      sessionStorage.removeItem(storageKey)
      configureSession(null)
      client.clear()
      setSession(null)
      setDeadline(null)
      setExpired('This temporary session has ended. Its server-side workspaces were deleted.')
    } catch (cause) { setError(cause instanceof Error ? cause : new Error('Could not end the session.')) }
    finally { setBusy(false) }
  }

  if (loading) return <main className="workspace-connection"><h1>Opening RiskScope</h1><p>A hosted service may need about a minute to wake up.</p><Skeleton rows={5} /></main>
  if (!runtime) return <main className="workspace-connection"><h1>Workspace unavailable</h1><ErrorNotice error={error} retry={() => window.location.reload()} /></main>
  if (expired) return <main className="workspace-connection"><h1>Temporary session ended</h1><p>{expired}</p><p>There are no accounts or backups. Start a fresh session; expired uploads cannot be recovered.</p><div className="button-row"><button className="button primary" disabled={busy} onClick={() => { void start('demo') }}>Start new demo</button><button className="button" disabled={busy} onClick={() => { void start('uploads') }}>Start empty workspace</button></div><ErrorNotice error={error} /></main>
  return <WorkspaceContext.Provider value={{
    runtime, workspace, generation, busy: busy || mutations > 0, switchWorkspace, reset, end,
  }}>{error && <div className="workspace-operation-error"><ErrorNotice error={error} /></div>}{children}</WorkspaceContext.Provider>
}

export function WorkspaceBanner() {
  const { runtime, workspace, busy, switchWorkspace, reset, end } = useWorkspace()
  if (runtime.mode === 'local') return null
  return <section className="workspace-banner" aria-label="Temporary session and data retention">
    <div><strong>Temporary session · No sign-in</strong><p>Uploads are processed on the server, isolated from other guest sessions. Export anything you need to keep.</p>
      <p>Expires after {duration(runtime.idle_seconds)} of inactivity ({duration(runtime.maximum_lifetime_seconds)} maximum), or sooner if the server sleeps or restarts.</p>
      <details><summary>When is my data removed?</summary><p>After {duration(runtime.idle_seconds)} of inactivity or {duration(runtime.maximum_lifetime_seconds)} maximum. Server sleep, restart or redeployment can end the session sooner. Closing a tab does not immediately erase server data; cleanup follows expiry. Use End session to delete it now. No backups. Do not upload secrets or sensitive organizational data.</p>
      <p>Each workspace is limited to {(runtime.workspace_bytes || 0) / 1024 / 1024} MiB. Imports allow 1,000 records/components, and correlation is limited to {runtime.max_correlations?.toLocaleString()} applicability checks. Use local mode for larger or sensitive inventories.</p></details></div>
    <div className="workspace-controls"><label htmlFor="active-workspace">Workspace<select id="active-workspace" disabled={busy} value={workspace} onChange={event => { const name = event.target.value; if (name === 'demo' || name === 'uploads') void switchWorkspace(name) }}><option value="demo">ExampleCorp · Synthetic demo</option><option value="uploads">My uploads · Temporary</option></select></label>
      <div className="button-row"><button className="button small" disabled={busy} onClick={() => { void reset() }}>Reset workspace</button><button className="button small" disabled={busy} onClick={() => { void end() }}>End session</button></div></div>
  </section>
}
