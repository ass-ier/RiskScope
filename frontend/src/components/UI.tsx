import { createContext, useContext, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { date, humanize, text } from '../lib/format'
import type { Values } from '../types'

const paths: Record<string, ReactNode> = {
  dashboard: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
  asset: <><rect x="3" y="4" width="18" height="13" rx="2" /><path d="M8 21h8M12 17v4M7 8h4" /></>,
  software: <><path d="m12 3 9 5v8l-9 5-9-5V8Zm0 0v18M3 8l9 5 9-5" /></>,
  risk: <><path d="M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7Z" /><path d="M12 8v5m0 3h.01" /></>,
  graph: <><circle cx="5" cy="5" r="2" /><circle cx="19" cy="5" r="2" /><circle cx="12" cy="19" r="2" /><path d="m6 7 5 10m7-10-5 10M7 5h10" /></>,
  import: <><path d="M12 3v12m-5-5 5 5 5-5M4 15v6h16v-6" /></>,
  check: <><rect x="3" y="3" width="18" height="18" rx="3" /><path d="m7 12 3 3 7-7" /></>,
  case: <><path d="M3 7h7l2-3h9v16H3Z" /></>,
  report: <><path d="M5 3h10l4 4v14H5ZM15 3v5h4M8 12h8m-8 4h8" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  settings: <><path d="M4 7h16M4 17h16" /><circle cx="9" cy="7" r="3" /><circle cx="15" cy="17" r="3" /></>,
  menu: <path d="M4 6h16M4 12h16M4 18h16" />,
  close: <path d="m6 6 12 12M6 18 18 6" />,
  arrow: <path d="M4 12h16m-6-6 6 6-6 6" />,
  search: <><circle cx="10" cy="10" r="6" /><path d="m15 15 6 6" /></>,
  refresh: <><path d="M20 7V3m0 4h-4M4 17v4m0-4h4" /><path d="M19 6A8 8 0 0 0 5 8m0 10a8 8 0 0 0 14-2" /></>,
  plus: <path d="M12 4v16M4 12h16" />,
}

export function Icon({ name, size = 18 }: { name: string; size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] || paths.report}</svg>
}

export function Pill({ value, children }: { value: unknown; children?: ReactNode }) {
  const raw = String(value ?? 'UNKNOWN')
  return <span className={`pill pill-${raw.toLowerCase().replaceAll('_', '-')}`}>{children || humanize(raw)}</span>
}

export function ErrorNotice({ error, retry }: { error: unknown; retry?: () => void }) {
  if (!error) return null
  return <div role="alert" className="notice error"><strong>Unable to complete this request</strong><p>{error instanceof Error ? error.message : text(error)}</p>{retry && <button className="button small" onClick={retry}>Try again</button>}</div>
}

export function Empty({ title = 'No records yet', children, action }: { title?: string; children?: ReactNode; action?: ReactNode }) {
  return <div className="empty"><span className="empty-symbol"><Icon name="report" size={25} /></span><h3>{title}</h3><p>{children || 'Add a record or import a local file to begin. New evidence will appear here after it is saved.'}</p>{action && <div className="button-row">{action}</div>}</div>
}

export function Skeleton({ rows = 4 }: { rows?: number }) {
  return <div className="skeletons" role="status" aria-label="Loading records"><span className="sr-only">Loading records…</span>{Array.from({ length: rows }, (_, i) => <div key={i} className="skeleton" />)}</div>
}

export function PageHeader({ title, description, actions, back }: { title: string; description?: string; actions?: ReactNode; back?: { to: string; label: string } }) {
  return <header className="page-header">{back && <Link className="back-link" to={back.to}>← {back.label}</Link>}<div className="page-heading"><div><h1>{title}</h1>{description && <p>{description}</p>}</div>{actions && <div className="button-row header-actions">{actions}</div>}</div></header>
}

export function Section({ title, description, actions, children, className = '' }: { title: string; description?: string; actions?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`section ${className}`}><div className="section-heading"><div><h2>{title}</h2>{description && <p>{description}</p>}</div>{actions}</div>{children}</section>
}

export function Facts({ data, fields }: { data: Values; fields: string[] }) {
  return <dl className="facts">{fields.map(key => <div key={key}><dt>{humanize(key)}</dt><dd>{key.endsWith('_at') || key.endsWith('_date') ? date(data[key], key.endsWith('_at')) : text(data[key])}</dd></div>)}</dl>
}

export function Structured({ value }: { value: unknown }) {
  if (Array.isArray(value)) return value.length ? <ul className="structured-list">{value.map((entry, i) => <li key={i}><Structured value={entry} /></li>)}</ul> : <span className="muted">None recorded</span>
  if (value && typeof value === 'object') return <dl className="structured">{Object.entries(value as Values).map(([key, v]) => <div key={key}><dt>{humanize(key)}</dt><dd><Structured value={v} /></dd></div>)}</dl>
  return <>{text(value)}</>
}

const NoticeContext = createContext<(message: string) => void>(() => {})
export function useNotice() { return useContext(NoticeContext) }
export function NoticeProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState('')
  return <NoticeContext.Provider value={setMessage}>{message && <div className="saved-notice" role="status"><Icon name="check" /><span>{message}</span><button className="icon-button" aria-label="Dismiss notification" onClick={() => setMessage('')}><Icon name="close" /></button></div>}{children}</NoticeContext.Provider>
}
