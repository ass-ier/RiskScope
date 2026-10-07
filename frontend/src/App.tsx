import { Component, Suspense, lazy, useEffect, useRef, useState, type ErrorInfo, type ReactNode } from 'react'
import { Link, NavLink, Route, Routes, useLocation } from 'react-router-dom'
import { navigation, resources } from './lib/resources'
import { Icon, NoticeProvider, Skeleton } from './components/UI'
import { Dashboard } from './pages/Dashboard'
import { AttackPaths, InventoryDetail, InventoryList, NotFound, Timeline } from './pages/Inventory'
import { Imports, ImportDetail } from './pages/Imports'
import { NewRisk, RiskComparison, RiskDetail } from './pages/Risk'

const Reports = lazy(() => import('./pages/Reports').then(module => ({ default: module.Reports })))
const ReportDetail = lazy(() => import('./pages/Reports').then(module => ({ default: module.ReportDetail })))
const Settings = lazy(() => import('./pages/Settings').then(module => ({ default: module.Settings })))

class RenderBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error('RiskScope interface error', error, info.componentStack) }
  render() {
    return this.state.failed ? <div role="alert" className="notice error"><h2>This view could not be displayed</h2><p>Your saved records are still in the local database. Reload to recover. If the problem persists, inspect the backend response and browser console.</p><button className="button" onClick={() => window.location.reload()}>Reload workstation</button></div> : this.props.children
  }
}

function Shell() {
  const [menuOpen, setMenuOpen] = useState(false)
  const location = useLocation()
  const menuButton = useRef<HTMLButtonElement>(null)
  const main = useRef<HTMLElement>(null)
  const initialRoute = useRef(true)
  useEffect(() => {
    if (initialRoute.current) { initialRoute.current = false; return }
    main.current?.focus()
  }, [location.pathname])
  useEffect(() => {
    if (!menuOpen) return
    const listener = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { setMenuOpen(false); menuButton.current?.focus() }
    }
    document.addEventListener('keydown', listener)
    return () => document.removeEventListener('keydown', listener)
  }, [menuOpen])
  return <div className="app-shell"><a className="skip-link" href="#main">Skip to main content</a><header className="mobile-header"><button ref={menuButton} className="icon-button" aria-label={menuOpen ? 'Close navigation' : 'Open navigation'} aria-expanded={menuOpen} aria-controls="sidebar" onClick={() => setMenuOpen(!menuOpen)}><Icon name={menuOpen ? 'close' : 'menu'} /></button><Link className="mobile-brand" to="/" onClick={() => setMenuOpen(false)}>RiskScope</Link><span>Local workstation</span></header>{menuOpen && <button className="nav-backdrop" aria-label="Close navigation" onClick={() => setMenuOpen(false)} />}<aside id="sidebar" className={`sidebar ${menuOpen ? 'is-open' : ''}`}><Link className="brand" to="/" onClick={() => setMenuOpen(false)}><span className="brand-symbol"><Icon name="risk" size={24} /></span><span>RiskScope<small>Analyst workstation</small></span></Link><nav aria-label="Main navigation">{navigation.map(group => <div className="nav-group" key={group.title}><h2>{group.title}</h2>{group.items.map(([to, label, icon]) => <NavLink key={to} to={to} end={to === '/'} onClick={() => setMenuOpen(false)} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}><Icon name={icon} /><span>{label}</span></NavLink>)}</div>)}<details className="more-navigation"><summary>Evidence & supporting records</summary>{[['/evidence', 'Evidence library'], ['/zones', 'Network zones'], ['/relationships', 'Asset relationships'], ['/installations', 'Installations'], ['/services', 'Services'], ['/exposure-observations', 'Exposure observations'], ['/exploitability-observations', 'Exploitability observations'], ['/audit', 'Audit trail']].map(([to, title]) => <NavLink className="nav-link" key={to} to={to} onClick={() => setMenuOpen(false)}>{title}</NavLink>)}</details></nav><div className="sidebar-foot"><span className="local-indicator" /><div>Local-first workspace<small>Evidence stays in your environment</small></div></div></aside><div className="main-shell"><div className="workstation-bar"><span>Asset-aware vulnerability prioritization</span><span>Observations <i>→</i> Assessment <i>→</i> Decision</span></div><main ref={main} id="main" tabIndex={-1}><RenderBoundary key={location.pathname}><Suspense fallback={<Skeleton rows={8} />}><Routes><Route path="/" element={<Dashboard />} /><Route path="/risk/new" element={<NewRisk />} /><Route path="/risk/compare" element={<RiskComparison />} /><Route path="/risk/:id" element={<RiskDetail />} /><Route path="/imports" element={<Imports />} /><Route path="/imports/:id" element={<ImportDetail />} /><Route path="/attack-paths" element={<AttackPaths />} /><Route path="/reports" element={<Reports />} /><Route path="/reports/:id" element={<ReportDetail />} /><Route path="/settings" element={<Settings />} /><Route path="/timeline" element={<Timeline />} />{Object.keys(resources).filter(resource => !['imports', 'reports'].includes(resource)).map(resource => <Route key={resource} path={`/${resource}`} element={<InventoryList resource={resource} />} />)}{Object.keys(resources).filter(resource => !['risk', 'imports', 'reports'].includes(resource)).map(resource => <Route key={resource} path={`/${resource}/:id`} element={<InventoryDetail resource={resource} />} />)}<Route path="*" element={<NotFound />} /></Routes></Suspense></RenderBoundary></main><footer className="workspace-footer"><span>RiskScope · Evidence-backed context, not security guarantees.</span><Link to="/settings">Assessment configuration</Link></footer></div></div>
}

export default function App() {
  return <NoticeProvider><Shell /></NoticeProvider>
}
