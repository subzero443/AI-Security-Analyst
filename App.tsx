import { lazy, Suspense, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  Check,
  ChevronDown,
  CircleCheck,
  Download,
  FileCode2,
  FileJson2,
  FileText,
  Fingerprint,
  Globe2,
  LockKeyhole,
  Menu,
  Radar,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  X,
  type LucideIcon,
} from 'lucide-react'
import './App.css'

const DashboardCharts = lazy(() => import('./DashboardCharts'))
const AUTO_SCAN_TARGET_KEY = 'signal.securityAnalyst.autoScanTarget'

const readAutoScanTarget = () => {
  if (typeof window === 'undefined') return ''
  try {
    const savedTarget = window.localStorage.getItem(AUTO_SCAN_TARGET_KEY)
    if (!savedTarget) return ''
    const url = new URL(savedTarget)
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return ''
    return url.origin
  } catch {
    return ''
  }
}
type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
type Section = 'Overview' | 'Scans' | 'Findings' | 'Targets' | 'Reports' | 'AI analyst' | 'Settings'
type TargetInputMode = 'url' | 'json'

type Finding = {
  id: string
  title: string
  severity: Severity
  confidence: number
  category: string
  target: string
  observed: string
  impact: string
  recommendation: string
  evidence: string
  icon?: LucideIcon
  source?: string
}

type ScanMetadata = {
  id: string
  target: string
  startedAt: string
  completedAt: string
  durationSeconds: number
  requestCount: number
  pagesChecked: number
  methodology: string
  resolvedIps: string[]
  webPorts: { port: number; service: string; state: string; address: string }[]
  technologySignals: { source: string; value: string }[]
  databaseDisclosures: { technology: string; source: string }[]
}

type Observation = {
  path: string
  status: number | null
  headers: Record<string, string>
  redirects: string[]
  blockedRedirect: string | null
  error: string | null
  metadataPreview: string
}

type Analysis = {
  engine: string
  summary: string
  findingCount: number
  severityCounts: Record<Severity, number>
  priorityFindingIds: string[]
  priorityReasons: { findingId: string; reason: string }[]
  limitations: string[]
  model?: string
  warning?: string
}

type ApiHealth = {
  status: string
  scanner: string
  aiConfigured: boolean
  aiModel: string | null
}

type ScanResponse = {
  scan: ScanMetadata
  findings: Finding[]
  analysis: Analysis
  observations: Observation[]
}

const navItems: { label: Section; icon: LucideIcon }[] = [
  { label: 'Overview', icon: Activity },
  { label: 'Scans', icon: Radar },
  { label: 'Findings', icon: AlertTriangle },
  { label: 'Targets', icon: Target },
  { label: 'Reports', icon: FileText },
]

const reportNarrative = {
  executiveSummary: 'This Northstar Labs workspace is illustrative demo content. No network requests were sent and these observations are not claims about a real website.',
  methodology: 'Static fixture data demonstrates the report layout only. Run an authorized passive scan to replace it with actual public HTTP evidence.',
  riskAnalysis: 'The seeded demo findings demonstrate prioritization only. Do not treat them as verified vulnerabilities.',
  conclusion: 'This is a fictional sample report. Run a separately authorized scan to generate a real assessment.',
}

const demoFindings: Finding[] = [
  { id: 'DEMO-024', title: 'Stored cross-site scripting', severity: 'Critical', confidence: 96, category: 'Application security', target: 'app.northstar.example', observed: 'Demo fixture: a stored input is rendered without a recorded output-encoding control.', impact: 'If confirmed in a real application, untrusted script could execute in another user\'s browser context.', recommendation: 'Apply context-aware output encoding. Add a restrictive Content Security Policy as defense in depth.', evidence: 'Illustrative fixture only: <div class="comment">{{userInput}}</div>', source: 'demo-fixture' },
  { id: 'DEMO-023', title: 'Session cookie missing SameSite', severity: 'High', confidence: 91, category: 'Session security', target: 'app.northstar.example', observed: 'Demo fixture: the example session cookie omits SameSite.', impact: 'Cross-site requests may include a cookie where a stricter SameSite policy could reduce exposure.', recommendation: 'Set an appropriate SameSite policy and keep Secure and HttpOnly enabled.', evidence: 'Illustrative fixture only: Set-Cookie: session=…; Secure; HttpOnly; Path=/', source: 'demo-fixture' },
  { id: 'DEMO-022', title: 'Content Security Policy not observed', severity: 'Medium', confidence: 99, category: 'Security headers', target: 'northstar.example', observed: 'Demo fixture: Content-Security-Policy is absent from the example response.', impact: 'A CSP can reduce the impact of some injection flaws. Its absence alone does not prove exploitability.', recommendation: 'Start with a report-only policy, review violations, then enforce a nonce- or hash-based policy.', evidence: 'Illustrative fixture only: response header list omits Content-Security-Policy.', source: 'demo-fixture' },
  { id: 'DEMO-021', title: 'Server technology disclosure', severity: 'Low', confidence: 100, category: 'Information disclosure', target: 'northstar.example', observed: 'Demo fixture: the Server header contains a product/version token.', impact: 'Technology details can help observers fingerprint a stack but do not establish a vulnerable version.', recommendation: 'Suppress unnecessary product/version tokens and keep patch management current.', evidence: 'Illustrative fixture only: Server: Northstar Edge/4.8', source: 'demo-fixture' },
]

const demoObservations: Observation[] = [
  { path: '/', status: 200, headers: { 'strict-transport-security': 'max-age=31536000', 'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin', server: 'Northstar Edge/4.8' }, redirects: [], blockedRedirect: null, error: null, metadataPreview: '' },
  { path: '/robots.txt', status: 200, headers: { 'strict-transport-security': 'max-age=31536000', 'x-content-type-options': 'nosniff' }, redirects: [], blockedRedirect: null, error: null, metadataPreview: 'User-agent: *' },
  { path: '/.well-known/security.txt', status: 404, headers: { 'strict-transport-security': 'max-age=31536000' }, redirects: [], blockedRedirect: null, error: null, metadataPreview: '' },
  { path: '/security.txt', status: 404, headers: { 'strict-transport-security': 'max-age=31536000' }, redirects: [], blockedRedirect: null, error: null, metadataPreview: '' },
]

const demoAnalysis: Analysis = {
  engine: 'demo-fixture',
  summary: 'Northstar Labs is illustrative demo data, not a live scan. The example prioritizes fictional findings to demonstrate the analysis view.',
  findingCount: 4,
  severityCounts: { Critical: 1, High: 1, Medium: 1, Low: 1 },
  priorityFindingIds: ['DEMO-024', 'DEMO-023', 'DEMO-022'],
  priorityReasons: [
    { findingId: 'DEMO-024', reason: 'Demo example: validate output encoding against authorized application evidence.' },
    { findingId: 'DEMO-023', reason: 'Demo example: confirm intended session-cookie behavior.' },
    { findingId: 'DEMO-022', reason: 'Demo example: absence of CSP does not establish exploitability.' },
  ],
  limitations: ['Fictional fixture data only. No website was contacted.'],
}

const securityHeaderDefinitions = [
  { key: 'strict-transport-security', label: 'HSTS' },
  { key: 'content-security-policy', label: 'Content Security Policy' },
  { key: 'x-content-type-options', label: 'X-Content-Type-Options' },
  { key: 'referrer-policy', label: 'Referrer-Policy' },
  { key: 'permissions-policy', label: 'Permissions-Policy' },
]

function App() {
  const [section, setSection] = useState<Section>('Overview')
  const [demoMode, setDemoMode] = useState(true)
  const [findings, setFindings] = useState<Finding[]>(demoFindings)
  const [observations, setObservations] = useState<Observation[]>(demoObservations)
  const [analysis, setAnalysis] = useState<Analysis | null>(demoAnalysis)
  const [lastScan, setLastScan] = useState<ScanMetadata | null>(null)
  const [apiReady, setApiReady] = useState<boolean | null>(null)
  const [aiConfigured, setAiConfigured] = useState(false)
  const [aiModel, setAiModel] = useState('')
  const [autoScanTarget, setAutoScanTarget] = useState(readAutoScanTarget)
  const [autoScanOnOpen, setAutoScanOnOpen] = useState(() => Boolean(readAutoScanTarget()))
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState<'All' | Severity>('All')
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [scanDialogOpen, setScanDialogOpen] = useState(false)
  const [scanTarget, setScanTarget] = useState('')
  const [targetInputMode, setTargetInputMode] = useState<TargetInputMode>('url')
  const [targetJson, setTargetJson] = useState('')
  const [target, setTarget] = useState('https://northstar.example')
  const [authorized, setAuthorized] = useState(false)
  const [useAiAnalysis, setUseAiAnalysis] = useState(false)
  const [isScanning, setIsScanning] = useState(false)
  const [scanNote, setScanNote] = useState('DEMO DATA · no network requests')
  const [printGeneratedAt, setPrintGeneratedAt] = useState('')
  const [toast, setToast] = useState('')
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const startupAutoScanTarget = useRef(autoScanTarget)
  const autoScanStarted = useRef(false)

  useEffect(() => {
    let active = true
    const checkHealth = async () => {
      try {
        const response = await fetch('/api/health')
        if (!response.ok) throw new Error('API unavailable')
        const health = await response.json() as ApiHealth
        if (!active) return
        setApiReady(true)
        setAiConfigured(health.aiConfigured)
        setAiModel(health.aiModel ?? '')
      } catch {
        if (active) setApiReady(false)
      }
    }
    void checkHealth()
    const intervalId = window.setInterval(() => { void checkHealth() }, 8000)
    return () => {
      active = false
      window.clearInterval(intervalId)
    }
  }, [])

  useEffect(() => {
    const savedTarget = startupAutoScanTarget.current
    if (apiReady !== true || !savedTarget || autoScanStarted.current) return
    autoScanStarted.current = true
    let active = true

    const runRememberedScan = async () => {
      setIsScanning(true)
      setScanNote('Running previously authorized passive scan…')
      try {
        const response = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: savedTarget, authorized: true, useAi: false }),
        })
        const payload = await response.json() as ScanResponse
        if (!response.ok) {
          throw new Error((payload as unknown as { detail?: string }).detail ?? 'The automatic passive scan could not be completed.')
        }
        if (!active) return
        setFindings(payload.findings)
        setObservations(payload.observations)
        setAnalysis(payload.analysis)
        setLastScan(payload.scan)
        setDemoMode(false)
        setTarget(payload.scan.target)
        setScanNote(`Auto scan · ${payload.scan.requestCount} GET requests · ${payload.scan.pagesChecked} responses`)
        setToast('Previously authorized passive scan complete.')
        window.setTimeout(() => setToast(''), 2800)
      } catch (error) {
        if (!active) return
        setScanNote('Automatic scan failed · no new result recorded')
        setToast(error instanceof TypeError
          ? 'Scanner API unavailable. Start the app with npm run dev.'
          : error instanceof Error ? error.message : 'The automatic passive scan could not be completed.')
        window.setTimeout(() => setToast(''), 3500)
      } finally {
        if (active) setIsScanning(false)
      }
    }

    void runRememberedScan()
    return () => { active = false }
  }, [apiReady])

  const filteredFindings = useMemo(() => findings.filter((finding) => {
    const matchesSearch = `${finding.title} ${finding.category} ${finding.target}`.toLowerCase().includes(search.toLowerCase())
    return matchesSearch && (severityFilter === 'All' || finding.severity === severityFilter)
  }), [findings, search, severityFilter])
  const severityCounts: Record<Severity, number> = {
    Critical: findings.filter((finding) => finding.severity === 'Critical').length,
    High: findings.filter((finding) => finding.severity === 'High').length,
    Medium: findings.filter((finding) => finding.severity === 'Medium').length,
    Low: findings.filter((finding) => finding.severity === 'Low').length,
  }
  const successfulObservations = observations.filter((observation) => observation.status !== null)
  const responseCount = successfulObservations.length
  const headerCoverage = securityHeaderDefinitions.map(({ key, label }) => {
    const observedOn = successfulObservations.filter((observation) => Object.hasOwn(observation.headers, key)).length
    return {
      label,
      observedOn,
      responseCount,
      percent: responseCount ? Math.round((observedOn / responseCount) * 100) : 0,
    }
  })
  const criticalHighCount = severityCounts.Critical + severityCounts.High
  const prioritizedFindings = analysis
    ? analysis.priorityFindingIds.map((id) => findings.find((finding) => finding.id === id)).filter((finding): finding is Finding => finding !== undefined)
    : findings.slice(0, 3)

  const showToast = (message: string) => {
    setToast(message)
    window.setTimeout(() => setToast(''), 2800)
  }

  const persistAutoScanPreference = (enabled: boolean, scanTargetValue: string) => {
    try {
      if (enabled) {
        const url = new URL(scanTargetValue)
        window.localStorage.setItem(AUTO_SCAN_TARGET_KEY, url.origin)
        setAutoScanTarget(url.origin)
      } else {
        window.localStorage.removeItem(AUTO_SCAN_TARGET_KEY)
        setAutoScanTarget('')
      }
      setAutoScanOnOpen(enabled)
    } catch {
      showToast('Could not save the auto-scan preference in this browser.')
    }
  }

  const parseJsonTarget = (value: string): string => {
    let parsed: unknown
    try {
      parsed = JSON.parse(value)
    } catch {
      throw new Error('Target JSON is invalid. Check its quotes, commas, and braces.')
    }
    if (typeof parsed === 'string') return parsed
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Target JSON must be an object with a target or url field.')
    }

    const config = parsed as Record<string, unknown>
    let candidate = config.target ?? config.url
    if (config.targets !== undefined) {
      if (!Array.isArray(config.targets) || config.targets.length !== 1) {
        throw new Error('Submit one website per scan. Use a one-item targets array or one target field.')
      }
      candidate = config.targets[0]
    }
    if (typeof candidate !== 'string' || !candidate.trim()) {
      throw new Error('Target JSON must contain a non-empty target or url string.')
    }
    return candidate.trim()
  }

  const runPreview = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!authorized || isScanning) return
    let targetValue: string
    try {
      targetValue = targetInputMode === 'json' ? parseJsonTarget(targetJson) : scanTarget
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Target JSON is invalid.')
      return
    }
    let parsedTarget: URL
    try {
      parsedTarget = new URL(targetValue)
    } catch {
      showToast(targetInputMode === 'json' ? 'Enter valid target JSON containing one website URL.' : 'Enter a complete target URL, including https://')
      return
    }
    if (!['http:', 'https:'].includes(parsedTarget.protocol) || parsedTarget.username || parsedTarget.password) {
      showToast('Use an http or https URL without embedded credentials')
      return
    }

    setIsScanning(true)
    setScanNote('Connecting to passive scanner…')
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: parsedTarget.origin, authorized: true, useAi: useAiAnalysis }),
      })
      const payload = await response.json() as ScanResponse
      if (!response.ok) {
        throw new Error((payload as unknown as { detail?: string }).detail ?? 'The passive scan could not be completed.')
      }

      setFindings(payload.findings)
      setObservations(payload.observations)
      setAnalysis(payload.analysis)
      setLastScan(payload.scan)
      setDemoMode(false)
      if (autoScanOnOpen) persistAutoScanPreference(true, payload.scan.target)
      setUseAiAnalysis(false)
      setTarget(payload.scan.target)
      setScanNote(`Live scan · ${payload.scan.requestCount} GET requests · ${payload.scan.pagesChecked} responses`)
      setScanDialogOpen(false)
      setAuthorized(false)
      setSection('Findings')
      showToast(`Passive scan complete. ${payload.findings.length} finding(s) recorded.`)
    } catch (error) {
      setScanNote('Scan failed · no result recorded')
      showToast(error instanceof TypeError
        ? 'Scanner API unavailable. Start it with npm run api.'
        : error instanceof Error ? error.message : 'The passive scan could not be completed.')
    } finally {
      setIsScanning(false)
    }
  }

  const reportData = (generatedAt: string) => ({
    title: 'Security Assessment Report',
    generatedAt,
    scope: { target, assessmentType: 'Passive configuration review', evidenceStatus: lastScan ? 'Live passive scan' : demoMode ? 'Northstar demo data · no network requests' : 'No completed assessment' },
    executiveSummary: lastScan
      ? `The passive review of ${target} recorded ${findings.length} finding(s) from ${lastScan.requestCount} bounded GET request(s). Findings reflect only the responses observed during this scan.`
      : reportNarrative.executiveSummary,
    methodology: lastScan?.methodology ?? reportNarrative.methodology,
    findings: findings.map(({ id, title, severity, confidence, category, target: findingTarget, observed, impact, recommendation, evidence }) => ({ id, title, severity, confidence, category, target: findingTarget, observed, impact, evidence, recommendation })),
    riskAnalysis: analysis?.summary ?? reportNarrative.riskAnalysis,
    analysis,
    scan: lastScan,
    observations,
    conclusion: lastScan
      ? 'This is a limited passive configuration assessment, not a penetration test. Validate each observation with application owners and review the listed scope limitations before remediation decisions.'
      : reportNarrative.conclusion,
  })

  const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character] ?? character)

  const exportReport = (format: 'json' | 'html' | 'pdf') => {
    if (!lastScan && !demoMode) {
      showToast('Complete a scan before exporting a report.')
      return
    }
    const report = reportData(new Date().toISOString())
    const reportFilename = demoMode && !lastScan ? 'northstar-security-report-demo' : 'security-assessment'
    if (format === 'pdf') {
      setPrintGeneratedAt(new Date().toLocaleString())
      const previousTitle = document.title
      document.title = reportFilename
      window.setTimeout(() => {
        window.print()
        document.title = previousTitle
      }, 50)
      return
    }

    const contents = format === 'json'
      ? JSON.stringify(report, null, 2)
      : `<!doctype html><html lang="en"><meta charset="utf-8"><title>${escapeHtml(report.title)}</title><style>body{font:15px/1.6 Arial,sans-serif;max-width:900px;margin:40px auto;padding:0 24px;color:#182128}h1,h2{font-family:Arial,sans-serif}h1{border-bottom:3px solid #65d27d;padding-bottom:12px}.notice{padding:12px;background:#fff3d4;border-left:4px solid #e9a829}article{border-top:1px solid #dce2e5;padding:18px 0}small{color:#56616a}</style><h1>${escapeHtml(report.title)}</h1><p class="notice"><strong>${escapeHtml(report.scope.evidenceStatus)}.</strong> ${escapeHtml(report.methodology)}</p><p><strong>Scope:</strong> ${escapeHtml(report.scope.target)} · ${escapeHtml(report.scope.assessmentType)}</p><h2>Executive Summary</h2><p>${escapeHtml(report.executiveSummary)}</p><h2>Methodology</h2><p>${escapeHtml(report.methodology)}</p><h2>Network details</h2><p><strong>Resolved public IPs:</strong> ${escapeHtml(report.scan?.resolvedIps.join(', ') ?? 'Not available')}</p><p><strong>TCP reachability:</strong> ${escapeHtml(report.scan?.webPorts.map((port) => `${port.port}/${port.service}: ${port.state}`).join('; ') ?? 'Not available')}</p><p><strong>Technology signals:</strong> ${escapeHtml(report.scan?.technologySignals.map((signal) => `${signal.source}: ${signal.value}`).join('; ') || 'None disclosed')}</p><p><strong>Database disclosure:</strong> ${escapeHtml(report.scan?.databaseDisclosures.map((item) => `${item.technology} (${item.source})`).join('; ') || 'No database engine was disclosed in public metadata; database ports were not probed.')}</p><h2>Response observations</h2>${report.observations.map((observation) => `<article><h3>${escapeHtml(observation.path)} · HTTP ${observation.status ?? 'unavailable'}</h3><p><strong>Headers:</strong> ${escapeHtml(Object.entries(observation.headers).map(([name, value]) => `${name}: ${value}`).join('; ') || 'None captured')}</p><p><strong>Redirects:</strong> ${escapeHtml(observation.redirects.join('; ') || 'None')}</p>${observation.blockedRedirect ? `<p><strong>Scope control:</strong> ${escapeHtml(observation.blockedRedirect)}</p>` : ''}${observation.error ? `<p><strong>Request note:</strong> ${escapeHtml(observation.error)}</p>` : ''}${observation.metadataPreview ? `<pre>${escapeHtml(observation.metadataPreview)}</pre>` : ''}</article>`).join('')}<h2>Findings</h2>${report.findings.map((finding) => `<article><h3>${escapeHtml(finding.title)} · ${finding.severity} · ${finding.confidence}% confidence</h3><small>${escapeHtml(finding.id)} / ${escapeHtml(finding.category)} / ${escapeHtml(finding.target)}</small><p><strong>Observation:</strong> ${escapeHtml(finding.observed)}</p><p><strong>Impact:</strong> ${escapeHtml(finding.impact)}</p><p><strong>Evidence:</strong> ${escapeHtml(finding.evidence)}</p><p><strong>Remediation:</strong> ${escapeHtml(finding.recommendation)}</p></article>`).join('')}<h2>Risk Analysis</h2><p>${escapeHtml(report.riskAnalysis)}</p>${report.analysis ? `<h2>Analysis engine and limitations</h2><p>${escapeHtml(report.analysis.warning ?? `${report.analysis.engine}${report.analysis.model ? ` (${report.analysis.model})` : ''}`)}</p><ul>${report.analysis.limitations.map((limitation) => `<li>${escapeHtml(limitation)}</li>`).join('')}</ul>` : ''}<h2>Conclusion</h2><p>${escapeHtml(report.conclusion)}</p><small>Generated ${escapeHtml(report.generatedAt)}</small></html>`

    const reportContents = format === 'html'
      ? contents.replace('</style>', '</style><style>*,*::before,*::after{font-family:"Roboto Variable",Roboto,Arial,sans-serif!important}</style>')
      : contents
    const blob = new Blob([reportContents], { type: format === 'json' ? 'application/json' : 'text/html' })
    const downloadUrl = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = downloadUrl
    link.download = `${reportFilename}.${format}`
    link.click()
    URL.revokeObjectURL(downloadUrl)
    showToast(`${format.toUpperCase()} report exported`)
  }

  const openScanDialog = () => {
    setAuthorized(false)
    setUseAiAnalysis(false)
    setScanTarget(lastScan?.target ?? '')
    setScanDialogOpen(true)
  }

  const renderFindingRows = (items: Finding[]) => items.map((finding) => {
    const Icon = finding.icon ?? ShieldAlert
    return (
      <button className="finding-row" key={finding.id} onClick={() => setSelectedFinding(finding)}>
        <span className="finding-icon"><Icon size={16} /></span>
        <span className="finding-name"><strong>{finding.title}</strong><small>{finding.id} <span className="row-separator">/</span> {finding.category}</small></span>
        <span className={`severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
        <span className="confidence"><i style={{ width: `${finding.confidence}%` }} /><b>{finding.confidence}%</b></span>
        <span className="row-target">{finding.target}</span>
        <ArrowRight className="row-arrow" size={15} />
      </button>
    )
  })

  return (
    <div className="app-shell min-h-screen">
      <aside className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <div className="brand-lockup">
          <span className="brand-mark"><Shield size={19} strokeWidth={2.4} /></span>
          <span className="brand-name">signal<span>/</span><small>SECURITY ANALYST</small></span>
          <button className="icon-button close-nav" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)}><X size={17} /></button>
        </div>

        <div className="workspace-switcher"><span className="workspace-avatar">N</span><span><strong>Northstar Labs</strong><small>{demoMode ? 'Demo workspace' : 'Security workspace'}</small></span><ChevronDown size={14} /></div>
        <div className="side-label">WORKSPACE</div>
        <nav className="side-nav" aria-label="Main navigation">
          {navItems.map(({ label, icon: Icon }) => (
            <button key={label} className={`nav-link ${section === label ? 'active' : ''}`} onClick={() => { setSection(label); setMobileNavOpen(false) }}>
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>{label === 'Findings' && <b className="nav-count">{String(findings.length).padStart(2, '0')}</b>}
            </button>
          ))}
        </nav>
        <div className="side-label side-label-spaced">ASSISTANT</div>
        <button className={`nav-link ${section === 'AI analyst' ? 'active' : ''}`} onClick={() => { setSection('AI analyst'); setMobileNavOpen(false) }}><Sparkles size={17} /><span>AI analyst</span><span className="new-tag">BETA</span></button>
        <div className="side-bottom">
          <div className="authorization-card"><div className="authorization-head"><LockKeyhole size={14} /><span>SAFE MODE</span><span className="live-dot" /></div><p>Passive checks only. No exploit attempts or intrusive requests.</p></div>
          <button className={`nav-link ${section === 'Settings' ? 'active' : ''}`} onClick={() => setSection('Settings')}><Fingerprint size={17} /><span>Settings</span></button>
          <div className="user-profile"><span className="user-avatar">SA</span><span><strong>Security analyst</strong><small>Local workspace</small></span><Menu size={16} /></div>
        </div>
      </aside>
      {mobileNavOpen && <button className="nav-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}

      <main className="main-panel">
        <header className="topbar">
          <button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileNavOpen(true)}><Menu size={19} /></button>
          <div className="breadcrumbs"><span>Workspace</span><span className="crumb-divider">/</span><strong>{section}</strong></div>
          <div className="topbar-actions"><span className={`system-status ${apiReady === false ? 'status-offline' : ''}`}><i /> {apiReady === null ? 'Checking scanner' : apiReady ? 'Scanner ready' : 'Scanner offline'}</span><span className="topbar-divider" /><button className="icon-button help-button" title="Help and documentation" aria-label="Help"><span>?</span></button><button className="top-avatar" aria-label="Account menu">SA</button></div>
        </header>

        <div className="page-content">
          {section === 'Overview' && <>
            <div className="page-heading">
              <div><div className="eyebrow"><span className="eyebrow-line" /> SECURITY POSTURE <span className={lastScan ? 'demo-tag live-data-tag' : 'demo-tag'}>{lastScan ? 'LIVE SCAN' : demoMode ? 'DEMO DATA' : apiReady ? 'READY' : 'API OFFLINE'}</span></div><h1>Good morning, Jordan<span className="heading-period">.</span></h1><p className="page-subtitle">Here is the security picture across your workspace.</p></div>
              <div className="heading-actions"><button className="button button-secondary" disabled={!lastScan && !demoMode} onClick={() => exportReport('json')}><Download size={15} /> Export JSON</button><button className="button button-primary" onClick={openScanDialog}><Radar size={16} /> Start scan</button></div>
            </div>

            <div className="target-strip"><span className="target-mark"><Globe2 size={15} /></span><span className="target-label">{lastScan ? 'SCANNED TARGET' : demoMode ? 'DEMO TARGET' : 'TARGET'}</span><strong>{target ? target.replace(/^https?:\/\//, '') : 'No target scanned'}</strong><span className="target-divider" /><span className="sample-status"><i /> {scanNote}</span><button className="target-change" onClick={openScanDialog}>{lastScan ? 'Scan another' : 'Start live scan'} <ArrowRight size={13} /></button></div>

            <section className="metric-grid" aria-label="Workspace metrics">
              <article className="metric-card"><div className="metric-top"><span className="metric-label">TOTAL SCANS</span><span className="metric-icon metric-icon-green"><Radar size={15} /></span></div><div className="metric-value">{lastScan ? '13' : demoMode ? '12' : '00'}</div><div className="metric-foot"><span className="metric-trend trend-good">{lastScan ? '1 just completed' : demoMode ? '2 this week' : 'Ready'}</span><span>{demoMode && !lastScan ? 'demo data' : 'across this session'}</span></div></article>
              <article className="metric-card"><div className="metric-top"><span className="metric-label">OPEN FINDINGS</span><span className="metric-icon metric-icon-amber"><AlertTriangle size={15} /></span></div><div className="metric-value">{findings.length.toString().padStart(2, '0')}</div><div className="metric-foot"><span className="metric-trend trend-warn">Current scope</span><span>from latest evidence</span></div></article>
              <article className="metric-card"><div className="metric-top"><span className="metric-label">CRITICAL / HIGH</span><span className="metric-icon metric-icon-red"><ShieldAlert size={15} /></span></div><div className="metric-value">{String(criticalHighCount).padStart(2, '0')}<span className="metric-suffix"> / {String(findings.length).padStart(2, '0')}</span></div><div className="metric-foot"><span className="metric-trend trend-muted">Needs attention</span><span>priority findings</span></div></article>
              <article className="metric-card posture-card"><div className="metric-top"><span className="metric-label">POSTURE SCORE</span><span className="metric-icon metric-icon-cyan"><Activity size={15} /></span></div><div className="metric-value">{demoMode && !lastScan ? '66' : '—'}{demoMode && !lastScan && <span className="metric-suffix">/100</span>}</div><div className="posture-track"><span style={{ width: demoMode && !lastScan ? '66%' : '0%' }} /></div><div className="metric-foot"><span className="metric-trend trend-muted">{demoMode && !lastScan ? 'Demo score' : 'Not scored'}</span><span>{demoMode && !lastScan ? 'illustrative only' : 'no scoring model configured'}</span></div></article>
            </section>

            <Suspense fallback={<div className="analysis-grid chart-loading">Loading charts…</div>}>
              <DashboardCharts headerCoverage={headerCoverage} responseCount={responseCount} severityCounts={severityCounts} isLive={Boolean(lastScan)} isDemo={demoMode} onViewFindings={() => setSection('Findings')} />
            </Suspense>

            <section className="panel findings-panel">
              <div className="panel-heading findings-heading"><div><div className="panel-kicker">LATEST SIGNALS</div><h2>Recent findings <span className="heading-count">{String(findings.length).padStart(2, '0')}</span></h2></div><button className="text-button" onClick={() => setSection('Findings')}>All findings <ArrowRight size={14} /></button></div>
              <div className="finding-table-head"><span>FINDING</span><span>SEVERITY</span><span>CONFIDENCE</span><span>TARGET</span><span /></div>
              <div className="finding-list">{renderFindingRows(findings)}</div>
              {findings.length === 0 ? <div className="empty-state">No findings yet. Start an authorized scan to collect evidence.</div> : <div className="finding-panel-footer"><span><span className="footer-dot" /> {demoMode && !lastScan ? 'Demo findings' : 'Live passive scan'} <span className="footer-separator">·</span> {demoMode && !lastScan ? 'fictional evidence only' : `${lastScan?.pagesChecked ?? 0} responses checked`}</span><button onClick={() => setSection('Findings')}>Open findings view <ArrowRight size={13} /></button></div>}
            </section>

            <section className="assistant-banner"><div className="assistant-icon"><Sparkles size={18} /></div><div className="assistant-copy"><span className="assistant-label">EVIDENCE ANALYST <span>{analysis ? 'GENERATED' : 'READY'}</span></span><p>{analysis?.summary ?? 'Analysis will be generated from the response headers, cookie attributes, and public metadata collected by your next scan.'}</p></div><button onClick={() => setSection('AI analyst')}>View analysis <ArrowRight size={14} /></button></section>
          </>}

          {section === 'Findings' && <section className="section-view"><div className="page-heading compact-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> EVIDENCE REGISTER <span className={lastScan ? 'demo-tag live-data-tag' : 'demo-tag'}>{lastScan ? 'LIVE SCAN' : demoMode ? 'DEMO DATA' : 'NO SCAN YET'}</span></div><h1>Findings<span className="heading-period">.</span></h1><p className="page-subtitle">Prioritized observations with evidence, impact, and practical next steps.</p></div><button className="button button-primary" onClick={() => exportReport('html')}><FileText size={15} /> Export report</button></div><div className="filter-toolbar"><label className="search-field"><Search size={15} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search findings, categories, targets" /></label><label className="filter-select"><span>Severity</span><select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as 'All' | Severity)}><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select><ChevronDown size={14} /></label><span className="result-count">{filteredFindings.length} of {findings.length} findings</span></div><div className="panel full-findings-panel"><div className="finding-table-head"><span>FINDING</span><span>SEVERITY</span><span>CONFIDENCE</span><span>TARGET</span><span /></div><div className="finding-list">{renderFindingRows(filteredFindings)}</div>{filteredFindings.length === 0 && <div className="empty-state">{lastScan ? 'No findings were reported for this scope.' : demoMode ? 'The Northstar demo contains no matching rows for these filters.' : 'No scan results yet. Start an authorized passive scan to inspect a website.'}</div>}</div><div className="evidence-note"><ShieldCheck size={16} /><span>{lastScan ? `Evidence came from ${lastScan.requestCount} bounded GET requests to this authorized target. Validate findings against application behavior before remediation.` : demoMode ? 'Northstar demo findings are fictional interface examples. Run an authorized scan to replace them with evidence.' : 'A scan must complete before this register can show evidence-backed findings.'}</span></div></section>}

          {section === 'Scans' && <section className="section-view"><div className="page-heading compact-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> SCAN HISTORY</div><h1>Scans<span className="heading-period">.</span></h1><p className="page-subtitle">Review live passive assessments and launch a new authorized scan.</p></div><button className="button button-primary" onClick={openScanDialog}><Radar size={15} /> Start scan</button></div><div className="scan-notice"><div><span className="notice-icon"><LockKeyhole size={16} /></span><span><strong>{lastScan ? 'Live scan completed' : 'Passive scanner ready'}</strong><small>{lastScan ? `${lastScan.target} · ${lastScan.pagesChecked} responses from ${lastScan.requestCount} bounded GET requests.` : 'The scanner checks public web configuration only after you confirm authorization.'}</small></span></div><span className={lastScan ? 'demo-tag live-data-tag' : 'demo-tag'}>{lastScan ? 'LIVE' : 'SAFE MODE'}</span></div><div className="panel scan-history"><div className="panel-heading"><div><div className="panel-kicker">RECENT ACTIVITY</div><h2>Assessment history</h2></div><span className="history-count">{lastScan ? '1 scan' : '0 scans'}</span></div>{lastScan ? <div className="scan-history-row"><span className="scan-history-icon"><ShieldCheck size={16} /></span><span className="scan-history-name"><strong>Passive configuration review</strong><small>{lastScan.completedAt} <span>·</span> {lastScan.target}</small></span><span className="scan-findings-count">{findings.length} findings</span><span className="scan-complete"><i /> Complete</span><ArrowRight size={15} /></div> : <div className="empty-state">No scans run in this session yet.</div>}</div></section>}

          {section === 'Targets' && <section className="section-view"><div className="page-heading compact-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> SCOPE MANAGEMENT</div><h1>Targets<span className="heading-period">.</span></h1><p className="page-subtitle">Only websites assessed with explicit authorization appear here.</p></div><button className="button button-primary" onClick={openScanDialog}><Target size={15} /> Scan target</button></div>{lastScan ? <><div className="target-grid"><article className="panel target-card"><div className="target-card-top"><span className="target-card-icon"><Globe2 size={17} /></span><span className="target-state"><i /> Scanned this session</span></div><h2>{lastScan.target.replace(/^https?:\/\//, '')}</h2><p>{lastScan.pagesChecked} HTTP response(s) · {findings.length} finding(s)</p><div className="target-card-bottom"><span className="environment-tag">Authorized scope</span><span>{lastScan.requestCount} GET requests</span><button aria-label="Rescan target" onClick={() => { setScanTarget(lastScan.target); openScanDialog() }}><ArrowUpRight size={15} /></button></div></article></div><section className="panel target-intel"><div className="panel-heading"><div><div className="panel-kicker">PUBLIC NETWORK METADATA</div><h2>Resolved address and web services</h2></div><span className="live-data-tag demo-tag">LIVE SCAN</span></div><div className="target-intel-grid"><div><span className="target-intel-label">RESOLVED IP ADDRESSES</span>{lastScan.resolvedIps.length ? lastScan.resolvedIps.map((address) => <code className="intel-value" key={address}>{address}</code>) : <span className="intel-empty">No public address returned</span>}</div><div><span className="target-intel-label">STANDARD WEB PORTS</span>{lastScan.webPorts.map((port) => <div className="intel-port" key={port.port}><code>{port.port}/tcp</code><span>{port.service}</span><b className={`port-state port-${port.state}`}>{port.state}</b></div>)}</div><div><span className="target-intel-label">PUBLIC TECHNOLOGY SIGNALS</span>{lastScan.technologySignals.length ? lastScan.technologySignals.map((signal) => <div className="intel-tech" key={`${signal.source}-${signal.value}`}><span>{signal.source}</span><strong>{signal.value}</strong></div>) : <span className="intel-empty">No server technology disclosed</span>}</div><div><span className="target-intel-label">DATABASE ENGINE</span>{lastScan.databaseDisclosures.length ? lastScan.databaseDisclosures.map((item) => <div className="intel-tech" key={`${item.technology}-${item.source}`}><span>{item.source}</span><strong>{item.technology}</strong></div>) : <span className="intel-empty">Not disclosed in public responses; no database ports were probed.</span>}</div></div></section></> : <div className="panel empty-state">No targets saved. Run an authorized scan to add the assessed target to this session.</div>}<div className="evidence-note"><LockKeyhole size={15} /><span>Only validated public IP addresses and TCP 80/443 reachability are collected. No database/admin-port sweep is performed.</span></div></section>}

          {section === 'Reports' && <section className="section-view"><div className="page-heading compact-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> REPORT LIBRARY <span className={demoMode && !lastScan ? 'demo-tag' : 'demo-tag live-data-tag'}>{lastScan ? 'LIVE REPORT' : demoMode ? 'DEMO FILES' : 'NO REPORT'}</span></div><h1>Reports<span className="heading-period">.</span></h1><p className="page-subtitle">{lastScan ? `Export the passive assessment for ${lastScan.target}.` : demoMode ? 'Northstar Labs · northstar.example · fictional demonstration reports.' : 'Reports become available after the first completed scan.'}</p></div><button className="button button-primary" onClick={() => exportReport('pdf')} disabled={!lastScan && !demoMode}><Download size={15} /> Export PDF</button></div><div className="report-options"><button className="panel report-option" disabled={!lastScan && !demoMode} onClick={() => exportReport('html')}><span className="report-icon report-html"><FileCode2 size={19} /></span><span><strong>HTML report</strong><small>{lastScan ? `security-assessment.html · ${target}` : 'northstar-security-report.html · DEMO ONLY'}</small></span><ArrowRight size={15} /></button><button className="panel report-option" disabled={!lastScan && !demoMode} onClick={() => exportReport('json')}><span className="report-icon report-json"><FileJson2 size={19} /></span><span><strong>JSON data</strong><small>{lastScan ? `security-assessment.json · ${target}` : 'northstar-security-report.json · DEMO ONLY'}</small></span><ArrowRight size={15} /></button><button className="panel report-option" disabled={!lastScan && !demoMode} onClick={() => exportReport('pdf')}><span className="report-icon report-pdf"><FileText size={19} /></span><span><strong>PDF report</strong><small>{lastScan ? `Print-ready assessment · ${target}` : 'northstar-security-report.pdf · DEMO ONLY'}</small></span><ArrowRight size={15} /></button></div><div className="report-outline panel"><div className="panel-kicker">REPORT CONTENTS</div><div className="outline-flow">{['Executive summary', 'Scope', 'Methodology', 'Findings', 'Risk analysis', 'Evidence', 'Remediation', 'Conclusion'].map((label, index) => <span key={label}><b>{String(index + 1).padStart(2, '0')}</b>{label}</span>)}</div><p>{lastScan ? `Live scan: ${lastScan.requestCount} bounded GET requests to ${lastScan.target}.` : demoMode ? 'JSON and PDF exports are fictional examples, clearly labeled to avoid confusing them with scan results.' : 'No scan data to export yet.'}</p></div></section>}

          {section === 'AI analyst' && <section className="section-view"><div className="page-heading compact-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> EVIDENCE-LED REVIEW <span className="demo-tag">{analysis?.engine === 'openai-compatible' ? analysis.model ?? 'AI ANALYSIS' : 'LOCAL RULES'}</span></div><h1>Security analysis<span className="heading-period">.</span></h1><p className="page-subtitle">Prioritization generated from observed response evidence.</p></div></div><div className="ai-intro"><span className="ai-large-icon"><Sparkles size={21} /></span><div><strong>{analysis ? 'Analysis generated from this scan' : 'Waiting for scan evidence'}</strong><p>{analysis?.summary ?? 'Run an authorized passive scan to generate explanations and priorities from the target\'s actual responses.'}</p></div></div>{analysis && <div className="evidence-note"><Sparkles size={15} /><span>{analysis.warning ?? `Analysis engine: ${analysis.engine}${analysis.model ? ` (${analysis.model})` : ''}.`} {analysis.limitations.join(' ')}</span></div>}<div className="ai-priority-list">{prioritizedFindings.map((finding, index) => <button className="ai-priority-item panel" key={finding.id} onClick={() => setSelectedFinding(finding)}><span className="priority-number">0{index + 1}</span><span className="priority-content"><small>REVIEW FIRST · {finding.severity.toUpperCase()}</small><strong>{finding.title}</strong><span>{analysis?.priorityReasons.find((item) => item.findingId === finding.id)?.reason ?? finding.impact}</span></span><span className="priority-confidence">{finding.confidence}%<small>evidence confidence</small></span><ArrowRight size={15} /></button>)}</div>{prioritizedFindings.length === 0 && <div className="empty-state">No findings to prioritize. Run an authorized passive scan first.</div>}<div className="evidence-note"><Sparkles size={15} /><span>Confidence describes how directly the observed evidence supports the configuration finding. It is not a probability of exploitability.</span></div></section>}

          {section === 'Settings' && <section className="section-view"><div className="page-heading compact-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> WORKSPACE CONTROLS</div><h1>Settings<span className="heading-period">.</span></h1><p className="page-subtitle">Review the safety boundaries applied by this local scanner.</p></div></div><div className="panel settings-panel"><div className="settings-row"><span className="settings-icon"><LockKeyhole size={17} /></span><span><strong>Authorization required</strong><small>Require an explicit ownership or authorization affirmation before each scan.</small></span><span className="setting-state"><i /> Enabled</span></div><div className="settings-row"><span className="settings-icon"><Radar size={17} /></span><span><strong>Passive checks only</strong><small>No exploitation, brute force, credential testing, crawling, or state-changing requests.</small></span><span className="setting-state"><i /> Enabled</span></div><div className="settings-row"><span className="settings-icon"><Sparkles size={17} /></span><span><strong>Evidence-based analysis</strong><small>Findings are generated from observed headers and cookie attributes by local rules.</small></span><span className="setting-state"><i /> Enabled</span></div><div className="settings-row"><span className="settings-icon"><Globe2 size={17} /></span><span><strong>Scanner API</strong><small>Bound to localhost with public-IP pinning, same-host redirects, and an eight-request cap per scan.</small></span><span className={`setting-state ${lastScan ? '' : 'state-demo'}`}><i /> {lastScan ? 'Connected' : 'Ready'}</span></div></div></section>}

          <footer className="page-foot section-footer"><span>Signal Security Analyst <span>·</span> Preview build 0.1.0</span><span><CircleCheck size={13} /> Passive mode enabled</span></footer>
        </div>
      </main>

      {scanDialogOpen && <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !isScanning) setScanDialogOpen(false) }}><section className="scan-modal" role="dialog" aria-modal="true" aria-labelledby="scan-title"><div className="modal-topline"><span className="modal-mark"><Radar size={17} /></span><button className="icon-button" aria-label="Close dialog" disabled={isScanning} onClick={() => setScanDialogOpen(false)}><X size={17} /></button></div><div className="modal-eyebrow">AUTHORIZED ASSESSMENT</div><h2 id="scan-title">Start a passive scan</h2><p className="modal-description">Confirm authorization. The scanner makes at most 8 unauthenticated HTTP GET requests and TCP connect checks on ports 80 and 443. It does not crawl, probe database/admin ports, exploit, or change target data.</p><form onSubmit={runPreview}><span className="form-label">Target input</span><div className="target-input-mode" role="group" aria-label="Target input format"><button type="button" className={targetInputMode === 'url' ? 'mode-active' : ''} aria-pressed={targetInputMode === 'url'} onClick={() => setTargetInputMode('url')}>URL</button><button type="button" className={targetInputMode === 'json' ? 'mode-active' : ''} aria-pressed={targetInputMode === 'json'} onClick={() => setTargetInputMode('json')}>JSON</button></div>{targetInputMode === 'url' ? <><label className="form-label" htmlFor="target-url">Target website</label><div className="url-input"><Globe2 size={16} /><input id="target-url" type="url" value={scanTarget} onChange={(event) => setScanTarget(event.target.value)} placeholder="https://your-authorized-site.com" required /></div></> : <div className="json-target-input"><div className="json-file-row"><label className="json-file-button">Import JSON<input type="file" accept=".json,application/json" onChange={(event) => { const file = event.currentTarget.files?.[0]; if (!file) return; if (file.size > 16384) { showToast('JSON files must be smaller than 16 KB.'); event.currentTarget.value = ''; return }; void file.text().then(setTargetJson).catch(() => showToast('Could not read that JSON file.')) }} /></label><span>Paste a target object below</span></div><textarea id="target-json" aria-label="Target JSON" value={targetJson} onChange={(event) => setTargetJson(event.target.value)} placeholder={'{\n  "target": "https://your-authorized-site.com"\n}'} maxLength={16384} required /></div>}<div className="scan-scope-box"><div className="scope-box-head"><ShieldCheck size={15} /><strong>Passive configuration checks</strong></div><div className="scope-checks"><span><Check size={13} /> Security headers</span><span><Check size={13} /> Cookie attributes</span><span><Check size={13} /> HTTPS and HSTS</span><span><Check size={13} /> robots.txt / security.txt</span></div><div className="scope-box-note"><LockKeyhole size={13} /> Public IPs only · same-host redirects · TCP 80/443 only</div></div>{aiConfigured ? <label className="authorization-check ai-opt-in"><input type="checkbox" checked={useAiAnalysis} onChange={(event) => setUseAiAnalysis(event.target.checked)} /><span className="custom-check"><Check size={12} /></span><span>Send finding evidence to {aiModel} for additional explanation. Response bodies and cookie values are not sent.</span></label> : <div className="scope-box-note ai-local-note"><Sparkles size={13} /> Local evidence rules will generate the analysis. Configure an AI provider to enable optional model analysis.</div>}<label className="authorization-check"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span className="custom-check"><Check size={12} /></span><span>I own this website or have explicit authorization to assess it.</span></label><button type="submit" className="button button-primary modal-submit" disabled={!authorized || isScanning}>{isScanning ? <><span className="button-spinner" /> Scanning configuration…</> : <><Radar size={16} /> Start passive scan</>}</button><div className="modal-footnote"><LockKeyhole size={12} /> Findings are observations, not proof of exploitability.</div></form></section></div>}

      {selectedFinding && <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setSelectedFinding(null) }}><section className="finding-drawer" role="dialog" aria-modal="true" aria-labelledby="detail-title"><div className="drawer-top"><span className="drawer-id">{selectedFinding.id} <span> / </span> FINDING DETAIL</span><button className="icon-button" aria-label="Close finding details" onClick={() => setSelectedFinding(null)}><X size={17} /></button></div><div className={`severity severity-${selectedFinding.severity.toLowerCase()}`}>{selectedFinding.severity} severity</div><h2 id="detail-title">{selectedFinding.title}</h2><div className="drawer-meta"><span>{selectedFinding.category}</span><span>{selectedFinding.target}</span></div><div className="detail-confidence"><span>Evidence confidence</span><strong>{selectedFinding.confidence}%</strong><div><i style={{ width: `${selectedFinding.confidence}%` }} /></div></div><section className="detail-section"><div className="panel-kicker">OBSERVATION</div><p>{selectedFinding.observed}</p></section><section className="detail-section"><div className="panel-kicker">POTENTIAL IMPACT</div><p>{selectedFinding.impact}</p></section><section className="detail-section"><div className="panel-kicker">EVIDENCE</div><pre>{selectedFinding.evidence}</pre></section><section className="detail-section remediation-section"><div className="panel-kicker"><Sparkles size={12} /> SUGGESTED REMEDIATION</div><p>{selectedFinding.recommendation}</p></section><div className="drawer-disclaimer"><AlertTriangle size={14} /> Passive observation only. Validate impact in application context.</div></section></div>}

      <div className={`toast ${toast ? 'toast-visible' : ''}`} role="status"><CircleCheck size={15} />{toast}</div>

      <section className="print-report" aria-hidden="true"><div className="print-report-head"><span>SIGNAL / SECURITY ANALYST</span><span>{lastScan ? 'LIVE PASSIVE SCAN' : demoMode ? 'NORTHSTAR DEMO · NO NETWORK REQUESTS' : 'NO COMPLETED SCAN'}</span></div><h1>Security Assessment Report</h1><p className="print-warning">{lastScan ? 'Limited passive assessment. Results reflect only the public HTTP responses collected; no exploitability was tested.' : demoMode ? 'Fictional Northstar Labs interface demo. These sample findings are not evidence about a real website and no scan was performed.' : 'No assessment data is available. Run an authorized scan before exporting a report.'}</p><p><strong>Scope:</strong> {target || 'No target scanned'} · Passive configuration review</p><h2>Executive Summary</h2><p>{lastScan ? `The passive review recorded ${findings.length} finding(s) from ${lastScan.requestCount} bounded GET request(s).` : reportNarrative.executiveSummary}</p><h2>Scope &amp; Methodology</h2><p>{lastScan?.methodology ?? reportNarrative.methodology}</p>{lastScan && <><h2>Network details</h2><p><strong>Resolved public IPs:</strong> {lastScan.resolvedIps.join(', ') || 'Not available'}</p><p><strong>TCP reachability:</strong> {lastScan.webPorts.map((port) => `${port.port}/${port.service}: ${port.state}`).join('; ')}</p><p><strong>Technology signals:</strong> {lastScan.technologySignals.map((signal) => `${signal.source}: ${signal.value}`).join('; ') || 'None disclosed'}</p><p><strong>Database disclosure:</strong> {lastScan.databaseDisclosures.map((item) => `${item.technology} (${item.source})`).join('; ') || 'Not disclosed in public responses; no database ports were probed.'}</p><h2>Response observations</h2>{observations.map((observation) => <article key={observation.path}><h3>{observation.path} · HTTP {observation.status ?? 'unavailable'}</h3><p><strong>Headers:</strong> {Object.entries(observation.headers).map(([name, value]) => `${name}: ${value}`).join('; ') || 'None captured'}</p><p><strong>Redirects:</strong> {observation.redirects.join('; ') || 'None'}</p>{observation.blockedRedirect && <p><strong>Scope control:</strong> {observation.blockedRedirect}</p>}{observation.error && <p><strong>Request note:</strong> {observation.error}</p>}{observation.metadataPreview && <pre>{observation.metadataPreview}</pre>}</article>)}</>}<h2>Findings</h2>{findings.map((finding) => <article key={finding.id}><h3>{finding.title} <span>{finding.severity} · {finding.confidence}% confidence</span></h3><p><strong>Observation:</strong> {finding.observed}</p><p><strong>Impact:</strong> {finding.impact}</p><pre>{finding.evidence}</pre><p><strong>Remediation:</strong> {finding.recommendation}</p></article>)}<h2>Risk Analysis</h2><p>{analysis?.summary ?? reportNarrative.riskAnalysis}</p>{analysis && <><h2>Analysis engine and limitations</h2><p>{analysis.warning ?? `${analysis.engine}${analysis.model ? ` (${analysis.model})` : ''}`}</p><ul>{analysis.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul></>}<h2>Conclusion</h2><p>{lastScan ? 'This is a limited passive configuration assessment, not a penetration test. Validate observations in application context before acting.' : reportNarrative.conclusion}</p><div className="print-end">Generated {printGeneratedAt} · Signal Security Analyst</div></section>
    </div>
  )
}

export default App
