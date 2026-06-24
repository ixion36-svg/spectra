import { useState, useMemo, useEffect, useCallback, useRef, lazy, Suspense } from 'react'
import {
  Shield, BarChart3, GitBranch, Bot, FileText, Settings, Play, Square, Trash2, Download, Search, Plus, X, AlertTriangle, Cpu, FlaskConical,
} from 'lucide-react'
import { format } from 'date-fns'
import { toast } from 'sonner'

import {
  type Finding, type Scan, type Severity, type View, type GraphNode, type GraphEdge, type ToolStatus,
  type TriageStatus, SEVERITY_ORDER, normalizeSeverity, findingPayloadSchema, progressPayloadSchema,
  TRIAGE_STATUSES, TRIAGE_LABELS, triageOf,
} from './types'
import { SpectraEngine } from './lib/engine'
import { exportFindings as exportFindingsFile, type ExportFormat } from './lib/export'
import {
  isTauriEnv, detectInstalledTools, loadScans as loadScansNative, saveScan as saveScanNative,
  tcpPortScan, runExternalScan, httpProbe, cancelRealScan, ollamaGenerateStream, ollamaModels as ollamaModelsNative, listenScanEvents,
} from './lib/tauri'
// Lazy-loaded: @xyflow/react is heavy and only needed on the Attack Graph view,
// so it loads on demand instead of bloating the initial bundle.
const GraphView = lazy(() => import('./components/GraphView').then((m) => ({ default: m.GraphView })))
import { FindingsTable, SeverityBadge, StatusPill } from './components/FindingsTable'
import { CommandPalette } from './components/CommandPalette'

const COMMON_PORTS = [22, 80, 443, 445, 3306, 5432, 8080, 8443, 21, 23, 25, 53, 110, 143, 993, 995, 1723, 3389, 5900, 8000]

function loadInitialScans(): Scan[] {
  try {
    const saved = localStorage.getItem('spectra_scans')
    return saved ? (JSON.parse(saved) as Scan[]) : []
  } catch {
    return []
  }
}

function App() {
  const [scans, setScans] = useState<Scan[]>(loadInitialScans)
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [currentView, setCurrentView] = useState<View>('dashboard')

  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [paletteOpen, setPaletteOpen] = useState(false)

  const [newTargets, setNewTargets] = useState('https://example.com\n10.10.14.7')
  const [newProfile, setNewProfile] = useState('Web Application + AI')
  const [newScanName, setNewScanName] = useState('External perimeter assessment')

  const activeScan = useMemo(() => scans.find((s) => s.id === activeScanId) || null, [scans, activeScanId])
  const hasSimulated = useMemo(() => !!activeScan?.findings.some((f) => f.source === 'simulator'), [activeScan])

  const [severityFilter, setSeverityFilter] = useState<Severity[]>(['critical', 'high', 'medium', 'low', 'info'])
  const [statusFilter, setStatusFilter] = useState<TriageStatus[]>([...TRIAGE_STATUSES])
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)

  const filteredFindings = useMemo(() => {
    if (!activeScan) return []
    const term = searchTerm.toLowerCase()
    return activeScan.findings
      .filter((f) => severityFilter.includes(f.severity))
      .filter((f) => statusFilter.includes(triageOf(f)))
      .filter((f) =>
        !term ||
        f.title.toLowerCase().includes(term) ||
        f.asset.toLowerCase().includes(term) ||
        (f.service && f.service.toLowerCase().includes(term)),
      )
      .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || b.discoveredAt.localeCompare(a.discoveredAt))
  }, [activeScan, severityFilter, statusFilter, searchTerm])

  // Update a finding in place (used by triage controls) and keep the open drawer in sync.
  const updateFinding = useCallback(
    (findingId: string, patch: Partial<Finding>) => {
      setScans((prev) =>
        prev.map((s) =>
          s.id === activeScanId ? { ...s, findings: s.findings.map((f) => (f.id === findingId ? { ...f, ...patch } : f)) } : s,
        ),
      )
      setSelectedFinding((sf) => (sf && sf.id === findingId ? { ...sf, ...patch } : sf))
    },
    [activeScanId],
  )

  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([])
  const [graphEdges, setGraphEdges] = useState<GraphEdge[]>([])

  const [aiMessages, setAiMessages] = useState<{ role: 'user' | 'assistant'; content: string }[]>([
    { role: 'assistant', content: "I'm Spectra's local co-pilot. I analyze findings, suggest attack paths, and help prioritize. If a local Ollama model is running I'll use it for real analysis — otherwise you'll get clearly-labelled demo responses." },
  ])
  const [aiInput, setAiInput] = useState('')
  const [aiLoading, setAiLoading] = useState(false)

  // Configurable local Ollama (model + endpoint), persisted.
  const [ollamaModel, setOllamaModel] = useState(() => localStorage.getItem('spectra_ollama_model') || 'llama3.2')
  const [ollamaEndpoint, setOllamaEndpoint] = useState(() => localStorage.getItem('spectra_ollama_endpoint') || 'http://127.0.0.1:11434')
  const [availableModels, setAvailableModels] = useState<string[]>([])
  useEffect(() => { localStorage.setItem('spectra_ollama_model', ollamaModel) }, [ollamaModel])
  useEffect(() => { localStorage.setItem('spectra_ollama_endpoint', ollamaEndpoint) }, [ollamaEndpoint])

  const [realTools, setRealTools] = useState<ToolStatus[]>([])
  const [useRealEngine, setUseRealEngine] = useState(true)
  const [realScanActive, setRealScanActive] = useState(false)
  const realScanActiveRef = useRef(false)
  useEffect(() => {
    realScanActiveRef.current = realScanActive
  }, [realScanActive])

  const engineRef = useRef<SpectraEngine | null>(null)
  // Scan ids that have reached a terminal state, so a late completion can't
  // overwrite a cancellation (and vice-versa).
  const terminalScansRef = useRef<Set<string>>(new Set())

  const growGraph = useCallback((f: Finding) => {
    const asset = f.asset
    setGraphNodes((prev) => (prev.find((n) => n.id === asset) ? prev : [...prev, { id: asset, label: asset, type: 'host' }]))
    if (f.port && f.service) {
      const svcId = `${asset}:${f.port}`
      setGraphNodes((prev) => (prev.find((n) => n.id === svcId) ? prev : [...prev, { id: svcId, label: `${f.service}:${f.port}`, type: 'service' }]))
      setGraphEdges((prev) => {
        const edgeId = `${asset}-${svcId}`
        return prev.find((e) => e.id === edgeId) ? prev : [...prev, { id: edgeId, source: asset, target: svcId, label: f.service }]
      })
    }
    if (f.source === 'nuclei' || f.source === 'trivy') {
      const vulnId = `${asset}-${f.title.slice(0, 20)}`
      setGraphNodes((prev) => (prev.find((n) => n.id === vulnId) ? prev : [...prev, { id: vulnId, label: f.title, type: 'vuln', severity: f.severity }]))
      setGraphEdges((prev) => {
        const edgeId = `${asset}-${vulnId}`
        return prev.find((e) => e.id === edgeId) ? prev : [...prev, { id: edgeId, source: asset, target: vulnId }]
      })
    }
  }, [])

  const finishScan = useCallback((id: string, status: 'completed' | 'cancelled') => {
    // Idempotent: first terminal transition wins (cancel beats a late completion).
    if (terminalScansRef.current.has(id)) return
    terminalScansRef.current.add(id)
    engineRef.current?.stop()
    engineRef.current = null
    setIsScanning(false)
    setRealScanActive(false)
    setScanProgress(100)
    setScans((prev) => prev.map((s) => (s.id === id ? { ...s, status, completedAt: new Date().toISOString(), progress: 100 } : s)))
    if (status === 'completed') toast.success('Scan complete')
    else toast('Scan cancelled')
  }, [])

  // ── Mount-only: detect tools + hydrate native-persisted scans (runs once) ───
  useEffect(() => {
    if (!isTauriEnv) return
    detectInstalledTools().then(setRealTools).catch(() => {})
    loadScansNative()
      .then((loaded) => {
        if (!loaded?.length) return
        setScans((prev) => {
          const map = new Map(prev.map((s) => [s.id, s] as const))
          loaded.forEach((l) => { if (l?.id && !map.has(l.id)) map.set(l.id, l) })
          return Array.from(map.values()).sort((a, b) => (b.startedAt || '').localeCompare(a.startedAt || ''))
        })
      })
      .catch(() => {})
  }, [])

  // ── Live native scan events, re-bound when the active scan changes ──────────
  useEffect(() => {
    if (!isTauriEnv || !activeScanId) return
    let unlisten: (() => void) | undefined
    let disposed = false

    listenScanEvents((p) => {
      if (!p || p.scan_id !== activeScanId) return

      if (p.event_type === 'finding') {
        const d = findingPayloadSchema.safeParse(p.data)
        if (!d.success) {
          console.warn('Dropping malformed finding payload', d.error.issues)
          return
        }
        const data = d.data
        const f: Finding = {
          id: 'real_' + Date.now() + Math.random().toString(36).slice(2, 7),
          scanId: activeScanId,
          severity: normalizeSeverity(data.severity),
          title: data.title || (data.port ? `Open port ${data.port}` : 'External finding'),
          asset: data.asset || data.matched || data.host || 'target',
          port: data.port,
          service: data.service,
          evidence: data.evidence || data.line || '',
          description: data.description || (data.template ? `Matched by template ${data.template}` : 'Discovered by Spectra native engine.'),
          recommendation: data.recommendation || 'Investigate and remediate according to the finding details.',
          discoveredAt: new Date().toISOString(),
          tags: Array.isArray(data.tags) ? data.tags : data.tags ? [data.tags] : ['external'],
          exploitability: typeof data.exploitability === 'number' ? data.exploitability : data.port ? 40 : 65,
          cwe: data.cwe,
          cve: data.cve,
          source: data.source || (data.port ? 'rust-tcp' : 'external'),
        }
        setScans((prev) => prev.map((s) => (s.id === activeScanId ? { ...s, findings: [...(s.findings || []), f] } : s)))
        growGraph(f)
      } else if (p.event_type === 'progress') {
        const pr = progressPayloadSchema.safeParse(p.data)
        setScanProgress(pr.success ? pr.data.progress ?? 0 : 0)
      } else if (p.event_type === 'complete') {
        // One tool finished. Overall completion is driven by Promise.allSettled
        // over every native job (see startNewScan), so we don't finish here —
        // otherwise the first tool to finish would end the whole scan.
        console.log('[Spectra Real] tool complete')
      } else if (p.event_type === 'cancelled') {
        finishScan(activeScanId, 'cancelled')
      } else if (p.event_type === 'error') {
        toast.error('Native engine error', { description: String((p.data as { message?: string })?.message ?? 'see console') })
      } else if (p.event_type === 'log') {
        console.log('[Spectra Real]', (p.data as { line?: string })?.line)
      }
    }).then((u) => {
      if (disposed) u()
      else unlisten = u
    })

    return () => {
      disposed = true
      if (unlisten) unlisten()
    }
  }, [activeScanId, growGraph, finishScan])

  // ── Persist scans (localStorage, quota-guarded) + native file persistence ───
  useEffect(() => {
    try {
      localStorage.setItem('spectra_scans', JSON.stringify(scans))
    } catch (e) {
      if (e instanceof DOMException && (e.name === 'QuotaExceededError' || e.code === 22)) {
        toast.warning('Local storage full', { description: 'Older scans may not be saved in the browser. The desktop app persists to disk.' })
      }
    }
    if (isTauriEnv && scans[0]) saveScanNative(scans[0]).catch(() => {})
  }, [scans])

  const startNewScan = useCallback(async () => {
    const targets = newTargets.split('\n').map((t) => t.trim()).filter(Boolean)
    if (targets.length === 0) {
      toast.error('Add at least one target')
      return
    }

    const id = 'scan_' + Date.now().toString(36)
    const newScan: Scan = {
      id,
      name: newScanName || `Scan ${format(new Date(), 'yyyy-MM-dd HH:mm')}`,
      targets,
      profile: newProfile,
      status: 'running',
      startedAt: new Date().toISOString(),
      findings: [],
      progress: 0,
    }

    setScans((prev) => [newScan, ...prev])
    setActiveScanId(id)
    setCurrentView('findings')
    setScanProgress(0)
    setIsScanning(true)
    setSelectedFinding(null)
    setGraphNodes([])
    setGraphEdges([])
    setSearchTerm('')
    setSeverityFilter(['critical', 'high', 'medium', 'low', 'info'])

    if (isTauriEnv && useRealEngine) {
      setRealScanActive(true)
      const bestTool = realTools.find((t) => t.available && ['trivy', 'nmap'].includes(t.name))?.name

      // Fan out every native job across ALL targets; the scan is "complete" only
      // once every job settles (resolved or rejected), so a single tool finishing
      // — or failing to spawn — doesn't end the whole scan early.
      const jobs: Promise<unknown>[] = []
      for (const target of targets) {
        const host = target.replace(/^https?:\/\//, '').split('/')[0]
        jobs.push(tcpPortScan(id, host, COMMON_PORTS, 80).catch((e) => console.warn('TCP scan error', e)))
        jobs.push(runExternalScan(id, 'nuclei', target, []).catch((e) => console.warn('Nuclei error', e)))
        if (bestTool) jobs.push(runExternalScan(id, bestTool, target, []).catch((e) => console.warn('Secondary tool error', e)))

        if (target.includes('http') || target.includes('.')) {
          jobs.push(
            httpProbe(target)
              .then((probe) => {
                if (!probe?.server) return
                const f: Finding = {
                  id: 'probe_' + Date.now() + Math.random().toString(36).slice(2, 6),
                  scanId: id,
                  severity: 'low',
                  title: `Web server banner: ${probe.server}`,
                  asset: target,
                  evidence: JSON.stringify(probe),
                  description: 'HTTP probe result from native reqwest client.',
                  recommendation: 'Harden headers and review exposed version information.',
                  discoveredAt: new Date().toISOString(),
                  tags: ['http', 'banner', 'rust'],
                  source: 'rust-http',
                }
                setScans((prev) => prev.map((s) => (s.id === id ? { ...s, findings: [...(s.findings || []), f] } : s)))
              })
              .catch(() => {}),
          )
        }
      }

      Promise.allSettled(jobs).then(() => finishScan(id, 'completed'))
      toast('Native scan started', {
        description: `${targets.length} target${targets.length > 1 ? 's' : ''} • ${bestTool ? `nuclei + ${bestTool} + Rust TCP` : 'nuclei + Rust TCP'}`,
      })
    } else {
      const engine = new SpectraEngine(
        (finding) => setScans((prev) => prev.map((s) => (s.id === id ? { ...s, findings: [...s.findings, finding] } : s))),
        (prog) => {
          if (!realScanActiveRef.current) setScanProgress(prog)
          setScans((prev) => prev.map((s) => (s.id === id ? { ...s, progress: Math.max(s.progress, prog) } : s)))
        },
        (asset, port, service) => growGraph({ asset, port, service, source: 'simulator' } as Finding),
      )
      engineRef.current = engine
      engine.start(targets, newProfile, id)
      toast('Simulated scan started', { description: 'Demo data — enable real tools in the desktop app for live results.' })
    }
  }, [newTargets, newProfile, newScanName, realTools, useRealEngine, growGraph, finishScan])

  const cancelScan = useCallback(() => {
    if (!activeScanId) return
    if (isTauriEnv && useRealEngine) cancelRealScan(activeScanId).catch(() => {})
    finishScan(activeScanId, 'cancelled') // marks terminal; a late completion becomes a no-op
  }, [activeScanId, useRealEngine, finishScan])

  // Simulator completion is driven by progress; native completion by the 'complete' event.
  useEffect(() => {
    if (activeScan && activeScan.progress >= 100 && activeScan.status === 'running' && !realScanActiveRef.current) {
      finishScan(activeScan.id, 'completed')
    }
  }, [activeScan, finishScan])

  const deleteScan = (id: string) => {
    if (activeScanId === id) {
      cancelScan()
      setActiveScanId(null)
      setCurrentView('dashboard')
    }
    setScans((prev) => prev.filter((s) => s.id !== id))
  }

  const loadScan = (scan: Scan) => {
    setActiveScanId(scan.id)
    setCurrentView('findings')
    setScanProgress(scan.progress)
    setIsScanning(scan.status === 'running')
    setSelectedFinding(null)
    const nodes: GraphNode[] = []
    const seen = new Set<string>()
    scan.findings.forEach((f) => {
      if (!seen.has(f.asset)) {
        nodes.push({ id: f.asset, label: f.asset, type: 'host' })
        seen.add(f.asset)
      }
    })
    setGraphNodes(nodes)
    setGraphEdges([])
  }

  const sendToAI = async () => {
    if (!aiInput.trim()) return
    const question = aiInput.trim()
    setAiMessages((m) => [...m, { role: 'user', content: question }])
    setAiInput('')
    setAiLoading(true)

    const contextFindings = activeScan ? activeScan.findings.slice(0, 12) : []
    const context = contextFindings.length
      ? `Current scan context (${activeScan?.name}):\n` +
        contextFindings.map((f) => `- [${f.severity.toUpperCase()}] ${f.title} on ${f.asset}${f.port ? ':' + f.port : ''} (exploitability ${f.exploitability || 'n/a'})`).join('\n')
      : 'No active scan data.'
    const prompt = `You are an elite red team / appsec analyst AI embedded in Spectra vulnerability scanner.\n\n${context}\n\nUser question: ${question}\n\nRespond concisely, prioritize real risk, suggest concrete next steps or validation commands. Mention specific CVEs or techniques when relevant. Be direct.`

    // Append an empty assistant placeholder, then stream tokens into it.
    setAiMessages((m) => [...m, { role: 'assistant', content: '' }])
    const appendToLast = (tok: string) =>
      setAiMessages((m) => {
        const copy = [...m]
        const i = copy.length - 1
        copy[i] = { ...copy[i], content: copy[i].content + tok }
        return copy
      })
    const replaceLast = (content: string) =>
      setAiMessages((m) => {
        const copy = [...m]
        copy[copy.length - 1] = { role: 'assistant', content }
        return copy
      })

    let streamed = ''
    const onToken = (tok: string) => {
      streamed += tok
      appendToLast(tok)
    }

    try {
      if (isTauriEnv) {
        await ollamaGenerateStream(prompt, ollamaModel, ollamaEndpoint, onToken) // proxied + streamed through Rust
      } else {
        const res = await fetch(`${ollamaEndpoint}/api/generate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ model: ollamaModel, prompt, stream: true, options: { temperature: 0.3 } }),
        })
        if (!res.ok || !res.body) throw new Error('Ollama not responding')
        const reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buf = ''
        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })
          let nl: number
          while ((nl = buf.indexOf('\n')) >= 0) {
            const line = buf.slice(0, nl).trim()
            buf = buf.slice(nl + 1)
            if (!line) continue
            try {
              const j = JSON.parse(line) as { response?: string }
              if (j.response) onToken(j.response)
            } catch {
              /* ignore partial/non-JSON line */
            }
          }
        }
      }
      if (!streamed.trim()) throw new Error('empty response')
    } catch {
      // Honest demo fallback — summarizes REAL scan data, never invents findings.
      const f = activeScan?.findings ?? []
      const crit = f.filter((x) => x.severity === 'critical').length
      const high = f.filter((x) => x.severity === 'high').length
      const top = [...f].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity])[0]
      const summary = f.length
        ? `This scan has ${f.length} findings (${crit} critical, ${high} high). Prioritise the highest-severity item${top ? `, e.g. "${top.title}" on ${top.asset}` : ''}, then validate and remediate in severity order.`
        : 'There is no scan data loaded yet. Start a scan, then ask me to prioritise the findings.'
      replaceLast(`⚠️ DEMO MODE — no local Ollama model reachable. ${summary}\n\nStart Ollama with a model (e.g. \`ollama pull llama3.2\`) for live AI analysis.`)
    } finally {
      setAiLoading(false)
    }
  }

  const exportFindings = (fmt: ExportFormat) => {
    if (activeScan) exportFindingsFile(activeScan, fmt)
  }

  // Query the configured Ollama endpoint for its installed models.
  const detectModels = async () => {
    try {
      let names: string[]
      if (isTauriEnv) {
        names = await ollamaModelsNative(ollamaEndpoint)
      } else {
        const res = await fetch(`${ollamaEndpoint}/api/tags`)
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()
        names = ((data.models ?? []) as { name: string }[]).map((m) => m.name)
      }
      setAvailableModels(names)
      if (names.length) {
        toast.success(`Found ${names.length} model${names.length > 1 ? 's' : ''}`)
        if (!names.includes(ollamaModel)) setOllamaModel(names[0])
      } else {
        toast('No models installed', { description: 'Pull one with `ollama pull llama3.2`.' })
      }
    } catch {
      toast.error('Could not reach Ollama', { description: ollamaEndpoint })
    }
  }

  // Keyboard: Cmd/Ctrl+K → palette; '/' → new scan; Esc → close drawer
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen((o) => !o)
      } else if (e.key === '/' && document.activeElement?.tagName === 'BODY') {
        e.preventDefault()
        setCurrentView('new')
      } else if (e.key === 'Escape' && selectedFinding) {
        setSelectedFinding(null)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [selectedFinding])

  const Stat = ({ label, value, color }: { label: string; value: number | string; color?: string }) => (
    <div className="text-center">
      <div className="text-2xl font-semibold tabular-nums" style={{ color: color || 'var(--text-h)' }}>{value}</div>
      <div className="text-[11px] uppercase tracking-[1px] text-muted">{label}</div>
    </div>
  )

  return (
    <div className="flex h-screen text-sm overflow-hidden bg-[#0b0c11] text-[#a1a1aa]">
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} onNavigate={setCurrentView} onNewScan={startNewScan} />

      {/* Sidebar */}
      <div className="w-64 border-r border-[#24262f] bg-[#0f1117] flex flex-col">
        <div className="p-5 border-b border-[#24262f] flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-400 to-teal-500 flex items-center justify-center text-black">
            <Shield size={18} />
          </div>
          <div>
            <div className="font-semibold text-lg tracking-[-0.5px] text-white">SPECTRA</div>
            <div className="text-[10px] text-[#52525b] -mt-1">BEYOND TRADITIONAL SCANNING</div>
          </div>
        </div>

        <div className="p-3 space-y-1">
          {([
            { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
            { id: 'new', label: 'New Scan', icon: Plus },
            { id: 'findings', label: 'Findings', icon: Search },
            { id: 'graph', label: 'Attack Graph', icon: GitBranch },
            { id: 'ai', label: 'AI Co-pilot', icon: Bot },
            { id: 'reports', label: 'Reports', icon: FileText },
            { id: 'settings', label: 'Settings', icon: Settings },
          ] as const).map((item) => {
            const Icon = item.icon
            return (
              <button key={item.id} onClick={() => setCurrentView(item.id)} className={`sidebar-link w-full justify-start ${currentView === item.id ? 'active' : ''}`}>
                <Icon size={16} /> {item.label}
              </button>
            )
          })}
        </div>

        <div className="mt-auto p-3 border-t border-[#24262f] text-[11px] text-[#52525b]">
          Local-first • Authorized use only<br />
          v0.1.0 • Tauri-ready • ⌘K
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        <div className="h-14 border-b border-[#24262f] px-5 flex items-center justify-between bg-[#0f1117]">
          <div className="flex items-center gap-3">
            {activeScan ? (
              <div className="flex items-center gap-2 text-sm">
                <span className="font-medium text-white">{activeScan.name}</span>
                <span className="text-[#52525b]">•</span>
                <span className="font-mono text-xs">{activeScan.targets.length} targets • {activeScan.profile}</span>
              </div>
            ) : (
              <div className="text-white font-medium tracking-tight">Spectra Vulnerability Intelligence</div>
            )}
          </div>

          <div className="flex items-center gap-2">
            {isScanning && activeScan && (
              <>
                <div className="flex items-center gap-2 text-xs px-3 py-1 rounded bg-[#16181f] border border-[#24262f]">
                  <div className="w-2 h-2 bg-[#22d3ee] animate-pulse rounded-full" /> SCANNING
                  <span className="font-mono tabular-nums">{scanProgress}%</span>
                </div>
                <button onClick={cancelScan} className="btn btn-danger text-xs px-3 py-1.5"><Square size={14} /> CANCEL</button>
              </>
            )}
            {activeScan && activeScan.status !== 'running' && (
              <button onClick={() => deleteScan(activeScan.id)} className="btn btn-ghost text-xs"><Trash2 size={14} /> Delete Scan</button>
            )}
            <button onClick={() => setCurrentView('new')} className="btn btn-primary text-xs"><Plus size={14} /> NEW SCAN</button>
          </div>
        </div>

        {/* Safety banner */}
        <div className="bg-[#1a1209] border-b border-[#3f2a14] px-5 py-2 text-xs flex items-center gap-2 text-[#f4a261]">
          <AlertTriangle size={14} />
          <span>For <strong>authorized security testing only</strong>. Never scan systems without explicit permission. All activity is logged locally.</span>
        </div>

        {/* Simulated-data banner — prevents mistaking demo findings for real intel */}
        {hasSimulated && (
          <div className="bg-[#2a1430] border-b border-[#5b2a6b] px-5 py-2 text-xs flex items-center gap-2 text-[#e9a8ff]">
            <FlaskConical size={14} />
            <span>This scan contains <strong>SIMULATED demo findings</strong> (source: simulator). They are illustrative and not real results.</span>
          </div>
        )}

        {isTauriEnv && (
          <div className="bg-[#0f1a1f] border-b border-[#1f3a42] px-5 py-1.5 text-xs flex items-center gap-3 text-[#67e8f9]">
            <Cpu size={13} />
            <span className="font-medium">Native engine</span>
            <span className="text-[#a1a1aa]">
              {realTools.length > 0
                ? realTools.filter((t) => t.available).map((t) => `${t.name}${t.version ? ' ' + t.version.split(' ').pop() : ''}`).join(' • ') || 'no external tools detected'
                : 'detecting tools...'}
            </span>
            <span className="ml-2 px-2 py-0.5 bg-emerald-900 text-emerald-300 rounded text-[10px]">REAL MODE</span>
            <label className="ml-auto flex items-center gap-1.5 cursor-pointer text-[#67e8f9]">
              <input type="checkbox" checked={useRealEngine} onChange={(e) => setUseRealEngine(e.target.checked)} className="accent-[#67e8f9]" />
              Prefer real tools when available
            </label>
          </div>
        )}

        <div className="flex-1 overflow-auto p-6">
          {currentView === 'dashboard' && (
            <div>
              <div className="flex items-end justify-between mb-6">
                <div>
                  <h1 className="text-4xl tracking-[-1.5px] text-white">Dashboard</h1>
                  <p className="text-[#71717a]">Recent scans &amp; intelligence overview</p>
                </div>
                <button onClick={() => setCurrentView('new')} className="btn btn-primary">Start New Scan</button>
              </div>

              {scans.length === 0 && (
                <div className="card p-10 text-center max-w-lg mx-auto mt-12">
                  <Shield className="mx-auto mb-4 text-[#22d3ee]" size={42} />
                  <div className="text-xl font-semibold text-white mb-2">No scans yet</div>
                  <p className="text-sm mb-6">Launch your first scan to see Spectra's correlation engine, live attack graph, and local AI co-pilot in action.</p>
                  <button onClick={() => setCurrentView('new')} className="btn btn-primary mx-auto">Create first scan</button>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                {scans.slice(0, 6).map((scan) => {
                  const crit = scan.findings.filter((f) => f.severity === 'critical').length
                  const high = scan.findings.filter((f) => f.severity === 'high').length
                  return (
                    <div key={scan.id} onClick={() => loadScan(scan)} className="card p-5 hover:border-[#32343e] cursor-pointer transition-colors">
                      <div className="flex justify-between">
                        <div className="font-semibold text-white pr-4">{scan.name}</div>
                        <div className={`text-[10px] px-2 py-0.5 rounded ${scan.status === 'running' ? 'bg-[#22d3ee] text-black' : 'bg-[#24262f]'}`}>{scan.status}</div>
                      </div>
                      <div className="text-xs text-[#71717a] mt-1 font-mono">{scan.targets.join(', ')}</div>
                      <div className="flex gap-6 mt-5">
                        <Stat label="Findings" value={scan.findings.length} />
                        <Stat label="Critical" value={crit} color="var(--critical)" />
                        <Stat label="High" value={high} color="var(--high)" />
                      </div>
                      <div className="mt-4 text-[10px] text-[#52525b] flex justify-between">
                        <div>{format(new Date(scan.startedAt), 'PPp')}</div>
                        <div className="font-mono">{scan.profile}</div>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {currentView === 'new' && (
            <div className="max-w-2xl">
              <h1 className="text-4xl tracking-[-1.5px] text-white mb-1">New Scan</h1>
              <p className="mb-8 text-[#71717a]">Define targets and choose an intelligence profile. Spectra will discover, correlate, and augment results with local analysis.</p>

              <div className="space-y-6">
                <div>
                  <div className="text-xs uppercase tracking-widest mb-2 text-[#52525b]">Scan Name</div>
                  <input className="input" value={newScanName} onChange={(e) => setNewScanName(e.target.value)} />
                </div>
                <div>
                  <div className="text-xs uppercase tracking-widest mb-2 text-[#52525b]">Targets (one per line, IPs, hostnames, or URLs)</div>
                  <textarea className="input font-mono h-28" value={newTargets} onChange={(e) => setNewTargets(e.target.value)} />
                </div>
                <div>
                  <div className="text-xs uppercase tracking-widest mb-2 text-[#52525b]">Profile — determines depth and "beyond" analysis</div>
                  <div className="grid grid-cols-2 gap-2">
                    {['Quick Recon', 'Web Application', 'Network + Services', 'Web Application + AI', 'Deep + AI Augmented', 'Custom (all checks)'].map((p) => (
                      <button key={p} onClick={() => setNewProfile(p)} className={`btn justify-start text-left h-auto py-3 ${newProfile === p ? 'btn-primary' : 'btn-secondary'}`}>{p}</button>
                    ))}
                  </div>
                </div>
                <div className="flex items-center gap-3 mt-2">
                  <button onClick={startNewScan} className="btn btn-primary flex-1 py-3 text-base"><Play size={18} /> LAUNCH SPECTRA ENGINE</button>
                  {isTauriEnv && realTools.length > 0 && (
                    <label className="flex items-center gap-2 text-xs cursor-pointer select-none">
                      <input type="checkbox" checked={useRealEngine} onChange={(e) => setUseRealEngine(e.target.checked)} className="accent-[#22d3ee]" />
                      Use real tools (Nmap/Nuclei/Trivy + Rust)
                    </label>
                  )}
                </div>
                <div className="text-[11px] text-center text-[#52525b]">In the desktop app, real tools produce actual results. In the browser, scans are simulated demo data.</div>
              </div>
            </div>
          )}

          {currentView === 'findings' && activeScan && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-white text-2xl tracking-tight">Findings <span className="text-[#52525b] font-mono">({filteredFindings.length})</span></h2>
                  <div className="text-xs text-[#52525b]">Live results • Click any row for deep analysis and AI context</div>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => exportFindings('json')} className="btn btn-ghost text-xs"><Download size={14} /> JSON</button>
                  <button onClick={() => exportFindings('csv')} className="btn btn-ghost text-xs"><Download size={14} /> CSV</button>
                  <button onClick={() => exportFindings('md')} className="btn btn-ghost text-xs"><Download size={14} /> Markdown</button>
                  <button onClick={() => exportFindings('sarif')} className="btn btn-ghost text-xs"><Download size={14} /> SARIF</button>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 mb-3">
                {(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => (
                  <button
                    key={s}
                    onClick={() => setSeverityFilter((prev) => (prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]))}
                    className={`badge sev-${s} cursor-pointer ${!severityFilter.includes(s) ? 'opacity-40 line-through' : ''}`}
                  >
                    {s}
                  </button>
                ))}
                <span className="w-px h-4 bg-[#24262f] mx-1" />
                {TRIAGE_STATUSES.map((st) => (
                  <button
                    key={st}
                    onClick={() => setStatusFilter((prev) => (prev.includes(st) ? prev.filter((x) => x !== st) : [...prev, st]))}
                    className={`status-pill status-${st} is-button ${statusFilter.includes(st) ? 'active' : ''}`}
                    title={`Toggle ${TRIAGE_LABELS[st]}`}
                  >
                    {TRIAGE_LABELS[st]}
                  </button>
                ))}
                <input className="input w-64 ml-auto text-sm h-8" placeholder="Filter by asset, title, service..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} />
              </div>

              <FindingsTable findings={filteredFindings} onSelect={setSelectedFinding} />

              {selectedFinding && (
                <div className="fixed right-0 top-14 bottom-0 w-[440px] border-l border-[#24262f] bg-[#12141b] p-6 overflow-auto z-50 shadow-2xl">
                  <button onClick={() => setSelectedFinding(null)} className="absolute top-4 right-4 text-[#71717a]"><X /></button>
                  <div className="mb-3 flex items-center gap-2"><SeverityBadge sev={selectedFinding.severity} /> <StatusPill status={triageOf(selectedFinding)} /></div>
                  <h3 className="text-xl leading-tight text-white font-semibold pr-8">{selectedFinding.title}</h3>
                  <div className="mt-4 text-xs font-mono text-[#52525b]">{selectedFinding.asset}{selectedFinding.port ? ':' + selectedFinding.port : ''}</div>

                  <div className="mt-5">
                    <div className="uppercase text-[10px] tracking-widest text-[#52525b] mb-1.5">Triage</div>
                    <div className="flex flex-wrap gap-1.5">
                      {TRIAGE_STATUSES.map((st) => (
                        <button
                          key={st}
                          onClick={() => updateFinding(selectedFinding.id, { status: st })}
                          className={`status-pill status-${st} is-button ${triageOf(selectedFinding) === st ? 'active' : ''}`}
                        >
                          {TRIAGE_LABELS[st]}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="mt-6 text-sm space-y-4">
                    <div>
                      <div className="uppercase text-[10px] tracking-widest text-[#52525b] mb-1">Evidence</div>
                      <div className="text-[#ededf0] break-words">{selectedFinding.evidence}</div>
                    </div>
                    <div>
                      <div className="uppercase text-[10px] tracking-widest text-[#52525b] mb-1">Description</div>
                      <div>{selectedFinding.description}</div>
                    </div>
                    <div>
                      <div className="uppercase text-[10px] tracking-widest text-[#52525b] mb-1">Recommendation</div>
                      <div className="text-[#ededf0]">{selectedFinding.recommendation}</div>
                    </div>
                  </div>

                  <div className="mt-8 grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
                    {selectedFinding.cvss && <div>CVSS <span className="font-mono text-white">{selectedFinding.cvss}</span></div>}
                    {selectedFinding.exploitability != null && <div>Exploitability <span className="font-mono text-[#22d3ee]">{selectedFinding.exploitability}</span></div>}
                    {selectedFinding.cwe ? <div>{String(selectedFinding.cwe)}</div> : null}
                    {selectedFinding.owasp && <div>{selectedFinding.owasp}</div>}
                    {selectedFinding.source && <div>Source <span className="font-mono text-[#67e8f9]">{selectedFinding.source}</span></div>}
                  </div>

                  <div className="mt-8 pt-6 border-t border-[#24262f]">
                    <button
                      onClick={() => {
                        setCurrentView('ai')
                        const ctx = `Source: ${selectedFinding.source || 'unknown'}\n${selectedFinding.cve ? 'CVE: ' + selectedFinding.cve : ''}\n${selectedFinding.cwe ? 'CWE: ' + selectedFinding.cwe : ''}`
                        setAiMessages((prev) => [...prev, { role: 'user', content: `Analyze this finding and suggest validation steps: ${selectedFinding.title} on ${selectedFinding.asset}\n\n${ctx}\nEvidence: ${selectedFinding.evidence}` }])
                      }}
                      className="btn btn-secondary w-full"
                    >
                      <Bot size={15} /> Ask AI Co-pilot about this finding
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {currentView === 'graph' && (
            <div className="h-[calc(100vh-120px)]">
              <div className="flex justify-between items-center mb-3">
                <div>
                  <h2 className="text-white text-2xl tracking-tight">Attack Surface Graph</h2>
                  <div className="text-xs text-[#52525b]">Live correlation of hosts, services and high-value findings</div>
                </div>
                <div className="text-xs text-[#71717a]">Nodes and edges are added in real time during scans</div>
              </div>
              <div className="card h-[90%] border-[#32343e] overflow-hidden">
                <div style={{ height: '100%' }} className="bg-[#0b0c11]">
                  <Suspense fallback={<div className="h-full flex items-center justify-center text-[#52525b] text-sm">Loading graph…</div>}>
                    <GraphView nodes={graphNodes} edges={graphEdges} />
                  </Suspense>
                </div>
              </div>
            </div>
          )}

          {currentView === 'ai' && (
            <div className="max-w-3xl">
              <h2 className="text-white text-2xl tracking-tight mb-1 flex items-center gap-2"><Bot /> AI Co-pilot</h2>
              <p className="text-xs text-[#71717a] mb-4">Local intelligence (Ollama) or clearly-labelled demo mode. Full scan context is provided automatically.</p>

              <div className="card p-0 overflow-hidden h-[520px] flex flex-col">
                <div className="flex-1 p-5 space-y-4 overflow-auto text-sm bg-[#12141b]">
                  {aiMessages.map((m, idx) =>
                    !m.content ? null : (
                      <div key={idx} className={m.role === 'user' ? 'text-right' : ''}>
                        <div className={`inline-block max-w-[85%] px-4 py-2 rounded-2xl whitespace-pre-wrap text-left ${m.role === 'user' ? 'bg-[#22d3ee] text-black' : 'bg-[#24262f] text-[#ededf0]'}`}>{m.content}</div>
                      </div>
                    ),
                  )}
                  {aiLoading && <div className="text-[#52525b] text-xs">Thinking with local model…</div>}
                </div>
                <div className="border-t border-[#24262f] p-3 flex gap-2 bg-[#16181f]">
                  <input
                    className="input flex-1"
                    placeholder="Ask about risk, next steps, attack paths, or specific findings..."
                    value={aiInput}
                    onChange={(e) => setAiInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && !aiLoading && sendToAI()}
                    disabled={aiLoading}
                  />
                  <button onClick={sendToAI} disabled={aiLoading || !aiInput.trim()} className="btn btn-primary">Send</button>
                </div>
              </div>
              <div className="text-[11px] mt-2 text-[#52525b]">Model <span className="font-mono text-[#71717a]">{ollamaModel}</span> @ <span className="font-mono text-[#71717a]">{ollamaEndpoint}</span> (configurable in Settings). Demo mode is used when no model is reachable.</div>
            </div>
          )}

          {currentView === 'reports' && activeScan && (
            <div className="max-w-2xl">
              <h2 className="text-white text-2xl mb-4 tracking-tight">Report — {activeScan.name}</h2>
              <div className="card p-6 space-y-4">
                <button onClick={() => exportFindings('md')} className="btn btn-primary w-full">Export Full Markdown Report</button>
                <button onClick={() => exportFindings('json')} className="btn btn-secondary w-full">Export Machine-Readable JSON</button>
                <button onClick={() => exportFindings('sarif')} className="btn btn-secondary w-full">Export SARIF 2.1 (DefectDojo, GitHub code scanning)</button>
                <div className="text-xs text-[#52525b] pt-2">Roadmap: PDF, HTML executive summary, Jira ticket creation.</div>
              </div>
            </div>
          )}

          {currentView === 'settings' && (
            <div className="max-w-xl">
              <h2 className="text-white text-2xl tracking-tight mb-6">Settings</h2>
              <div className="card p-6 space-y-6 text-sm">
                <div>
                  <div className="font-semibold mb-2">Local AI (Ollama)</div>
                  <div className="text-[#71717a] mb-3">Private, local analysis — proxied through the Rust backend in the desktop app (no CORS).</div>
                  <div className="grid grid-cols-1 gap-3">
                    <label className="block">
                      <span className="text-[10px] uppercase tracking-widest text-[#52525b]">Endpoint</span>
                      <input className="input mt-1 font-mono text-xs" value={ollamaEndpoint} onChange={(e) => setOllamaEndpoint(e.target.value)} placeholder="http://127.0.0.1:11434" />
                    </label>
                    <label className="block">
                      <span className="text-[10px] uppercase tracking-widest text-[#52525b]">Model</span>
                      <input className="input mt-1 font-mono text-xs" value={ollamaModel} onChange={(e) => setOllamaModel(e.target.value)} placeholder="llama3.2" />
                    </label>
                  </div>
                  <div className="flex items-center gap-2 mt-3">
                    <button onClick={detectModels} className="btn btn-secondary text-xs">Detect installed models</button>
                    {availableModels.length > 0 && <span className="text-[10px] text-[#52525b]">{availableModels.length} found</span>}
                  </div>
                  {availableModels.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {availableModels.map((m) => (
                        <button
                          key={m}
                          onClick={() => setOllamaModel(m)}
                          className={`status-pill is-button ${ollamaModel === m ? 'status-triaged active' : 'status-open'}`}
                        >
                          {m}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
                <div>
                  <div className="font-semibold mb-1">External Tool Integration</div>
                  <div className="text-[#71717a]">In the Tauri desktop app, Spectra auto-detects nmap, nuclei and trivy and orchestrates them, enriching results with correlation + LLM analysis.</div>
                </div>
                <div>
                  <div className="font-semibold mb-1">Data</div>
                  <button onClick={() => { localStorage.clear(); window.location.reload() }} className="btn btn-ghost text-xs">Clear all local scans &amp; data</button>
                </div>
              </div>
            </div>
          )}

          {!activeScan && (currentView === 'findings' || currentView === 'graph' || currentView === 'ai' || currentView === 'reports') && (
            <div className="text-center text-[#52525b] mt-16">Select or start a scan from the Dashboard or New Scan view.</div>
          )}
        </div>

        <div className="h-7 border-t border-[#24262f] bg-[#0f1117] px-4 text-[10px] flex items-center text-[#52525b] font-mono justify-between">
          <div>SPECTRA • LOCAL • {scans.length} scans stored</div>
          <div>Press <span className="text-[#71717a]">⌘K</span> for the command palette • Built for defenders &amp; red teams</div>
        </div>
      </div>
    </div>
  )
}

export default App
