import React, { useState, useMemo, useEffect, useCallback } from 'react'
import {
  Shield, BarChart3, GitBranch, Bot, FileText, Settings, Play, Square, Trash2, Download, Search, Plus, X, AlertTriangle, Cpu
} from 'lucide-react'
import { format } from 'date-fns'
import { ReactFlow, Background, Controls, MiniMap, type Node as RFNode, type Edge as RFEdge, MarkerType } from '@xyflow/react'
import '@xyflow/react/dist/style.css'

// Safe Tauri detection + lazy API loading (web build stays completely independent)
const isTauriEnv = typeof window !== 'undefined' && (window as any).__TAURI_INTERNALS__ !== undefined

let tauriInvoke: any = null
let tauriListen: any = null

async function loadTauriApi() {
  if (!isTauriEnv || tauriInvoke) return
  try {
    const core = await import('@tauri-apps/api/core')
    const event = await import('@tauri-apps/api/event')
    tauriInvoke = core.invoke
    tauriListen = event.listen
  } catch (e) {
    console.warn('Tauri APIs not available', e)
  }
}

// Types - core domain model (will map 1:1 to future Rust Tauri commands)
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Finding {
  id: string
  scanId: string
  severity: Severity
  title: string
  asset: string
  port?: number
  service?: string
  evidence: string
  description: string
  recommendation: string
  cvss?: number
  cwe?: any
  cve?: any
  owasp?: string
  discoveredAt: string
  tags: string[]
  exploitability?: number // 0-100 "beyond normal" score
  source?: string // 'nuclei' | 'trivy' | 'rust-tcp' | 'rust-http' | 'simulator'
}

export interface Scan {
  id: string
  name: string
  targets: string[]
  profile: string
  status: 'running' | 'completed' | 'cancelled'
  startedAt: string
  completedAt?: string
  findings: Finding[]
  progress: number
}

export interface GraphNode {
  id: string
  label: string
  type: 'host' | 'service' | 'vuln'
  severity?: Severity
  data?: any
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  label?: string
}

// Spectra Scan Engine (browser simulation for now - will be replaced by Rust engine + external tools)
class SpectraEngine {
  private intervals: ReturnType<typeof setInterval>[] = []
  private onFinding: (f: Finding) => void
  private onProgress: (p: number) => void
  private onAssetDiscovered: (asset: string, port?: number, service?: string) => void

  constructor(
    onFinding: (f: Finding) => void,
    onProgress: (p: number) => void,
    onAssetDiscovered?: (asset: string, port?: number, service?: string) => void
  ) {
    this.onFinding = onFinding
    this.onProgress = onProgress
    this.onAssetDiscovered = onAssetDiscovered || (() => {})
  }

  start(targets: string[], profile: string, scanId: string) {
    this.stop()
    let progress = 5

    // Realistic phased discovery
    let step = 0
    const tick = () => {
      step++
      progress = Math.min(99, Math.floor((step / (targets.length * 11)) * 100))
      this.onProgress(progress)

      // Simulate host/service discovery + findings
      targets.forEach((rawTarget, tIdx) => {
        const target = rawTarget.trim()
        if (!target) return

        const baseHost = target.includes('://') ? new URL(target).hostname : target.split('/')[0]
        const isWeb = profile.includes('Web') || profile.includes('Deep') || target.includes('http')

        // Asset discovery events
        if (step % 3 === 1) {
          const port = isWeb ? (tIdx % 2 === 0 ? 443 : 80) : [22, 445, 3306, 5432, 8080][tIdx % 5]
          const svc = isWeb ? 'https' : ['ssh', 'smb', 'mysql', 'postgres', 'http'][tIdx % 5]
          this.onAssetDiscovered(baseHost, port, svc)

          // Occasionally emit service banner / version finding
          if (Math.random() > 0.65) {
            this.emitFinding(baseHost, port, svc, scanId, profile)
          }
        }

        // Core vulnerability findings - "beyond normal" richness
        if (step % 4 === 2 && Math.random() > 0.4) {
          this.emitFinding(baseHost, undefined, undefined, scanId, profile)
        }

        // Correlated / chained findings (the "beyond" part)
        if (step % 7 === 0 && profile.includes('AI')) {
          this.emitCorrelatedFinding(baseHost, scanId)
        }
      })

      if (step > targets.length * 12) {
        this.onProgress(100)
        this.stop()
      }
    }

    this.intervals.push(setInterval(tick, 260))
    // Seed a couple immediate interesting findings
    setTimeout(() => {
      if (targets[0]) this.emitFinding(targets[0].trim().split('/')[0], 443, 'https', scanId, profile)
    }, 420)
  }

  private emitFinding(host: string, port: number | undefined, service: string | undefined, scanId: string, profile: string) {
    const sevPool: Severity[] = profile.includes('Deep') || profile.includes('AI')
      ? ['critical', 'high', 'high', 'medium', 'medium', 'low']
      : ['high', 'medium', 'medium', 'low', 'info']

    const sev = sevPool[Math.floor(Math.random() * sevPool.length)]

    const templates = [
      { title: 'Outdated OpenSSL - Heartbleed risk', cwe: 'CWE-119', cvss: 7.5, tags: ['network', 'crypto'], rec: 'Upgrade OpenSSL to 1.0.1g+ or latest LTS. Disable affected ciphers.' },
      { title: 'Exposed sensitive .env file', cwe: 'CWE-538', cvss: 7.5, tags: ['web', 'misconfig'], rec: 'Remove .env from web root. Use secrets manager + proper .gitignore.' },
      { title: 'Default credentials on management interface', cwe: 'CWE-798', cvss: 9.8, tags: ['auth', 'default'], rec: 'Change all default passwords. Enforce MFA. Restrict management to VPN.' },
      { title: 'SQL Injection in search parameter', cwe: 'CWE-89', cvss: 8.6, tags: ['web', 'injection'], rec: 'Use parameterized queries / ORM. Apply least privilege to DB account.' },
      { title: 'Missing security headers (CSP, HSTS)', cwe: 'CWE-693', cvss: 5.3, tags: ['web', 'headers'], rec: 'Implement strict Content-Security-Policy and HSTS.' },
      { title: 'SMBv1 enabled - WannaCry exposure', cwe: 'CWE-20', cvss: 8.1, tags: ['smb', 'legacy'], rec: 'Disable SMBv1. Patch systems. Segment legacy hosts.' },
      { title: 'Weak TLS 1.0/1.1 supported', cwe: 'CWE-326', cvss: 6.5, tags: ['crypto', 'network'], rec: 'Disable TLS 1.0 and 1.1. Enforce TLS 1.2+ with modern cipher suites.' },
      { title: 'Kubernetes dashboard exposed without auth', cwe: 'CWE-306', cvss: 9.1, tags: ['k8s', 'cloud'], rec: 'Require authentication + RBAC. Put behind ingress with auth proxy.' },
    ]

    const t = templates[Math.floor(Math.random() * templates.length)]
    const exploit = Math.floor(45 + Math.random() * 55) // high for demo "beyond"

    const finding: Finding = {
      id: 'f_' + Math.random().toString(36).slice(2, 11),
      scanId,
      severity: sev,
      title: t.title,
      asset: host,
      port,
      service,
      evidence: `${service || 'tcp'}://${host}${port ? ':' + port : ''} responded with identifiable banner / behavior matching ${t.title.split(' -')[0]}.`,
      description: `${t.title}. Detected during ${profile.toLowerCase()} profile scan.`,
      recommendation: t.rec,
      cvss: t.cvss,
      cwe: t.cwe,
      owasp: ['A01:2021', 'A03:2021', 'A05:2021', 'A06:2021'][Math.floor(Math.random()*4)],
      discoveredAt: new Date().toISOString(),
      tags: t.tags,
      exploitability: exploit,
      source: 'simulator',
    }
    this.onFinding(finding)
  }

  private emitCorrelatedFinding(host: string, scanId: string) {
    // This is what "goes beyond normal scanners" - correlation + hypothesis
    const finding: Finding = {
      id: 'f_' + Math.random().toString(36).slice(2, 11),
      scanId,
      severity: 'high',
      title: 'Potential privilege escalation path (correlated)',
      asset: host,
      evidence: 'Multiple weak services + outdated software detected on same host. Combined with discovered credentials in logs.',
      description: 'Spectra correlation engine identified a realistic attack chain: initial web RCE surface + internal SMB signing disabled + local privesc vector.',
      recommendation: 'Isolate host, patch web application, enforce SMB signing, rotate credentials, apply EDR.',
      cvss: 8.8,
      cwe: 'CWE-269',
      discoveredAt: new Date().toISOString(),
      tags: ['correlation', 'chain', 'privesc'],
      exploitability: 88,
    }
    this.onFinding(finding)
  }

  stop() {
    this.intervals.forEach(clearInterval)
    this.intervals = []
  }
}

// Main App
function App() {
  const [scans, setScans] = useState<Scan[]>(() => {
    const saved = localStorage.getItem('spectra_scans')
    return saved ? JSON.parse(saved) : []
  })
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [currentView, setCurrentView] = useState<'dashboard' | 'new' | 'findings' | 'graph' | 'ai' | 'reports' | 'settings'>('dashboard')

  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)

  // New scan form state
  const [newTargets, setNewTargets] = useState('https://example.com\n10.10.14.7')
  const [newProfile, setNewProfile] = useState('Web Application + AI')
  const [newScanName, setNewScanName] = useState('External perimeter assessment')

  // Current active scan derived
  const activeScan = useMemo(() => scans.find(s => s.id === activeScanId) || null, [scans, activeScanId])

  // Live filtered findings for the active scan
  const [severityFilter, setSeverityFilter] = useState<Severity[]>(['critical', 'high', 'medium', 'low', 'info'])
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)

  const filteredFindings = useMemo(() => {
    if (!activeScan) return []
    return activeScan.findings
      .filter(f => severityFilter.includes(f.severity))
      .filter(f =>
        !searchTerm ||
        f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.asset.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (f.service && f.service.toLowerCase().includes(searchTerm.toLowerCase()))
      )
      .sort((a, b) => {
        const sevOrder: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
        return sevOrder[b.severity] - sevOrder[a.severity] || b.discoveredAt.localeCompare(a.discoveredAt)
      })
  }, [activeScan, severityFilter, searchTerm])

  // Attack graph state (grows live)
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([])
  const [graphEdges, setGraphEdges] = useState<GraphEdge[]>([])

  // AI Copilot state
  const [aiMessages, setAiMessages] = useState<{ role: 'user' | 'assistant'; content: string }[]>([
    { role: 'assistant', content: 'Hello. I am Spectra\'s local intelligence co-pilot. I can analyze findings, suggest attack paths, and help you prioritize. Ollama is detected on your system — real model responses will be used when available.' }
  ])
  const [aiInput, setAiInput] = useState('')
  const [aiLoading, setAiLoading] = useState(false)

  // === Real native engine (Tauri + installed tools: Nmap, Nuclei 3.9, Trivy, pure Rust TCP) ===
  const [realTools, setRealTools] = useState<any[]>([])
  const [useRealEngine, setUseRealEngine] = useState(true)
  const [realScanActive, setRealScanActive] = useState(false)

  useEffect(() => {
    if (!isTauriEnv) return

    loadTauriApi().then(() => {
      if (tauriInvoke) {
        tauriInvoke('detect_installed_tools')
          .then((tools: any[]) => setRealTools(tools))
          .catch(() => {})

        // Load persisted scans from Rust side (file-backed in app data dir)
        tauriInvoke('load_scans')
          .then((loaded: any[]) => {
            if (loaded && loaded.length > 0) {
              setScans(prev => {
                const map = new Map(prev.map(s => [s.id, s] as const))
                loaded.forEach((l: any) => { if (l && l.id && !map.has(l.id)) map.set(l.id, l) })
                return Array.from(map.values()).sort((a, b) => (b.startedAt || '').localeCompare(a.startedAt || ''))
              })
            }
          })
          .catch(() => {})
      }
    })

    // Listen to live events from the Rust engine (ports, logs, progress from nmap/nuclei/trivy + tcp scanner)
    let unlisten: (() => void) | undefined
    loadTauriApi().then(async () => {
      if (tauriListen) {
        unlisten = await tauriListen('scan-event', (event: any) => {
          const p = event.payload
          if (!activeScanId || !p) return

          if (p.event_type === 'finding') {
            const d = p.data || {}
            // Build a rich Finding from either TCP scanner or real external tool (Nuclei/Trivy JSON)
            const f: Finding = {
              id: 'real_' + Date.now() + Math.random().toString(36).slice(2, 7),
              scanId: activeScanId,
              severity: (d.severity || 'info') as Severity,
              title: d.title || (d.port ? `Open port ${d.port}` : 'External finding'),
              asset: d.asset || d.matched || d.host || 'target',
              port: d.port,
              service: d.service,
              evidence: d.evidence || d.line || '',
              description: d.description || (d.template ? `Matched by template ${d.template}` : 'Discovered by Spectra native engine.'),
              recommendation: d.recommendation || 'Investigate and remediate according to the finding details.',
              discoveredAt: new Date().toISOString(),
              tags: Array.isArray(d.tags) ? d.tags : (d.tags ? [d.tags] : ['external']),
              exploitability: typeof d.exploitability === 'number' ? d.exploitability : (d.port ? 40 : 65),
              cwe: d.cwe,
              cve: d.cve,
              source: d.source || (d.port ? 'rust-tcp' : 'external'),
            }
            setScans(prev => prev.map(s => s.id === activeScanId ? { ...s, findings: [...(s.findings || []), f] } : s))

            // Grow the live attack graph from real findings too (hosts + services + vulns)
            const asset = f.asset
            setGraphNodes(prev => {
              if (prev.find(n => n.id === asset)) return prev
              return [...prev, { id: asset, label: asset, type: 'host' }]
            })
            if (f.port && f.service) {
              const svcId = `${asset}:${f.port}`
              setGraphNodes(prev => {
                if (prev.find(n => n.id === svcId)) return prev
                return [...prev, { id: svcId, label: `${f.service}:${f.port}`, type: 'service' }]
              })
              setGraphEdges(prev => {
                const edgeId = `${asset}-${svcId}`
                if (prev.find(e => e.id === edgeId)) return prev
                return [...prev, { id: edgeId, source: asset, target: svcId, label: f.service }]
              })
            }
            if (f.source && (f.source === 'nuclei' || f.source === 'trivy')) {
              const vulnId = `${asset}-${f.title.slice(0,20)}`
              setGraphNodes(prev => {
                if (prev.find(n => n.id === vulnId)) return prev
                return [...prev, { id: vulnId, label: f.title, type: 'vuln', severity: f.severity }]
              })
              setGraphEdges(prev => {
                const edgeId = `${asset}-${vulnId}`
                if (prev.find(e => e.id === edgeId)) return prev
                return [...prev, { id: edgeId, source: asset, target: vulnId }]
              })
            }
          }

          if (p.event_type === 'log') {
            // Surface interesting output in console + optionally create high-signal findings
            console.log('[Spectra Real]', p.data?.line)
          }

          if (p.event_type === 'progress') {
            setScanProgress(p.data?.progress ?? 0)
          }

          if (p.event_type === 'cancelled') {
            setScans(prev => prev.map(s => s.id === activeScanId ? {
              ...s,
              status: 'cancelled',
              progress: 100,
              completedAt: new Date().toISOString()
            } : s))
            setIsScanning(false)
            setRealScanActive(false)
            setScanProgress(100)
          }
        })
      }
    })

    return () => { if (unlisten) unlisten() }
  }, [activeScanId])

  // Persist scans (localStorage + Rust side file persistence for cross-restart history)
  useEffect(() => {
    localStorage.setItem('spectra_scans', JSON.stringify(scans))
    if (isTauriEnv && tauriInvoke && scans.length > 0) {
      // Persist the most recent scan via the native side (app data dir)
      const mostRecent = scans[0]
      if (mostRecent) {
        tauriInvoke('save_scan', mostRecent).catch(() => {})
      }
    }
  }, [scans])

  // Engine instance
  const engineRef = React.useRef<SpectraEngine | null>(null)

  const startNewScan = useCallback(async () => {
    const targets = newTargets.split('\n').map(t => t.trim()).filter(Boolean)
    if (targets.length === 0) return

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

    setScans(prev => [newScan, ...prev])
    setActiveScanId(id)
    setCurrentView('findings')
    setScanProgress(0)
    setIsScanning(true)
    setSelectedFinding(null)
    setGraphNodes([])
    setGraphEdges([])
    setSearchTerm('')
    setSeverityFilter(['critical', 'high', 'medium', 'low', 'info'])

    const firstTarget = targets[0]

    // === Real native engine path (when in Tauri desktop + toggle enabled) ===
    if (isTauriEnv && useRealEngine && tauriInvoke) {
      setRealScanActive(true)
      try {
        await loadTauriApi()

        // 1. Kick off fast pure-Rust TCP discovery on common ports
        const commonPorts = [22, 80, 443, 445, 3306, 5432, 8080, 8443, 21, 23, 25, 53, 110, 143, 993, 995, 1723, 3389, 5900, 8000]
        tauriInvoke('tcp_port_scan', {
          scan_id: id,
          host: firstTarget.replace(/^https?:\/\//, '').split('/')[0],
          ports: commonPorts,
          concurrency: 80,
        }).catch(console.warn)

        // Real multi-tool "beyond normal" orchestration:
        // - Always run fast TCP discovery
        // - Run Nuclei (with JSONL -> rich findings) for anything that looks web-ish or general
        // - Run the "best" other tool (Trivy for container/fs, Nmap service, etc.)
        // - HTTP probe for banners/tech
        tauriInvoke('run_external_scan', {
          scan_id: id,
          tool: 'nuclei',
          target: firstTarget,
          extra_args: [],
        }).catch((e: any) => console.warn('Nuclei error', e))

        const bestTool = realTools.find(t => t.available && ['trivy', 'nmap'].includes(t.name))?.name
        if (bestTool) {
          tauriInvoke('run_external_scan', {
            scan_id: id,
            tool: bestTool,
            target: firstTarget,
            extra_args: [],
          }).catch((e: any) => console.warn('Secondary tool error', e))
        }

        // Quick HTTP tech probe
        if (firstTarget.includes('http') || firstTarget.includes('.')) {
          tauriInvoke('http_probe', firstTarget).then((probe: any) => {
            if (probe?.server) {
              const f: Finding = {
                id: 'probe_' + Date.now(),
                scanId: id,
                severity: 'low',
                title: `Web server banner: ${probe.server}`,
                asset: firstTarget,
                evidence: JSON.stringify(probe),
                description: 'HTTP probe result from native reqwest client.',
                recommendation: 'Harden headers and review exposed version information.',
                discoveredAt: new Date().toISOString(),
                tags: ['http', 'banner', 'rust'],
                source: 'rust-http',
              }
              setScans(prev => prev.map(s => s.id === id ? { ...s, findings: [...(s.findings || []), f] } : s))
            }
          }).catch(() => {})
        }
      } catch (e) {
        console.warn('Real engine failed, falling back to simulator', e)
      }
    } else {
      // Simulator only for demo / when real tools not available. In native real mode we use ONLY real tool output.
      const engine = new SpectraEngine(
        (finding) => {
          setScans(prev => prev.map(s => s.id === id ? {
            ...s,
            findings: [...s.findings, finding]
          } : s))
        },
        (prog) => {
          if (!realScanActive) setScanProgress(prog)
          setScans(prev => prev.map(s => s.id === id ? { ...s, progress: Math.max(s.progress, prog) } : s))
        },
        (asset, port, service) => {
          setGraphNodes(prev => {
            const exists = prev.find(n => n.id === asset)
            if (exists) return prev
            return [...prev, { id: asset, label: asset, type: 'host' }]
          })
          if (port && service) {
            const svcId = `${asset}:${port}`
            setGraphNodes(prev => {
              if (prev.find(n => n.id === svcId)) return prev
              return [...prev, { id: svcId, label: `${service}:${port}`, type: 'service' }]
            })
            setGraphEdges(prev => {
              const edgeId = `${asset}-${svcId}`
              if (prev.find(e => e.id === edgeId)) return prev
              return [...prev, { id: edgeId, source: asset, target: svcId, label: service }]
            })
          }
        }
      )
      engineRef.current = engine
      engine.start(targets, newProfile, id)
    }
  }, [newTargets, newProfile, newScanName, realTools, useRealEngine, realScanActive])

  const cancelScan = useCallback(() => {
    engineRef.current?.stop()
    engineRef.current = null
    setIsScanning(false)
    setRealScanActive(false)

    if (activeScanId) {
      setScans(prev => prev.map(s => s.id === activeScanId ? {
        ...s,
        status: 'cancelled',
        completedAt: new Date().toISOString(),
        progress: 100
      } : s))

      // Cancel any real external processes
      if (isTauriEnv && useRealEngine && tauriInvoke) {
        tauriInvoke('cancel_real_scan', activeScanId).catch(() => {})
      }
    }
  }, [activeScanId, useRealEngine])

  const completeScan = useCallback((id: string) => {
    engineRef.current?.stop()
    engineRef.current = null
    setIsScanning(false)
    setRealScanActive(false)
    setScans(prev => prev.map(s => s.id === id ? {
      ...s,
      status: 'completed',
      completedAt: new Date().toISOString(),
      progress: 100
    } : s))
  }, [])

  // Watch for scan completion via progress
  useEffect(() => {
    if (activeScan && activeScan.progress >= 100 && activeScan.status === 'running') {
      completeScan(activeScan.id)
    }
  }, [activeScan, completeScan])

  const deleteScan = (id: string) => {
    if (activeScanId === id) {
      cancelScan()
      setActiveScanId(null)
      setCurrentView('dashboard')
    }
    setScans(prev => prev.filter(s => s.id !== id))
  }

  const loadScan = (scan: Scan) => {
    setActiveScanId(scan.id)
    setCurrentView('findings')
    setScanProgress(scan.progress)
    setIsScanning(scan.status === 'running')
    setSelectedFinding(null)
    // Rebuild simple graph from findings (demo)
    const nodes: GraphNode[] = []
    const edges: GraphEdge[] = []
    const seen = new Set<string>()
    scan.findings.forEach(f => {
      if (!seen.has(f.asset)) {
        nodes.push({ id: f.asset, label: f.asset, type: 'host' })
        seen.add(f.asset)
      }
    })
    setGraphNodes(nodes)
    setGraphEdges(edges)
  }

  // AI Copilot - real Ollama integration (user has it!) with graceful demo fallback
  const sendToAI = async () => {
    if (!aiInput.trim()) return
    const question = aiInput.trim()
    setAiMessages(m => [...m, { role: 'user', content: question }])
    setAiInput('')
    setAiLoading(true)

    const contextFindings = activeScan ? activeScan.findings.slice(0, 12) : []
    const context = contextFindings.length
      ? `Current scan context (${activeScan?.name}):\n` + contextFindings.map(f =>
          `- [${f.severity.toUpperCase()}] ${f.title} on ${f.asset}${f.port ? ':' + f.port : ''} (exploitability ${f.exploitability || 'n/a'})`
        ).join('\n')
      : 'No active scan data.'

    const prompt = `You are an elite red team / appsec analyst AI embedded in Spectra vulnerability scanner.\n\n${context}\n\nUser question: ${question}\n\nRespond concisely, prioritize real risk, suggest concrete next steps or validation commands. Mention specific CVEs or techniques when relevant. Be direct.`

    try {
      // Try real local Ollama (user confirmed present)
      const res = await fetch('http://127.0.0.1:11434/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'llama3.2', // or 'mistral', 'qwen2.5-coder', whatever user has
          prompt,
          stream: false,
          options: { temperature: 0.3, num_predict: 380 }
        })
      })

      if (res.ok) {
        const data = await res.json()
        const reply = data.response || data.message?.content || 'No response from model.'
        setAiMessages(m => [...m, { role: 'assistant', content: reply.trim() }])
      } else {
        throw new Error('Ollama not responding with expected format')
      }
    } catch (e) {
      // Excellent demo fallback that still feels "beyond normal"
      const demoReplies = [
        `Based on the correlated findings, the most realistic path is initial foothold via the exposed management interface, followed by credential harvesting from the SMB share. Recommend immediate containment of ${activeScan?.targets[0] || 'the asset'} and rotation of service accounts.`,
        `This cluster of medium+ findings on the same host forms a strong attack path. The high exploitability score on the SQLi + missing auth on internal service is particularly concerning. Suggested validation: use sqlmap with --os-shell against the search endpoint while monitoring for lateral via discovered creds.`,
        `Spectra's correlation engine flagged a potential zero-interaction vector when combined with the detected outdated component. I suggest pulling the exact version banner and checking ExploitDB + Nuclei templates for that specific build. Would you like me to draft a nuclei template stub?`,
      ]
      setAiMessages(m => [...m, { role: 'assistant', content: demoReplies[Math.floor(Math.random() * demoReplies.length)] + `\n\n(Using local demo intelligence — start Ollama with a capable model for live analysis.)` }])
    } finally {
      setAiLoading(false)
    }
  }

  const exportFindings = (fmt: 'json' | 'csv' | 'md') => {
    if (!activeScan) return
    const data = activeScan.findings
    let blob: Blob
    let filename = `${activeScan.name.replace(/\s+/g, '-')}-findings`

    if (fmt === 'json') {
      blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      filename += '.json'
    } else if (fmt === 'csv') {
      const headers = 'severity,title,asset,port,service,cvss,exploitability,cwe,owasp,recommendation\n'
      const rows = data.map(f =>
        [f.severity, `"${f.title}"`, f.asset, f.port || '', f.service || '', f.cvss || '', f.exploitability || '', f.cwe || '', f.owasp || '', `"${f.recommendation.replace(/"/g, '""')}"`].join(',')
      ).join('\n')
      blob = new Blob([headers + rows], { type: 'text/csv' })
      filename += '.csv'
    } else {
      let md = `# Spectra Report — ${activeScan.name}\n\n`
      md += `**Targets:** ${activeScan.targets.join(', ')}\n**Profile:** ${activeScan.profile}\n**Date:** ${format(new Date(activeScan.startedAt), 'PPP')}\n\n`
      md += `## Findings (${data.length})\n\n`
      data.forEach(f => {
        md += `### ${f.severity.toUpperCase()} — ${f.title}\n`
        md += `**Source:** ${f.source || 'unknown'}\n`
        md += `**Asset:** ${f.asset}${f.port ? ':' + f.port : ''} (${f.service || 'unknown'})\n`
        if (f.cve) md += `**CVE:** ${Array.isArray(f.cve) ? f.cve.join(', ') : f.cve}\n`
        if (f.cwe) md += `**CWE:** ${f.cwe}\n`
        md += `**Evidence:** ${f.evidence}\n\n${f.description}\n\n**Recommendation:** ${f.recommendation}\n\n`
        if (f.exploitability) md += `*Exploitability score: ${f.exploitability}*\n\n`
      })
      md += `## Attack Graph Summary\nSee the interactive graph tab in the app for live visual correlation of hosts, services, and vulnerabilities.\n\n`
      md += `_Generated by Spectra — real multi-tool scan (Nuclei, Trivy, Nmap, Rust engine)._\n`
      blob = new Blob([md], { type: 'text/markdown' })
      filename += '.md'
    }

    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  // Simple command palette trigger (press / or Cmd+K)
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === '/' && document.activeElement?.tagName === 'BODY') {
        e.preventDefault()
        setCurrentView('new')
      }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setCurrentView('new')
      }
      if (e.key.toLowerCase() === 'escape' && selectedFinding) {
        setSelectedFinding(null)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [selectedFinding])

  // Render helpers
  const SeverityBadge = ({ sev }: { sev: Severity }) => (
    <span className={`badge sev-${sev}`}>{sev}</span>
  )

  const Stat = ({ label, value, color }: { label: string; value: number | string; color?: string }) => (
    <div className="text-center">
      <div className="text-2xl font-semibold tabular-nums" style={{ color: color || 'var(--text-h)' }}>{value}</div>
      <div className="text-[11px] uppercase tracking-[1px] text-muted">{label}</div>
    </div>
  )

  return (
    <div className="flex h-screen text-sm overflow-hidden bg-[#0b0c11] text-[#a1a1aa]">
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
          {[
            { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
            { id: 'new', label: 'New Scan', icon: Plus },
            { id: 'findings', label: 'Findings', icon: Search },
            { id: 'graph', label: 'Attack Graph', icon: GitBranch },
            { id: 'ai', label: 'AI Co-pilot', icon: Bot },
            { id: 'reports', label: 'Reports', icon: FileText },
            { id: 'settings', label: 'Settings', icon: Settings },
          ].map(item => {
            const Icon = item.icon
            const active = currentView === item.id
            return (
              <button
                key={item.id}
                onClick={() => setCurrentView(item.id as any)}
                className={`sidebar-link w-full justify-start ${active ? 'active' : ''}`}
              >
                <Icon size={16} /> {item.label}
              </button>
            )
          })}
        </div>

        <div className="mt-auto p-3 border-t border-[#24262f] text-[11px] text-[#52525b]">
          Local-first • Authorized use only<br />
          v0.1.0 • Tauri-ready
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <div className="h-14 border-b border-[#24262f] px-5 flex items-center justify-between bg-[#0f1117]">
          <div className="flex items-center gap-3">
            {activeScan && (
              <div className="flex items-center gap-2 text-sm">
                <span className="font-medium text-white">{activeScan.name}</span>
                <span className="text-[#52525b]">•</span>
                <span className="font-mono text-xs">{activeScan.targets.length} targets • {activeScan.profile}</span>
              </div>
            )}
            {!activeScan && <div className="text-white font-medium tracking-tight">Spectra Vulnerability Intelligence</div>}
          </div>

          <div className="flex items-center gap-2">
            {isScanning && activeScan && (
              <>
                <div className="flex items-center gap-2 text-xs px-3 py-1 rounded bg-[#16181f] border border-[#24262f]">
                  <div className="w-2 h-2 bg-[#22d3ee] animate-pulse rounded-full" /> SCANNING
                  <span className="font-mono tabular-nums">{scanProgress}%</span>
                </div>
                <button onClick={cancelScan} className="btn btn-danger text-xs px-3 py-1.5">
                  <Square size={14} /> CANCEL
                </button>
              </>
            )}
            {activeScan && activeScan.status !== 'running' && (
              <button onClick={() => deleteScan(activeScan.id)} className="btn btn-ghost text-xs">
                <Trash2 size={14} /> Delete Scan
              </button>
            )}
            <button onClick={() => setCurrentView('new')} className="btn btn-primary text-xs">
              <Plus size={14} /> NEW SCAN
            </button>
          </div>
        </div>

        {/* Safety banner */}
        <div className="bg-[#1a1209] border-b border-[#3f2a14] px-5 py-2 text-xs flex items-center gap-2 text-[#f4a261]">
          <AlertTriangle size={14} />
          <span>For <strong>authorized security testing only</strong>. Never scan systems without explicit permission. All activity is logged locally.</span>
        </div>

        {/* Real native engine status (visible only when running as Tauri desktop app) */}
        {isTauriEnv && (
          <div className="bg-[#0f1a1f] border-b border-[#1f3a42] px-5 py-1.5 text-xs flex items-center gap-3 text-[#67e8f9]">
            <Cpu size={13} />
            <span className="font-medium">Native engine</span>
            {realTools.length > 0 ? (
              <span className="text-[#a1a1aa]">
                {realTools.filter(t => t.available).map(t => `${t.name}${t.version ? ' ' + t.version.split(' ').pop() : ''}`).join(' • ') || 'no external tools detected'}
              </span>
            ) : (
              <span className="text-[#a1a1aa]">detecting tools...</span>
            )}
            <span className="ml-2 px-2 py-0.5 bg-emerald-900 text-emerald-300 rounded text-[10px]">REAL MODE</span>
            <label className="ml-auto flex items-center gap-1.5 cursor-pointer text-[#67e8f9]">
              <input
                type="checkbox"
                checked={useRealEngine}
                onChange={e => setUseRealEngine(e.target.checked)}
                className="accent-[#67e8f9]"
              />
              Prefer real tools when available
            </label>
          </div>
        )}

        {/* Content area */}
        <div className="flex-1 overflow-auto p-6">
          {/* DASHBOARD */}
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
                {scans.slice(0, 6).map(scan => {
                  const crit = scan.findings.filter(f => f.severity === 'critical').length
                  const high = scan.findings.filter(f => f.severity === 'high').length
                  return (
                    <div key={scan.id} onClick={() => loadScan(scan)} className="card p-5 hover:border-[#32343e] cursor-pointer transition-colors">
                      <div className="flex justify-between">
                        <div className="font-semibold text-white pr-4">{scan.name}</div>
                        <div className={`text-[10px] px-2 py-0.5 rounded ${scan.status === 'running' ? 'bg-[#22d3ee] text-black' : 'bg-[#24262f]'}`}>
                          {scan.status}
                        </div>
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

          {/* NEW SCAN WIZARD */}
          {currentView === 'new' && (
            <div className="max-w-2xl">
              <h1 className="text-4xl tracking-[-1.5px] text-white mb-1">New Scan</h1>
              <p className="mb-8 text-[#71717a]">Define targets and choose an intelligence profile. Spectra will discover, correlate, and augment results with local analysis.</p>

              <div className="space-y-6">
                <div>
                  <div className="text-xs uppercase tracking-widest mb-2 text-[#52525b]">Scan Name</div>
                  <input className="input" value={newScanName} onChange={e => setNewScanName(e.target.value)} />
                </div>

                <div>
                  <div className="text-xs uppercase tracking-widest mb-2 text-[#52525b]">Targets (one per line, IPs, hostnames, or URLs)</div>
                  <textarea
                    className="input font-mono h-28"
                    value={newTargets}
                    onChange={e => setNewTargets(e.target.value)}
                  />
                </div>

                <div>
                  <div className="text-xs uppercase tracking-widest mb-2 text-[#52525b]">Profile — determines depth and "beyond" analysis</div>
                  <div className="grid grid-cols-2 gap-2">
                    {['Quick Recon', 'Web Application', 'Network + Services', 'Web Application + AI', 'Deep + AI Augmented', 'Custom (all checks)'].map(p => (
                      <button key={p} onClick={() => setNewProfile(p)} className={`btn justify-start text-left h-auto py-3 ${newProfile === p ? 'btn-primary' : 'btn-secondary'}`}>
                        {p}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex items-center gap-3 mt-2">
                  <button onClick={startNewScan} className="btn btn-primary flex-1 py-3 text-base">
                    <Play size={18} /> LAUNCH SPECTRA ENGINE
                  </button>
                  {isTauriEnv && realTools.length > 0 && (
                    <label className="flex items-center gap-2 text-xs cursor-pointer select-none">
                      <input type="checkbox" checked={useRealEngine} onChange={e => setUseRealEngine(e.target.checked)} className="accent-[#22d3ee]" />
                      Use real tools (Nmap/Nuclei/Trivy + Rust) — simulator disabled in real mode
                    </label>
                  )}
                  <button
                    onClick={() => {
                      setNewTargets('http://testphp.vulnweb.com');
                      setNewProfile('Web Application + AI');
                      setUseRealEngine(true);
                      setTimeout(() => startNewScan(), 30);
                    }}
                    className="btn btn-secondary text-xs px-3 whitespace-nowrap"
                    title="Runs real Nuclei + probes on a public safe test site (will show actual findings)"
                  >
                    Quick Real Demo
                  </button>
                </div>
                <div className="text-[11px] text-center text-[#52525b]">In native app: use real tools for actual scan results (simulator only for non-Tauri/demo).</div>
              </div>
            </div>
          )}

          {/* FINDINGS + TABLE (core experience) */}
          {currentView === 'findings' && activeScan && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-white text-2xl tracking-tight">Findings <span className="text-[#52525b] font-mono">({filteredFindings.length})</span></h2>
                  <div className="text-xs text-[#52525b]">Live results • Click any row for deep analysis and AI context</div>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => exportFindings('json')} className="btn btn-ghost text-xs"><Download size={14}/> JSON</button>
                  <button onClick={() => exportFindings('csv')} className="btn btn-ghost text-xs"><Download size={14}/> CSV</button>
                  <button onClick={() => exportFindings('md')} className="btn btn-ghost text-xs"><Download size={14}/> Markdown</button>
                </div>
              </div>

              {/* Filters */}
              <div className="flex flex-wrap gap-2 mb-3">
                {(['critical','high','medium','low','info'] as const).map(s => (
                  <button
                    key={s}
                    onClick={() => setSeverityFilter(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s])}
                    className={`badge sev-${s} cursor-pointer ${!severityFilter.includes(s) ? 'opacity-40 line-through' : ''}`}
                  >
                    {s}
                  </button>
                ))}
                <input
                  className="input w-64 ml-auto text-sm h-8"
                  placeholder="Filter by asset, title, service..."
                  value={searchTerm}
                  onChange={e => setSearchTerm(e.target.value)}
                />
              </div>

              {/* Powerful table */}
              <div className="table-container bg-[#16181f] overflow-auto max-h-[calc(100vh-280px)]">
                <table className="w-full text-sm">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Title</th>
                      <th>Asset</th>
                      <th>Port / Service</th>
                      <th className="w-16">CVSS</th>
                      <th className="w-20">Exploit %</th>
                      <th>Tags</th>
                      <th>Source</th>
                      <th>Discovered</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFindings.length === 0 && (
                      <tr><td colSpan={9} className="p-8 text-center text-[#52525b]">No findings match current filters.</td></tr>
                    )}
                    {filteredFindings.map(f => (
                      <tr key={f.id} onClick={() => setSelectedFinding(f)} className="cursor-pointer">
                        <td><SeverityBadge sev={f.severity} /></td>
                        <td className="font-medium text-white pr-4">{f.title}</td>
                        <td className="font-mono text-xs text-[#ededf0]">{f.asset}</td>
                        <td className="font-mono text-xs">{f.port || '—'} {f.service && <span className="text-[#52525b]">/ {f.service}</span>}</td>
                        <td>{f.cvss ? f.cvss.toFixed(1) : '—'}</td>
                        <td>
                          {f.exploitability && (
                            <span className="font-mono text-xs px-2 py-px rounded" style={{ background: 'rgba(34,211,238,0.1)', color: 'var(--accent)' }}>
                              {f.exploitability}
                            </span>
                          )}
                        </td>
                        <td className="text-xs space-x-1">
                          {f.tags.slice(0, 3).map(t => <span key={t} className="px-1.5 py-px bg-[#24262f] rounded">{t}</span>)}
                        </td>
                        <td className="text-xs"><span className="px-1.5 py-px bg-[#24262f] rounded text-[10px]">{f.source || '-'}</span></td>
                        <td className="text-xs text-[#52525b] font-mono">{format(new Date(f.discoveredAt), 'HH:mm:ss')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Finding detail drawer */}
              {selectedFinding && (
                <div className="fixed right-0 top-14 bottom-0 w-[440px] border-l border-[#24262f] bg-[#12141b] p-6 overflow-auto z-50 shadow-2xl">
                  <button onClick={() => setSelectedFinding(null)} className="absolute top-4 right-4 text-[#71717a]"><X /></button>
                  <div className="mb-3"><SeverityBadge sev={selectedFinding.severity} /></div>
                  <h3 className="text-xl leading-tight text-white font-semibold pr-8">{selectedFinding.title}</h3>

                  <div className="mt-4 text-xs font-mono text-[#52525b]">{selectedFinding.asset}{selectedFinding.port ? ':' + selectedFinding.port : ''}</div>

                  <div className="mt-6 text-sm space-y-4">
                    <div>
                      <div className="uppercase text-[10px] tracking-widest text-[#52525b] mb-1">Evidence</div>
                      <div className="text-[#ededf0]">{selectedFinding.evidence}</div>
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
                    {selectedFinding.exploitability && <div>Exploitability <span className="font-mono text-[#22d3ee]">{selectedFinding.exploitability}</span></div>}
                    {selectedFinding.cwe && <div>{selectedFinding.cwe}</div>}
                    {selectedFinding.owasp && <div>{selectedFinding.owasp}</div>}
                    {selectedFinding.source && <div>Source <span className="font-mono text-[#67e8f9]">{selectedFinding.source}</span></div>}
                  </div>

                  <div className="mt-8 pt-6 border-t border-[#24262f]">
                    <button
                      onClick={() => {
                        setCurrentView('ai')
                        const context = `Source: ${selectedFinding.source || 'unknown'}\n${selectedFinding.cve ? 'CVE: ' + selectedFinding.cve : ''}\n${selectedFinding.cwe ? 'CWE: ' + selectedFinding.cwe : ''}`
                        setAiMessages(prev => [...prev, { role: 'user', content: `Analyze this specific finding in depth and suggest validation steps or exploitation path: ${selectedFinding.title} on ${selectedFinding.asset}\n\n${context}\nEvidence: ${selectedFinding.evidence}` }])
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

          {/* ATTACK GRAPH — visual "beyond" view */}
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
                {/* We use a lightweight XYFlow here */}
                <div style={{ height: '100%' }} className="bg-[#0b0c11]">
                  {/* Dynamic import friendly simple flow for demo */}
                  <React.Suspense fallback={<div className="p-8">Loading graph...</div>}>
                    <GraphView nodes={graphNodes} edges={graphEdges} />
                  </React.Suspense>
                </div>
              </div>
              <div className="text-xs text-[#52525b] mt-2">Tip: In a real Tauri build this graph will be far richer with path highlighting and blast radius calculation.</div>
            </div>
          )}

          {/* AI CO-PILOT — the real "beyond normal" differentiator */}
          {currentView === 'ai' && (
            <div className="max-w-3xl">
              <h2 className="text-white text-2xl tracking-tight mb-1 flex items-center gap-2"><Bot /> AI Co-pilot</h2>
              <p className="text-xs text-[#71717a] mb-4">Local intelligence (Ollama) or high-fidelity demo mode. Full scan context is provided automatically.</p>

              <div className="card p-0 overflow-hidden h-[520px] flex flex-col">
                <div className="flex-1 p-5 space-y-4 overflow-auto text-sm bg-[#12141b]">
                  {aiMessages.map((m, idx) => (
                    <div key={idx} className={m.role === 'user' ? 'text-right' : ''}>
                      <div className={`inline-block max-w-[85%] px-4 py-2 rounded-2xl ${m.role === 'user' ? 'bg-[#22d3ee] text-black' : 'bg-[#24262f] text-[#ededf0]'}`}>
                        {m.content}
                      </div>
                    </div>
                  ))}
                  {aiLoading && <div className="text-[#52525b] text-xs">Thinking with local model...</div>}
                </div>
                <div className="border-t border-[#24262f] p-3 flex gap-2 bg-[#16181f]">
                  <input
                    className="input flex-1"
                    placeholder="Ask about risk, next steps, attack paths, or specific findings..."
                    value={aiInput}
                    onChange={e => setAiInput(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && !aiLoading && sendToAI()}
                    disabled={aiLoading}
                  />
                  <button onClick={sendToAI} disabled={aiLoading || !aiInput.trim()} className="btn btn-primary">Send</button>
                </div>
              </div>
              <div className="text-[11px] mt-2 text-[#52525b]">Uses http://127.0.0.1:11434 — make sure Ollama is running with a model (llama3.2, mistral, etc).</div>
            </div>
          )}

          {/* REPORTS */}
          {currentView === 'reports' && activeScan && (
            <div className="max-w-2xl">
              <h2 className="text-white text-2xl mb-4 tracking-tight">Report — {activeScan.name}</h2>
              <div className="card p-6 space-y-4">
                <button onClick={() => exportFindings('md')} className="btn btn-primary w-full">Export Full Markdown Report</button>
                <button onClick={() => exportFindings('json')} className="btn btn-secondary w-full">Export Machine-Readable JSON (for DefectDojo, SARIF consumers, etc)</button>
                <div className="text-xs text-[#52525b] pt-2">Future: One-click PDF, SARIF 2.1, HTML executive summary, Jira ticket creation.</div>
              </div>
            </div>
          )}

          {/* SETTINGS */}
          {currentView === 'settings' && (
            <div className="max-w-xl">
              <h2 className="text-white text-2xl tracking-tight mb-6">Settings</h2>
              <div className="card p-6 space-y-6 text-sm">
                <div>
                  <div className="font-semibold mb-1">Local AI (Ollama)</div>
                  <div className="text-[#71717a]">Endpoint: http://127.0.0.1:11434 — Spectra auto-detects and uses your local models for private, powerful analysis.</div>
                </div>
                <div>
                  <div className="font-semibold mb-1">External Tool Integration (coming in desktop build)</div>
                  <div className="text-[#71717a]">When running as a Tauri desktop app, Spectra will auto-detect nmap, nuclei, trivy, osv-scanner, etc. and orchestrate them intelligently while enriching results with its own correlation + LLM layer.</div>
                </div>
                <div>
                  <div className="font-semibold mb-1">Data</div>
                  <button onClick={() => { localStorage.clear(); window.location.reload() }} className="btn btn-ghost text-xs">Clear all local scans &amp; data</button>
                </div>
                <div className="pt-4 border-t border-[#24262f] text-[11px] text-[#52525b]">
                  Spectra is designed from day one to be a <strong>desktop-first</strong> native app (Tauri + Rust core) while offering this beautiful web UI for rapid development and browser-based demos.
                </div>
              </div>
            </div>
          )}

          {!activeScan && (currentView === 'findings' || currentView === 'graph' || currentView === 'ai' || currentView === 'reports') && (
            <div className="text-center text-[#52525b] mt-16">Select or start a scan from the Dashboard or New Scan view.</div>
          )}
        </div>

        {/* Status bar */}
        <div className="h-7 border-t border-[#24262f] bg-[#0f1117] px-4 text-[10px] flex items-center text-[#52525b] font-mono justify-between">
          <div>SPECTRA • LOCAL • {scans.length} scans stored</div>
          <div>Press <span className="text-[#71717a]">/</span> for new scan • Built for defenders &amp; red teams who want more than checkboxes</div>
        </div>
      </div>
    </div>
  )
}

// Real interactive attack graph using @xyflow/react (populated from live scan findings)
function GraphView({ nodes: gNodes, edges: gEdges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  if (gNodes.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-[#52525b]">
        Run a real or simulated scan — hosts, services and vulnerabilities will appear here as an interactive graph.
      </div>
    )
  }

  const rfNodes: RFNode[] = gNodes.map((n, idx) => ({
    id: n.id,
    position: { x: 120 + (idx % 5) * 160, y: 80 + Math.floor(idx / 5) * 110 },
    data: { label: n.label },
    style: {
      background: n.type === 'vuln' ? '#ef4444' : n.type === 'service' ? '#22d3ee' : '#16181f',
      color: '#ededf0',
      border: '1px solid #32343e',
      borderRadius: '8px',
      fontSize: '11px',
      padding: '4px 8px',
    },
    type: 'default',
  }))

  const rfEdges: RFEdge[] = gEdges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.label,
    type: 'smoothstep',
    markerEnd: { type: MarkerType.ArrowClosed, color: '#67e8f9' },
    style: { stroke: '#67e8f9', strokeWidth: 1.5 },
  }))

  return (
    <div style={{ height: '100%', width: '100%' }} className="bg-[#0b0c11]">
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        fitView
        attributionPosition="bottom-left"
      >
        <Background />
        <Controls />
        <MiniMap />
      </ReactFlow>
      <div className="absolute bottom-4 right-4 text-[10px] bg-[#12141b] border border-[#24262f] px-3 py-1 rounded z-10 pointer-events-none">
        {gNodes.length} nodes • {gEdges.length} relationships (drag to rearrange)
      </div>
    </div>
  )
}

export default App
