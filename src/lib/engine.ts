import type { Finding, Severity } from '../types'

function rid(prefix: string): string {
  return prefix + Math.random().toString(36).slice(2, 11)
}

/** Extract a bare hostname from a raw target (URL, host, or host/path). */
export function hostOf(rawTarget: string): string {
  const target = rawTarget.trim()
  if (target.includes('://')) {
    try {
      return new URL(target).hostname
    } catch {
      /* fall through */
    }
  }
  return target.split('/')[0]
}

const TEMPLATES = [
  { title: 'Outdated OpenSSL - Heartbleed risk', cwe: 'CWE-119', cvss: 7.5, tags: ['network', 'crypto'], rec: 'Upgrade OpenSSL to 1.0.1g+ or latest LTS. Disable affected ciphers.' },
  { title: 'Exposed sensitive .env file', cwe: 'CWE-538', cvss: 7.5, tags: ['web', 'misconfig'], rec: 'Remove .env from web root. Use secrets manager + proper .gitignore.' },
  { title: 'Default credentials on management interface', cwe: 'CWE-798', cvss: 9.8, tags: ['auth', 'default'], rec: 'Change all default passwords. Enforce MFA. Restrict management to VPN.' },
  { title: 'SQL Injection in search parameter', cwe: 'CWE-89', cvss: 8.6, tags: ['web', 'injection'], rec: 'Use parameterized queries / ORM. Apply least privilege to DB account.' },
  { title: 'Missing security headers (CSP, HSTS)', cwe: 'CWE-693', cvss: 5.3, tags: ['web', 'headers'], rec: 'Implement strict Content-Security-Policy and HSTS.' },
  { title: 'SMBv1 enabled - WannaCry exposure', cwe: 'CWE-20', cvss: 8.1, tags: ['smb', 'legacy'], rec: 'Disable SMBv1. Patch systems. Segment legacy hosts.' },
  { title: 'Weak TLS 1.0/1.1 supported', cwe: 'CWE-326', cvss: 6.5, tags: ['crypto', 'network'], rec: 'Disable TLS 1.0 and 1.1. Enforce TLS 1.2+ with modern cipher suites.' },
  { title: 'Kubernetes dashboard exposed without auth', cwe: 'CWE-306', cvss: 9.1, tags: ['k8s', 'cloud'], rec: 'Require authentication + RBAC. Put behind ingress with auth proxy.' },
]

type FindingCb = (f: Finding) => void
type ProgressCb = (p: number) => void
type AssetCb = (asset: string, port?: number, service?: string) => void

/**
 * Browser-only scan SIMULATOR. Produces fabricated, demo-grade findings so the
 * UI can be developed/demoed without a backend. Every finding it emits is tagged
 * `source: 'simulator'` so the UI can clearly mark it as not-real.
 */
export class SpectraEngine {
  private intervals: ReturnType<typeof setInterval>[] = []
  private onFinding: FindingCb
  private onProgress: ProgressCb
  private onAssetDiscovered: AssetCb

  constructor(onFinding: FindingCb, onProgress: ProgressCb, onAssetDiscovered: AssetCb = () => {}) {
    this.onFinding = onFinding
    this.onProgress = onProgress
    this.onAssetDiscovered = onAssetDiscovered
  }

  start(targets: string[], profile: string, scanId: string) {
    this.stop()
    let step = 0
    const tick = () => {
      step++
      const progress = Math.min(99, Math.floor((step / (targets.length * 11)) * 100))
      this.onProgress(progress)

      targets.forEach((rawTarget, tIdx) => {
        const target = rawTarget.trim()
        if (!target) return
        const baseHost = hostOf(target)
        const isWeb = profile.includes('Web') || profile.includes('Deep') || target.includes('http')

        if (step % 3 === 1) {
          const port = isWeb ? (tIdx % 2 === 0 ? 443 : 80) : [22, 445, 3306, 5432, 8080][tIdx % 5]
          const svc = isWeb ? 'https' : ['ssh', 'smb', 'mysql', 'postgres', 'http'][tIdx % 5]
          this.onAssetDiscovered(baseHost, port, svc)
          if (Math.random() > 0.65) this.emitFinding(baseHost, port, svc, scanId, profile)
        }
        if (step % 4 === 2 && Math.random() > 0.4) {
          this.emitFinding(baseHost, undefined, undefined, scanId, profile)
        }
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
    setTimeout(() => {
      if (targets[0]) this.emitFinding(hostOf(targets[0]), 443, 'https', scanId, profile)
    }, 420)
  }

  private emitFinding(host: string, port: number | undefined, service: string | undefined, scanId: string, profile: string) {
    const sevPool: Severity[] = profile.includes('Deep') || profile.includes('AI')
      ? ['critical', 'high', 'high', 'medium', 'medium', 'low']
      : ['high', 'medium', 'medium', 'low', 'info']
    const sev = sevPool[Math.floor(Math.random() * sevPool.length)]
    const t = TEMPLATES[Math.floor(Math.random() * TEMPLATES.length)]

    this.onFinding({
      id: rid('f_'),
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
      owasp: ['A01:2021', 'A03:2021', 'A05:2021', 'A06:2021'][Math.floor(Math.random() * 4)],
      discoveredAt: new Date().toISOString(),
      tags: t.tags,
      exploitability: Math.floor(45 + Math.random() * 55),
      source: 'simulator',
    })
  }

  private emitCorrelatedFinding(host: string, scanId: string) {
    this.onFinding({
      id: rid('f_'),
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
      source: 'simulator',
    })
  }

  stop() {
    this.intervals.forEach(clearInterval)
    this.intervals = []
  }
}
