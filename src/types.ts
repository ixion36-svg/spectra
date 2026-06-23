import { z } from 'zod'

// ── Domain model ────────────────────────────────────────────────────────────
// These types are the contract the Rust core fulfils via invoke()/emit().

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
export const severitySchema = z.enum(SEVERITIES)
export type Severity = (typeof SEVERITIES)[number]

/** Normalise an arbitrary string into a known Severity, defaulting to 'info'. */
export function normalizeSeverity(raw: unknown): Severity {
  const s = String(raw ?? '').toLowerCase()
  return (SEVERITIES as readonly string[]).includes(s) ? (s as Severity) : 'info'
}

export const TRIAGE_STATUSES = ['open', 'confirmed', 'false-positive', 'triaged'] as const
export type TriageStatus = (typeof TRIAGE_STATUSES)[number]

export const TRIAGE_LABELS: Record<TriageStatus, string> = {
  open: 'Open',
  confirmed: 'Confirmed',
  'false-positive': 'False positive',
  triaged: 'Triaged',
}

/** A finding without an explicit triage status is treated as 'open'. */
export function triageOf(f: { status?: TriageStatus }): TriageStatus {
  return f.status ?? 'open'
}

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
  cwe?: unknown
  cve?: unknown
  owasp?: string
  discoveredAt: string
  tags: string[]
  exploitability?: number // 0-100 "beyond normal" score
  source?: string // 'nuclei' | 'trivy' | 'rust-tcp' | 'rust-http' | 'simulator'
  status?: TriageStatus // analyst triage state; defaults to 'open'
}

export type View = 'dashboard' | 'new' | 'findings' | 'graph' | 'ai' | 'reports' | 'settings'

export type ScanStatus = 'running' | 'completed' | 'cancelled'

export interface Scan {
  id: string
  name: string
  targets: string[]
  profile: string
  status: ScanStatus
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
  data?: unknown
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  label?: string
}

// ── Wire schemas (Rust emits `scan-event` with this envelope) ────────────────
// Validated at the IPC boundary so a backend contract change fails loudly
// instead of silently producing `undefined` findings.

export const scanEventSchema = z.object({
  scan_id: z.string(),
  event_type: z.enum(['log', 'finding', 'progress', 'complete', 'error', 'cancelled']),
  data: z.unknown(),
})
export type ScanEvent = z.infer<typeof scanEventSchema>

/** Loose schema for the `finding` payload — every field is optional because
 *  it is emitted by several producers (TCP scanner, nuclei, trivy, http probe). */
export const findingPayloadSchema = z.object({
  source: z.string().optional(),
  title: z.string().optional(),
  severity: z.string().optional(),
  asset: z.string().optional(),
  matched: z.string().optional(),
  host: z.string().optional(),
  port: z.number().optional(),
  service: z.string().optional(),
  evidence: z.string().optional(),
  line: z.string().optional(),
  description: z.string().optional(),
  recommendation: z.string().optional(),
  template: z.string().optional(),
  tags: z.union([z.array(z.string()), z.string()]).optional(),
  exploitability: z.number().optional(),
  cwe: z.unknown().optional(),
  cve: z.unknown().optional(),
})
export type FindingPayload = z.infer<typeof findingPayloadSchema>

export const progressPayloadSchema = z.object({ progress: z.number() }).partial()

export interface ToolStatus {
  name: string
  available: boolean
  path?: string | null
  version?: string | null
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
}
