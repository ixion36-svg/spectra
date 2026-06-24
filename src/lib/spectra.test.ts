import { describe, it, expect } from 'vitest'
import { csvCell, findingsToCsv } from './export'
import { hostOf } from './engine'
import { findingsToSarif, sarifRuleId } from './sarif'
import { findingsToHtml, escapeHtml } from './html'
import { dedupeFindings } from './dedup'
import { normalizeSeverity, findingPayloadSchema } from '../types'
import type { Finding, Scan } from '../types'

describe('csvCell — formula injection guard', () => {
  it('quotes and escapes normal values', () => {
    expect(csvCell('hello')).toBe('"hello"')
    expect(csvCell('a "quoted" b')).toBe('"a ""quoted"" b"')
  })

  it('neutralises formula-leading characters', () => {
    expect(csvCell('=1+1')).toBe('"\'=1+1"')
    expect(csvCell('+SUM(A1)')).toBe('"\'+SUM(A1)"')
    expect(csvCell('-2')).toBe('"\'-2"')
    expect(csvCell('@cmd')).toBe('"\'@cmd"')
  })

  it('handles null/undefined/number', () => {
    expect(csvCell(null)).toBe('""')
    expect(csvCell(undefined)).toBe('""')
    expect(csvCell(7.5)).toBe('"7.5"')
  })
})

describe('findingsToCsv', () => {
  it('emits a header and one row per finding with injection-safe title', () => {
    const f: Finding = {
      id: '1', scanId: 's', severity: 'high', title: '=HYPERLINK("evil")',
      asset: 'h', evidence: '', description: '', recommendation: 'fix', discoveredAt: '', tags: [],
    }
    const csv = findingsToCsv([f])
    const [header, row] = csv.split('\n')
    expect(header.startsWith('severity,title,asset')).toBe(true)
    expect(row).toContain('"\'=HYPERLINK(""evil"")"')
  })
})

describe('dedupeFindings', () => {
  const mk = (over: Partial<Finding>): Finding => ({
    id: Math.random().toString(), scanId: 's', severity: 'low', title: 'X', asset: 'h',
    evidence: '', description: '', recommendation: '', discoveredAt: '', tags: [], ...over,
  })

  it('collapses identical findings at the same location and counts them', () => {
    const out = dedupeFindings([mk({}), mk({}), mk({})])
    expect(out).toHaveLength(1)
    expect(out[0].duplicates).toBe(2) // 3 total → 1 shown + 2 folded
  })

  it('keeps the higher-signal representative (severity, then exploitability)', () => {
    const out = dedupeFindings([
      mk({ severity: 'low', exploitability: 10 }),
      mk({ severity: 'critical', exploitability: 90 }),
    ])
    expect(out).toHaveLength(1)
    expect(out[0].severity).toBe('critical')
  })

  it('does not merge findings at different locations', () => {
    const out = dedupeFindings([mk({ asset: 'a' }), mk({ asset: 'b' }), mk({ title: 'Y', asset: 'a' })])
    expect(out).toHaveLength(3)
    expect(out.every((f) => f.duplicates === undefined)).toBe(true)
  })

  it('treats different ports as different locations', () => {
    const out = dedupeFindings([mk({ port: 80 }), mk({ port: 443 })])
    expect(out).toHaveLength(2)
  })
})

describe('hostOf (simulator host extraction)', () => {
  it('extracts hostname from a URL (not "https:")', () => {
    expect(hostOf('https://example.com')).toBe('example.com')
    expect(hostOf('https://example.com/path?q=1')).toBe('example.com')
    expect(hostOf('http://10.10.14.7:8080/x')).toBe('10.10.14.7')
  })
  it('passes through bare hosts and host/path', () => {
    expect(hostOf('10.10.14.7')).toBe('10.10.14.7')
    expect(hostOf('example.com/app')).toBe('example.com')
    expect(hostOf('  example.com  ')).toBe('example.com')
  })
})

describe('normalizeSeverity', () => {
  it('passes through known severities (case-insensitive)', () => {
    expect(normalizeSeverity('Critical')).toBe('critical')
    expect(normalizeSeverity('HIGH')).toBe('high')
  })
  it('defaults unknown/empty to info', () => {
    expect(normalizeSeverity('bogus')).toBe('info')
    expect(normalizeSeverity(undefined)).toBe('info')
    expect(normalizeSeverity(null)).toBe('info')
  })
})

describe('SARIF export', () => {
  type SarifDoc = {
    version: string
    runs: { tool: { driver: { name: string; rules: unknown[] } }; results: { level: string }[] }[]
  }
  const toDoc = (s: Scan) => findingsToSarif(s) as unknown as SarifDoc
  const mk = (over: Partial<Finding>): Finding => ({
    id: '1', scanId: 's', severity: 'high', title: 'SQL Injection', asset: 'https://t.example/x',
    evidence: 'payload', description: 'desc', recommendation: 'parameterize', discoveredAt: '', tags: ['web'], ...over,
  })
  const scan = (findings: Finding[]): Scan => ({
    id: 's', name: 'Test scan', targets: ['t'], profile: 'Web', status: 'completed', startedAt: '2026-01-01T00:00:00Z', findings, progress: 100,
  })

  it('produces a valid 2.1.0 envelope with Spectra as the driver', () => {
    const doc = toDoc(scan([mk({})]))
    expect(doc.version).toBe('2.1.0')
    expect(doc.runs[0].tool.driver.name).toBe('Spectra')
    expect(doc.runs[0].results).toHaveLength(1)
  })

  it('maps severity to SARIF level', () => {
    const doc = toDoc(scan([mk({ severity: 'critical' }), mk({ id: '2', severity: 'low' }), mk({ id: '3', severity: 'medium' })]))
    const levels = doc.runs[0].results.map((r) => r.level)
    expect(levels).toEqual(['error', 'note', 'warning'])
  })

  it('derives a stable ruleId (CVE > CWE > slug)', () => {
    expect(sarifRuleId(mk({ cve: ['CVE-2021-1'], cwe: ['CWE-89'] }))).toBe('CVE-2021-1')
    expect(sarifRuleId(mk({ cve: undefined, cwe: 'CWE-89' }))).toBe('CWE-89')
    expect(sarifRuleId(mk({ cve: undefined, cwe: undefined, source: 'nuclei' }))).toBe('nuclei/sql-injection')
  })

  it('dedups rules across findings with the same ruleId', () => {
    const doc = toDoc(scan([mk({ cwe: 'CWE-89' }), mk({ id: '2', cwe: 'CWE-89' })]))
    expect(doc.runs[0].tool.driver.rules).toHaveLength(1)
    expect(doc.runs[0].results).toHaveLength(2)
  })
})

describe('HTML report', () => {
  const mk = (over: Partial<Finding>): Finding => ({
    id: '1', scanId: 's', severity: 'high', title: 'SQLi', asset: 'h',
    evidence: 'e', description: 'd', recommendation: 'r', discoveredAt: '', tags: [], ...over,
  })
  const scan = (findings: Finding[]): Scan => ({
    id: 's', name: 'Test', targets: ['t'], profile: 'Web', status: 'completed', startedAt: '2026-01-01T00:00:00Z', findings, progress: 100,
  })

  it('escapeHtml neutralises HTML metacharacters', () => {
    expect(escapeHtml('<script>alert(1)</script>')).toBe('&lt;script&gt;alert(1)&lt;/script&gt;')
    expect(escapeHtml('a & "b" \'c\'')).toBe('a &amp; &quot;b&quot; &#39;c&#39;')
  })

  it('produces a full HTML document with a summary and the finding count', () => {
    const html = findingsToHtml(scan([mk({}), mk({ id: '2', severity: 'critical' })]))
    expect(html.startsWith('<!doctype html>')).toBe(true)
    expect(html).toContain('Findings (2)')
  })

  it('escapes attacker-influenced finding fields (no XSS in the report)', () => {
    const html = findingsToHtml(scan([mk({ title: '<img src=x onerror=alert(1)>', evidence: '</pre><script>evil()</script>' })]))
    expect(html).not.toContain('<img src=x onerror=alert(1)>')
    expect(html).not.toContain('<script>evil()</script>')
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;')
  })
})

describe('findingPayloadSchema', () => {
  it('accepts a partial payload from the TCP scanner', () => {
    const r = findingPayloadSchema.safeParse({ source: 'rust-tcp', port: 443, service: 'https' })
    expect(r.success).toBe(true)
  })
  it('accepts tags as string or array', () => {
    expect(findingPayloadSchema.safeParse({ tags: 'web' }).success).toBe(true)
    expect(findingPayloadSchema.safeParse({ tags: ['web', 'tls'] }).success).toBe(true)
  })
  it('rejects a wrong-typed field', () => {
    expect(findingPayloadSchema.safeParse({ port: 'not-a-number' }).success).toBe(false)
  })
})
