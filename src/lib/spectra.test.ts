import { describe, it, expect } from 'vitest'
import { csvCell, findingsToCsv } from './export'
import { normalizeSeverity, findingPayloadSchema } from '../types'
import type { Finding } from '../types'

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
