import { type Finding, type Scan, type Severity, triageOf } from '../types'

// SARIF 2.1.0 export. Lets Spectra results flow into DefectDojo, GitHub code
// scanning, and other SARIF consumers. Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
}

function first(v: unknown): string | undefined {
  if (Array.isArray(v)) return v.length ? String(v[0]) : undefined
  if (v == null || v === '') return undefined
  return String(v)
}

/** Stable rule id: prefer CVE, then CWE, else a slug of source + title. */
export function sarifRuleId(f: Finding): string {
  return (
    first(f.cve) ??
    first(f.cwe) ??
    `${f.source || 'spectra'}/${f.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48)}`
  )
}

function locationUri(f: Finding): string {
  if (/^[a-z]+:\/\//i.test(f.asset)) return f.asset // already a URL
  return f.port ? `${f.service || 'tcp'}://${f.asset}:${f.port}` : f.asset
}

export function findingsToSarif(scan: Scan): object {
  const rules = new Map<string, object>()

  const results = scan.findings.map((f) => {
    const ruleId = sarifRuleId(f)
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: f.title,
        shortDescription: { text: f.title },
        ...(f.recommendation ? { help: { text: f.recommendation } } : {}),
        properties: {
          ...(f.cwe ? { cwe: f.cwe } : {}),
          ...(f.cve ? { cve: f.cve } : {}),
          tags: f.tags,
        },
      })
    }
    return {
      ruleId,
      level: LEVEL[f.severity],
      message: { text: f.description || f.title },
      locations: [{ physicalLocation: { artifactLocation: { uri: locationUri(f) } } }],
      properties: {
        severity: f.severity,
        ...(f.cvss != null ? { 'security-severity': String(f.cvss) } : {}),
        ...(f.exploitability != null ? { exploitability: f.exploitability } : {}),
        status: triageOf(f),
        source: f.source ?? 'unknown',
        evidence: f.evidence,
        recommendation: f.recommendation,
      },
    }
  })

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Spectra',
            informationUri: 'https://github.com/ixion36-svg/spectra',
            version: '0.1.0',
            rules: Array.from(rules.values()),
          },
        },
        properties: {
          scanName: scan.name,
          targets: scan.targets,
          profile: scan.profile,
          startedAt: scan.startedAt,
        },
        results,
      },
    ],
  }
}
