import { type Finding, type Scan, SEVERITY_ORDER } from '../types'

// Scan-over-scan delta: compare a baseline scan to a current one and classify
// findings as added (new), fixed (gone), or persistent (still present). The
// trend signal every vuln-management workflow needs.

/** Stable identity for "the same finding" across scans. CVE findings key on the
 *  CVE id + asset; everything else on title + asset + port. */
export function findingKey(f: Finding): string {
  const cve = Array.isArray(f.cve) ? f.cve[0] : f.cve
  if (cve) return `cve:${String(cve).toLowerCase()}|${f.asset}`
  return `${f.title}|${f.asset}|${f.port ?? ''}`
}

export interface ScanDelta {
  added: Finding[]
  fixed: Finding[]
  persistent: Finding[]
}

const bySeverity = (a: Finding, b: Finding) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]

function dedupeByKey(findings: Finding[]): Map<string, Finding> {
  const m = new Map<string, Finding>()
  for (const f of findings) {
    const k = findingKey(f)
    if (!m.has(k)) m.set(k, f)
  }
  return m
}

export function diffScans(previous: Scan, current: Scan): ScanDelta {
  const prev = dedupeByKey(previous.findings)
  const curr = dedupeByKey(current.findings)

  const added: Finding[] = []
  const persistent: Finding[] = []
  for (const [k, f] of curr) {
    if (prev.has(k)) persistent.push(f)
    else added.push(f)
  }
  const fixed: Finding[] = []
  for (const [k, f] of prev) {
    if (!curr.has(k)) fixed.push(f)
  }

  return {
    added: added.sort(bySeverity),
    fixed: fixed.sort(bySeverity),
    persistent: persistent.sort(bySeverity),
  }
}

/** Markdown delta report for export. */
export function deltaToMarkdown(previous: Scan, current: Scan, delta: ScanDelta): string {
  const line = (f: Finding) => `- [${f.severity.toUpperCase()}] ${f.title} — ${f.asset}${f.port ? ':' + f.port : ''}`
  let md = `# Spectra Delta Report\n\n`
  md += `**Baseline:** ${previous.name} (${previous.findings.length} findings)\n`
  md += `**Current:** ${current.name} (${current.findings.length} findings)\n\n`
  md += `**New: ${delta.added.length} · Fixed: ${delta.fixed.length} · Still open: ${delta.persistent.length}**\n\n`
  md += `## 🔺 New (${delta.added.length})\n${delta.added.map(line).join('\n') || '_none_'}\n\n`
  md += `## ✅ Fixed (${delta.fixed.length})\n${delta.fixed.map(line).join('\n') || '_none_'}\n\n`
  md += `## ➖ Still open (${delta.persistent.length})\n${delta.persistent.map(line).join('\n') || '_none_'}\n`
  return md
}
