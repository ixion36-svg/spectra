import { format } from 'date-fns'
import { type Finding, type Scan, type Severity, SEVERITY_ORDER, SEVERITIES, triageOf, TRIAGE_LABELS } from '../types'

// Standalone HTML executive-summary report. The report embeds scanned-host-
// controlled text (titles, evidence), so every interpolated value is HTML-escaped
// to keep the report itself from becoming an XSS vector when opened in a browser.

export function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

const SEV_COLOR: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#3b82f6',
}

function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) counts[f.severity]++
  return counts
}

export function findingsToHtml(scan: Scan): string {
  const counts = severityCounts(scan.findings)
  const sorted = [...scan.findings].sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || (b.exploitability ?? 0) - (a.exploitability ?? 0),
  )

  const summaryCards = SEVERITIES.map(
    (s) => `<div class="card"><div class="num" style="color:${SEV_COLOR[s]}">${counts[s]}</div><div class="lbl">${s}</div></div>`,
  ).join('')

  const rows = sorted
    .map((f) => {
      const loc = escapeHtml(`${f.asset}${f.port ? ':' + f.port : ''}${f.service ? ' (' + f.service + ')' : ''}`)
      const meta = [
        f.cvss != null ? `CVSS ${escapeHtml(f.cvss)}` : '',
        f.exploitability != null ? `Exploitability ${escapeHtml(f.exploitability)}` : '',
        f.cwe ? escapeHtml(Array.isArray(f.cwe) ? f.cwe.join(', ') : f.cwe) : '',
        f.cve ? escapeHtml(Array.isArray(f.cve) ? f.cve.join(', ') : f.cve) : '',
        f.source ? `src:${escapeHtml(f.source)}` : '',
      ]
        .filter(Boolean)
        .join(' &middot; ')
      return `<article class="finding">
  <div class="fhead">
    <span class="pill" style="background:${SEV_COLOR[f.severity]}">${f.severity}</span>
    <span class="status">${escapeHtml(TRIAGE_LABELS[triageOf(f)])}</span>
    <h3>${escapeHtml(f.title)}</h3>
  </div>
  <div class="loc">${loc}</div>
  ${meta ? `<div class="meta">${meta}</div>` : ''}
  ${f.description ? `<p>${escapeHtml(f.description)}</p>` : ''}
  ${f.evidence ? `<div class="block"><b>Evidence</b><pre>${escapeHtml(f.evidence)}</pre></div>` : ''}
  ${f.recommendation ? `<div class="block"><b>Recommendation</b><p>${escapeHtml(f.recommendation)}</p></div>` : ''}
</article>`
    })
    .join('\n')

  const simulated = scan.findings.some((f) => f.source === 'simulator')

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Spectra Report — ${escapeHtml(scan.name)}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #0b0c11; color: #e5e7eb; }
  .wrap { max-width: 900px; margin: 0 auto; padding: 32px 20px 64px; }
  h1 { font-size: 28px; margin: 0 0 4px; color: #fff; }
  .sub { color: #9ca3af; font-size: 13px; margin-bottom: 8px; }
  .warn { background: #2a1430; border: 1px solid #5b2a6b; color: #e9a8ff; padding: 8px 12px; border-radius: 8px; font-size: 13px; margin: 12px 0; }
  .summary { display: flex; gap: 10px; margin: 20px 0 28px; flex-wrap: wrap; }
  .card { flex: 1; min-width: 90px; background: #16181f; border: 1px solid #24262f; border-radius: 10px; padding: 14px; text-align: center; }
  .num { font-size: 26px; font-weight: 700; }
  .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: #9ca3af; }
  .finding { background: #12141b; border: 1px solid #24262f; border-radius: 10px; padding: 16px; margin-bottom: 14px; }
  .fhead { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .fhead h3 { margin: 0; font-size: 16px; color: #fff; flex-basis: 100%; }
  .pill { color: #0b0c11; font-weight: 700; font-size: 11px; text-transform: uppercase; padding: 2px 8px; border-radius: 999px; }
  .status { font-size: 11px; color: #9ca3af; border: 1px solid #24262f; border-radius: 999px; padding: 1px 8px; }
  .loc { font-family: ui-monospace, monospace; font-size: 12px; color: #9ca3af; margin: 8px 0 4px; }
  .meta { font-size: 12px; color: #67e8f9; margin-bottom: 8px; }
  .block { margin-top: 8px; }
  .block b { font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: #6b7280; display: block; margin-bottom: 2px; }
  pre { white-space: pre-wrap; word-break: break-word; background: #0b0c11; border: 1px solid #24262f; border-radius: 6px; padding: 8px; font-size: 12px; margin: 0; }
  footer { color: #6b7280; font-size: 12px; margin-top: 32px; text-align: center; }
  @media print { body { background: #fff; color: #111; } .finding, .card { background: #fff; border-color: #ddd; } h1, .fhead h3 { color: #111; } }
</style>
</head>
<body>
<div class="wrap">
  <h1>${escapeHtml(scan.name)}</h1>
  <div class="sub">Targets: ${escapeHtml(scan.targets.join(', '))} &middot; Profile: ${escapeHtml(scan.profile)} &middot; ${escapeHtml(format(new Date(scan.startedAt), 'PPpp'))}</div>
  ${simulated ? '<div class="warn">⚠️ This report contains SIMULATED demo findings — illustrative, not real results.</div>' : ''}
  <div class="summary">${summaryCards}</div>
  <h2 style="font-size:18px;color:#fff;">Findings (${scan.findings.length})</h2>
  ${rows || '<p style="color:#9ca3af">No findings.</p>'}
  <footer>Generated by Spectra · ${escapeHtml(format(new Date(scan.startedAt), 'yyyy'))}</footer>
</div>
</body>
</html>`
}
