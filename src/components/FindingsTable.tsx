import { useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { format } from 'date-fns'
import { type Finding, type Severity, type TriageStatus, TRIAGE_LABELS, triageOf } from '../types'

const ROW_HEIGHT = 41

export function SeverityBadge({ sev }: { sev: Severity }) {
  return <span className={`badge sev-${sev}`}>{sev}</span>
}

export function StatusPill({ status }: { status: TriageStatus }) {
  return <span className={`status-pill status-${status}`}>{TRIAGE_LABELS[status]}</span>
}

// Virtualized findings list — only the visible rows are mounted, so a scan with
// tens of thousands of findings stays smooth. Layout is a CSS grid so rows align
// without the measurement pitfalls of virtualizing a native <table>.
const GRID = 'grid items-center gap-3 px-3'
const COLS = 'minmax(90px,0.6fr) minmax(170px,2fr) minmax(110px,1.2fr) 90px 52px 64px 110px 96px'

export function FindingsTable({
  findings,
  onSelect,
}: {
  findings: Finding[]
  onSelect: (f: Finding) => void
}) {
  const parentRef = useRef<HTMLDivElement>(null)
  const rowVirtualizer = useVirtualizer({
    count: findings.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  })

  return (
    <div className="table-container bg-[#16181f]">
      {/* Header */}
      <div
        className={`${GRID} h-10 text-[10px] uppercase tracking-wider text-[#71717a] border-b border-[#24262f] sticky top-0 bg-[#16181f] z-10`}
        style={{ gridTemplateColumns: COLS }}
      >
        <div>Severity</div>
        <div>Title</div>
        <div>Asset</div>
        <div>Port / Service</div>
        <div>CVSS</div>
        <div>Exploit %</div>
        <div>Status</div>
        <div>Discovered</div>
      </div>

      {findings.length === 0 ? (
        <div className="p-8 text-center text-[#52525b]">No findings match current filters.</div>
      ) : (
        <div ref={parentRef} className="overflow-auto" style={{ maxHeight: 'calc(100vh - 320px)' }}>
          <div style={{ height: rowVirtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
            {rowVirtualizer.getVirtualItems().map((vi) => {
              const f = findings[vi.index]
              return (
                <div
                  key={f.id}
                  onClick={() => onSelect(f)}
                  className={`${GRID} cursor-pointer border-b border-[#1c1e26] hover:bg-[#1c1e26] text-sm`}
                  style={{
                    gridTemplateColumns: COLS,
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    height: ROW_HEIGHT,
                    transform: `translateY(${vi.start}px)`,
                  }}
                >
                  <div><SeverityBadge sev={f.severity} /></div>
                  <div className="font-medium text-white truncate" title={f.title}>{f.title}</div>
                  <div className="font-mono text-xs text-[#ededf0] truncate" title={f.asset}>{f.asset}</div>
                  <div className="font-mono text-xs">
                    {f.port || '—'} {f.service && <span className="text-[#52525b]">/ {f.service}</span>}
                  </div>
                  <div className="text-xs">{f.cvss ? f.cvss.toFixed(1) : '—'}</div>
                  <div>
                    {f.exploitability != null && (
                      <span className="font-mono text-xs px-2 py-px rounded" style={{ background: 'rgba(34,211,238,0.1)', color: 'var(--accent)' }}>
                        {f.exploitability}
                      </span>
                    )}
                  </div>
                  <div><StatusPill status={triageOf(f)} /></div>
                  <div className="text-xs text-[#52525b] font-mono">{format(new Date(f.discoveredAt), 'HH:mm:ss')}</div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
