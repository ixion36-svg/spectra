import { Command } from 'cmdk'
import { BarChart3, Plus, Search, GitBranch, Bot, FileText, Settings, Play } from 'lucide-react'
import type { ComponentType } from 'react'
import type { View } from '../types'

interface Action {
  id: string
  label: string
  icon: ComponentType<{ size?: number }>
  run: () => void
}

export function CommandPalette({
  open,
  onOpenChange,
  onNavigate,
  onNewScan,
}: {
  open: boolean
  onOpenChange: (v: boolean) => void
  onNavigate: (v: View) => void
  onNewScan: () => void
}) {
  const go = (v: View) => () => {
    onNavigate(v)
    onOpenChange(false)
  }

  const actions: Action[] = [
    { id: 'new', label: 'New Scan', icon: Plus, run: go('new') },
    { id: 'launch', label: 'Launch scan now', icon: Play, run: () => { onNewScan(); onOpenChange(false) } },
    { id: 'dashboard', label: 'Go to Dashboard', icon: BarChart3, run: go('dashboard') },
    { id: 'findings', label: 'Go to Findings', icon: Search, run: go('findings') },
    { id: 'graph', label: 'Go to Attack Graph', icon: GitBranch, run: go('graph') },
    { id: 'ai', label: 'Go to AI Co-pilot', icon: Bot, run: go('ai') },
    { id: 'reports', label: 'Go to Reports', icon: FileText, run: go('reports') },
    { id: 'settings', label: 'Go to Settings', icon: Settings, run: go('settings') },
  ]

  return (
    <Command.Dialog open={open} onOpenChange={onOpenChange} label="Command palette" className="cmdk-dialog">
      <Command.Input placeholder="Type a command or search…" className="cmdk-input" />
      <Command.List className="cmdk-list">
        <Command.Empty className="cmdk-empty">No results found.</Command.Empty>
        <Command.Group heading="Actions">
          {actions.map((a) => {
            const Icon = a.icon
            return (
              <Command.Item key={a.id} value={a.label} onSelect={a.run} className="cmdk-item">
                <Icon size={15} /> {a.label}
              </Command.Item>
            )
          })}
        </Command.Group>
      </Command.List>
    </Command.Dialog>
  )
}
