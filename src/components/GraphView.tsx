import { ReactFlow, Background, Controls, MiniMap, type Node as RFNode, type Edge as RFEdge, MarkerType } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import type { GraphNode, GraphEdge } from '../types'

// Live interactive attack graph populated from scan findings.
export function GraphView({ nodes: gNodes, edges: gEdges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
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
    <div style={{ height: '100%', width: '100%' }} className="bg-[#0b0c11] relative">
      <ReactFlow nodes={rfNodes} edges={rfEdges} fitView attributionPosition="bottom-left">
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
