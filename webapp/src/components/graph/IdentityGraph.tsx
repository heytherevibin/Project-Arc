'use client';

import { useMemo, useCallback, useRef } from 'react';
import dynamic from 'next/dynamic';
import { colors } from '@/lib/theme';

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false });

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

export interface IdentityNode {
  id: string;
  label: string;
  type: 'ADUser' | 'ADGroup' | 'ADComputer' | 'AzureUser' | 'AzureApp' | 'AzureRole' | 'GPO' | 'OU' | string;
  enabled?: boolean;
  admin?: boolean;
  kerberoastable?: boolean;
  [key: string]: unknown;
}

export interface IdentityLink {
  source: string;
  target: string;
  type: string;
  label?: string;
}

export interface IdentityGraphProps {
  nodes: IdentityNode[];
  links: IdentityLink[];
  onNodeClick?: (node: IdentityNode) => void;
  selectedNode?: string | null;
  width?: number;
  height?: number;
}

/* ------------------------------------------------------------------ */
/* BloodHound-style colors                                             */
/* ------------------------------------------------------------------ */

const IDENTITY_COLORS: Record<string, string> = {
  ADUser: '#17e563',        // green (BloodHound user color)
  ADGroup: '#dbb800',       // gold
  ADComputer: '#ef233c',    // red
  AzureUser: '#34d058',     // Azure green
  AzureApp: '#6f42c1',      // purple
  AzureRole: '#0366d6',     // blue
  GPO: '#f66a0a',           // orange
  OU: '#959da5',            // grey
};

const LINK_COLORS: Record<string, string> = {
  MemberOf: '#6c757d',
  AdminTo: '#ef233c',
  CanRDPInto: '#ffc107',
  GenericAll: '#dc3545',
  WriteDacl: '#dc3545',
  WriteOwner: '#dc3545',
  HasSPN: '#17a2b8',
  Owns: '#28a745',
};

function identityNodeColor(node: IdentityNode): string {
  if (node.admin) return '#ff0000';
  if (node.kerberoastable) return '#ff6600';
  return IDENTITY_COLORS[node.type] ?? colors.accent.primary;
}

/* ------------------------------------------------------------------ */
/* Component                                                           */
/* ------------------------------------------------------------------ */

export function IdentityGraph({
  nodes,
  links,
  onNodeClick,
  selectedNode,
  width,
  height = 600,
}: IdentityGraphProps) {
  const fgRef = useRef<any>(null);

  const graphData = useMemo(() => ({ nodes, links }), [nodes, links]);

  const handleNodeClick = useCallback(
    (node: any) => {
      onNodeClick?.(node as IdentityNode);
      // Center on node
      if (fgRef.current) {
        fgRef.current.centerAt(node.x, node.y, 800);
        fgRef.current.zoom(3, 800);
      }
    },
    [onNodeClick],
  );

  const nodeCanvasObject = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const n = node as IdentityNode & { x: number; y: number };
      const size = n.admin ? 8 : 6;
      const isSelected = n.id === selectedNode;

      // Draw node circle
      ctx.beginPath();
      ctx.arc(n.x, n.y, size, 0, 2 * Math.PI, false);
      ctx.fillStyle = identityNodeColor(n);
      ctx.fill();

      if (isSelected) {
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      // Label
      if (globalScale > 1.5) {
        const label = n.label || n.id;
        ctx.font = `${Math.max(10 / globalScale, 3)}px monospace`;
        ctx.fillStyle = colors.text.primary;
        ctx.textAlign = 'center';
        ctx.fillText(label, n.x, n.y + size + 8 / globalScale);
      }
    },
    [selectedNode],
  );

  return (
    <ForceGraph2D
      ref={fgRef}
      graphData={graphData}
      width={width}
      height={height}
      backgroundColor={colors.bg.background}
      nodeCanvasObject={nodeCanvasObject}
      linkColor={(link: any) => LINK_COLORS[(link as IdentityLink).type] ?? colors.border.secondary}
      linkDirectionalArrowLength={4}
      linkDirectionalArrowRelPos={1}
      linkWidth={1}
      linkLabel={(link: any) => (link as IdentityLink).type}
      onNodeClick={handleNodeClick}
      enableNodeDrag
    />
  );
}
