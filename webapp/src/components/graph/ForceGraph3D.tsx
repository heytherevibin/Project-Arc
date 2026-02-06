'use client';

import { useRef, useCallback, useEffect, useMemo } from 'react';
import dynamic from 'next/dynamic';
import { colors } from '@/lib/theme';

const ForceGraph3DLib = dynamic(() => import('react-force-graph-3d'), { ssr: false });

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  group?: string;
  color?: string;
  [key: string]: unknown;
}

export interface GraphLink {
  source: string;
  target: string;
  label?: string;
  type?: string;
  color?: string;
}

export interface ForceGraph3DProps {
  nodes: GraphNode[];
  links: GraphLink[];
  onNodeClick?: (node: GraphNode) => void;
  selectedNode?: string | null;
  width?: number;
  height?: number;
  backgroundColor?: string;
}

/* ------------------------------------------------------------------ */
/* Color helpers                                                       */
/* ------------------------------------------------------------------ */

const NODE_COLORS: Record<string, string> = {
  Host: colors.accent.primary,
  IP: colors.accent.primary,
  Vulnerability: colors.severity.critical,
  Credential: colors.severity.high,
  ADUser: colors.accent.secondary,
  ADGroup: colors.status.warning,
  ADComputer: colors.accent.primary,
  Service: colors.status.info,
  Port: colors.text.muted,
};

function nodeColor(node: GraphNode): string {
  return node.color ?? NODE_COLORS[node.type] ?? colors.accent.primary;
}

/* ------------------------------------------------------------------ */
/* Component                                                           */
/* ------------------------------------------------------------------ */

export function ForceGraph3D({
  nodes,
  links,
  onNodeClick,
  selectedNode,
  width,
  height = 600,
  backgroundColor = colors.bg.background,
}: ForceGraph3DProps) {
  const fgRef = useRef<any>(null);

  const graphData = useMemo(() => ({ nodes, links }), [nodes, links]);

  const handleNodeClick = useCallback(
    (node: any) => {
      onNodeClick?.(node as GraphNode);
      // Fly camera to the clicked node
      if (fgRef.current) {
        const distance = 120;
        const distRatio = 1 + distance / Math.hypot(node.x || 0, node.y || 0, node.z || 0);
        fgRef.current.cameraPosition(
          { x: (node.x || 0) * distRatio, y: (node.y || 0) * distRatio, z: (node.z || 0) * distRatio },
          node,
          1500,
        );
      }
    },
    [onNodeClick],
  );

  return (
    <ForceGraph3DLib
      ref={fgRef}
      graphData={graphData}
      width={width}
      height={height}
      backgroundColor={backgroundColor}
      nodeLabel={(node: any) => `${(node as GraphNode).type}: ${(node as GraphNode).label}`}
      nodeColor={(node: any) => {
        const n = node as GraphNode;
        return n.id === selectedNode ? '#ffffff' : nodeColor(n);
      }}
      nodeRelSize={6}
      nodeOpacity={0.9}
      linkColor={() => colors.border.secondary}
      linkOpacity={0.3}
      linkWidth={1}
      linkDirectionalArrowLength={3.5}
      linkDirectionalArrowRelPos={1}
      onNodeClick={handleNodeClick}
      enableNodeDrag
      enableNavigationControls
    />
  );
}
