'use client';

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import dynamic from 'next/dynamic';
import {
  Select,
  Space,
  Typography,
  Spin,
  Empty,
  Drawer,
  Descriptions,
  Tag,
  Row,
  Col,
  Button,
  Slider,
  Checkbox,
  Segmented,
  Tooltip,
  List,
  Progress,
} from 'antd';
import type { CheckboxChangeEvent } from 'antd/es/checkbox';
import {
  ReloadOutlined,
  FullscreenOutlined,
  FullscreenExitOutlined,
  AimOutlined,
  PlayCircleOutlined,
  PauseCircleOutlined,
  StepForwardOutlined,
  NodeIndexOutlined,
} from '@ant-design/icons';
import useSWR from 'swr';
import { api } from '@/lib/api';
import { useAppStore } from '@/store/provider';
import { colors, getSeverityColor } from '@/lib/theme';
import { C2Panel, DataReadout } from '@/components/c2';
import type { Project, AttackPath, AttackPathNode } from '@/types';

const { Title, Text } = Typography;

// Dynamic imports for force graph (avoid SSR)
const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), {
  ssr: false,
  loading: () => (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
      <Spin size="large" />
    </div>
  ),
});

const ForceGraph3D = dynamic(() => import('react-force-graph-3d'), {
  ssr: false,
  loading: () => (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
      <Spin size="large" />
    </div>
  ),
});

interface GraphNode {
  id: string;
  label: string;
  type: string;
  properties: Record<string, unknown>;
  severity?: string;
  group?: string;
  x?: number;
  y?: number;
  z?: number;
  // attack path animation state
  __animActive?: boolean;
  __animVisited?: boolean;
}

interface GraphEdge {
  source: string;
  target: string;
  type: string;
}

interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  node_count: number;
  edge_count: number;
}

interface GraphStats {
  total_nodes: number;
  total_edges: number;
  node_types: Record<string, number>;
  edge_types: Record<string, number>;
}

// Color mapping for node types
const nodeTypeColors: Record<string, string> = {
  Domain: '#4096ff',
  Subdomain: '#36cfc9',
  IP: '#73d13d',
  Port: '#ff7a45',
  Service: '#ffc53d',
  URL: '#9254de',
  Endpoint: '#ff85c0',
  Technology: '#597ef7',
  Vulnerability: '#f5222d',
  CVE: '#fa541c',
  Host: '#73d13d',
  Credential: '#faad14',
  AttackNode: '#cc3333',
};

type ViewMode = '2D' | '3D';

/**
 * Attack Surface Graph Visualization — 2D/3D toggle + Attack Path Animator
 */
export default function GraphPage() {
  const currentProject = useAppStore((state) => state.currentProject);
  const [selectedProject, setSelectedProject] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [nodeLimit, setNodeLimit] = useState(300);
  const [fullscreen, setFullscreen] = useState(false);
  const [viewMode, setViewMode] = useState<ViewMode>('3D');
  const [visibleTypes, setVisibleTypes] = useState<Set<string>>(
    new Set(['Domain', 'Subdomain', 'IP', 'Port', 'URL', 'Vulnerability', 'Host', 'AttackNode'])
  );

  // Attack path animation state
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null);
  const [animStep, setAnimStep] = useState(-1);
  const [animPlaying, setAnimPlaying] = useState(false);
  const animTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [showPathPanel, setShowPathPanel] = useState(false);

  const graphRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [graphSize, setGraphSize] = useState({ width: 800, height: 500 });

  // Responsive graph dimensions
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0]?.contentRect ?? {};
      if (width != null && height != null && width > 0 && height > 0) {
        setGraphSize({ width: Math.floor(width), height: Math.floor(height) });
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Fetch projects
  const { data: projectsData } = useSWR<{ items: Project[] }>(
    '/api/v1/projects',
    api.get.bind(api)
  );

  const projectId = selectedProject || currentProject?.project_id;

  // Fetch graph data
  const { data: graphData, isLoading: graphLoading, mutate: mutateGraph } = useSWR<GraphData>(
    projectId ? `/api/v1/graph/data?project_id=${projectId}&limit=${nodeLimit}` : null,
    api.get.bind(api)
  );

  // Fetch graph stats
  const { data: graphStats } = useSWR<GraphStats>(
    projectId ? `/api/v1/graph/stats?project_id=${projectId}` : null,
    api.get.bind(api)
  );

  // Fetch attack paths
  const { data: attackPaths } = useSWR<AttackPath[]>(
    projectId ? `/api/v1/intelligence/attack-paths?project_id=${projectId}` : null,
    api.get.bind(api),
    { fallbackData: [] }
  );

  // ── Attack path animation ──────────────────────────────────────────

  const pathNodeIds = useMemo(() => {
    if (!selectedPath) return new Set<string>();
    return new Set(selectedPath.nodes.map((n) => n.id));
  }, [selectedPath]);

  const visitedNodeIds = useMemo(() => {
    if (!selectedPath || animStep < 0) return new Set<string>();
    return new Set(selectedPath.nodes.slice(0, animStep + 1).map((n) => n.id));
  }, [selectedPath, animStep]);

  const activeNodeId = useMemo(() => {
    if (!selectedPath || animStep < 0) return null;
    return selectedPath.nodes[animStep]?.id ?? null;
  }, [selectedPath, animStep]);

  const startAnimation = useCallback(() => {
    if (!selectedPath) return;
    setAnimStep(0);
    setAnimPlaying(true);
  }, [selectedPath]);

  const stopAnimation = useCallback(() => {
    setAnimPlaying(false);
    if (animTimerRef.current) {
      clearInterval(animTimerRef.current);
      animTimerRef.current = null;
    }
  }, []);

  const stepForward = useCallback(() => {
    if (!selectedPath) return;
    setAnimStep((prev) => Math.min(prev + 1, selectedPath.nodes.length - 1));
  }, [selectedPath]);

  const resetAnimation = useCallback(() => {
    stopAnimation();
    setAnimStep(-1);
  }, [stopAnimation]);

  // Auto-advance animation
  useEffect(() => {
    if (!animPlaying || !selectedPath) return;
    animTimerRef.current = setInterval(() => {
      setAnimStep((prev) => {
        if (prev >= selectedPath.nodes.length - 1) {
          setAnimPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 1200);
    return () => {
      if (animTimerRef.current) clearInterval(animTimerRef.current);
    };
  }, [animPlaying, selectedPath]);

  // ── Process graph data ─────────────────────────────────────────────

  const processedData = useMemo(() => {
    if (!graphData) return { nodes: [], links: [] };

    const filteredNodes = graphData.nodes.filter((node) => visibleTypes.has(node.type));
    const nodeIds = new Set(filteredNodes.map((n) => n.id));

    const nodes = filteredNodes.map((node) => ({
      ...node,
      __animActive: activeNodeId === node.id,
      __animVisited: visitedNodeIds.has(node.id),
    }));

    const links = graphData.edges
      .filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target))
      .map((edge) => ({
        source: edge.source,
        target: edge.target,
        type: edge.type,
      }));

    return { nodes, links };
  }, [graphData, visibleTypes, activeNodeId, visitedNodeIds]);

  // ── Callbacks ──────────────────────────────────────────────────────

  const handleNodeClick = useCallback((node: unknown) => {
    setSelectedNode(node as GraphNode);
    setDrawerOpen(true);
  }, []);

  const handleBackgroundClick = useCallback(() => {
    setSelectedNode(null);
    setDrawerOpen(false);
  }, []);

  // 2D canvas node renderer
  const nodeCanvasObject = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const label = String(node.label || node.type || '');
      const baseFontSize = label.length > 28 ? 9 : label.length > 20 ? 10 : 12;
      const fontSize = Math.max(8, baseFontSize / globalScale);
      ctx.font = `${fontSize}px ${'JetBrains Mono, ui-monospace, monospace'}`;

      const isOnPath = pathNodeIds.has(node.id);
      const isVisited = node.__animVisited;
      const isActive = node.__animActive;

      let nodeColor = node.severity
        ? getSeverityColor(node.severity)
        : nodeTypeColors[node.type] || colors.text.muted;

      let size = node.type === 'Vulnerability' ? 6 : 4;

      // Attack path highlighting
      if (selectedPath) {
        if (isActive) {
          nodeColor = '#ff4444';
          size = 10;
          // Glow effect
          ctx.shadowColor = '#ff4444';
          ctx.shadowBlur = 20;
        } else if (isVisited) {
          nodeColor = '#ff8800';
          size = 7;
          ctx.shadowColor = '#ff8800';
          ctx.shadowBlur = 10;
        } else if (isOnPath) {
          nodeColor = '#666666';
          size = 5;
        } else {
          // Dim non-path nodes
          nodeColor = '#1a1a1a';
          size = 2;
        }
      }

      ctx.beginPath();
      ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
      ctx.fillStyle = nodeColor;
      ctx.fill();
      ctx.shadowColor = 'transparent';
      ctx.shadowBlur = 0;

      if (selectedNode?.id === node.id || isActive) {
        ctx.strokeStyle = isActive ? '#ff4444' : colors.accent.primary;
        ctx.lineWidth = 2 / globalScale;
        ctx.stroke();
      }

      // Labels (only for path nodes when path is active, otherwise all)
      if (!selectedPath || isOnPath || isActive) {
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = isActive ? '#ffffff' : isVisited ? '#ffcc88' : colors.text.secondary;
        ctx.fillText(label, node.x, node.y + size + fontSize + 2);
      }
    },
    [selectedNode, selectedPath, pathNodeIds]
  );

  // 2D link renderer
  const linkCanvasObject = useCallback(
    (link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
      const targetId = typeof link.target === 'object' ? link.target.id : link.target;
      const start = typeof link.source === 'object' ? link.source : { x: 0, y: 0 };
      const end = typeof link.target === 'object' ? link.target : { x: 0, y: 0 };

      const isPathEdge =
        selectedPath && pathNodeIds.has(sourceId) && pathNodeIds.has(targetId);
      const isVisitedEdge =
        isPathEdge && visitedNodeIds.has(sourceId) && visitedNodeIds.has(targetId);

      ctx.beginPath();
      ctx.moveTo(start.x, start.y);
      ctx.lineTo(end.x, end.y);

      if (selectedPath) {
        if (isVisitedEdge) {
          ctx.strokeStyle = '#ff8800';
          ctx.lineWidth = 2 / globalScale;
          ctx.shadowColor = '#ff8800';
          ctx.shadowBlur = 8;
        } else if (isPathEdge) {
          ctx.strokeStyle = '#444444';
          ctx.lineWidth = 1 / globalScale;
        } else {
          ctx.strokeStyle = '#0d0d0d';
          ctx.lineWidth = 0.3 / globalScale;
        }
      } else {
        ctx.strokeStyle = colors.border.primary;
        ctx.lineWidth = 0.5 / globalScale;
      }

      ctx.stroke();
      ctx.shadowColor = 'transparent';
      ctx.shadowBlur = 0;
    },
    [selectedPath, pathNodeIds, visitedNodeIds]
  );

  // 3D node color
  const getNodeColor = useCallback(
    (node: any) => {
      if (selectedPath) {
        if (node.__animActive) return '#ff4444';
        if (node.__animVisited) return '#ff8800';
        if (pathNodeIds.has(node.id)) return '#555555';
        return '#1a1a1a';
      }
      if (node.severity) return getSeverityColor(node.severity);
      return nodeTypeColors[node.type] || colors.text.muted;
    },
    [selectedPath, pathNodeIds]
  );

  // 3D node size
  const getNodeVal = useCallback(
    (node: any) => {
      if (selectedPath) {
        if (node.__animActive) return 8;
        if (node.__animVisited) return 5;
        if (pathNodeIds.has(node.id)) return 3;
        return 0.5;
      }
      return node.type === 'Vulnerability' ? 4 : 2;
    },
    [selectedPath, pathNodeIds]
  );

  // 3D link color
  const getLinkColor = useCallback(
    (link: any) => {
      if (!selectedPath) return 'rgba(38,38,38,0.6)';
      const sid = typeof link.source === 'object' ? link.source.id : link.source;
      const tid = typeof link.target === 'object' ? link.target.id : link.target;
      if (visitedNodeIds.has(sid) && visitedNodeIds.has(tid)) return '#ff8800';
      if (pathNodeIds.has(sid) && pathNodeIds.has(tid)) return '#333333';
      return 'rgba(13,13,13,0.3)';
    },
    [selectedPath, pathNodeIds, visitedNodeIds]
  );

  const getLinkWidth = useCallback(
    (link: any) => {
      if (!selectedPath) return 0.5;
      const sid = typeof link.source === 'object' ? link.source.id : link.source;
      const tid = typeof link.target === 'object' ? link.target.id : link.target;
      if (visitedNodeIds.has(sid) && visitedNodeIds.has(tid)) return 3;
      if (pathNodeIds.has(sid) && pathNodeIds.has(tid)) return 1;
      return 0.2;
    },
    [selectedPath, pathNodeIds, visitedNodeIds]
  );

  // 3D node label
  const getNodeLabel = useCallback(
    (node: any) => {
      const label = node.label || node.type || '';
      if (selectedPath && node.__animActive) {
        const stepIdx = selectedPath.nodes.findIndex((n: AttackPathNode) => n.id === node.id);
        const tech = selectedPath.edges[stepIdx - 1]?.technique || '';
        return `<div class="graph3d-tooltip graph3d-tooltip--active">
          <div class="graph3d-tooltip__title">${label}</div>
          <div class="graph3d-tooltip__type">${node.type}</div>
          ${tech ? `<div class="graph3d-tooltip__technique">${tech}</div>` : ''}
          <div class="graph3d-tooltip__step">Step ${stepIdx + 1} of ${selectedPath.nodes.length}</div>
        </div>`;
      }
      return `<div class="graph3d-tooltip">
        <div class="graph3d-tooltip__title">${label}</div>
        <div class="graph3d-tooltip__type">${node.type}</div>
      </div>`;
    },
    [selectedPath]
  );

  // Sync fullscreen state with browser
  useEffect(() => {
    const handler = () => setFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);

  const toggleFullscreen = useCallback(() => {
    if (!containerRef.current) return;
    if (!fullscreen) {
      containerRef.current.requestFullscreen?.();
    } else {
      document.exitFullscreen?.();
    }
  }, [fullscreen]);

  // Handle type visibility toggle
  const handleTypeToggle = (type: string) => (e: CheckboxChangeEvent) => {
    const newTypes = new Set(visibleTypes);
    if (e.target.checked) {
      newTypes.add(type);
    } else {
      newTypes.delete(type);
    }
    setVisibleTypes(newTypes);
  };

  // Available node types from data
  const availableTypes = useMemo(() => {
    if (!graphData) return [];
    return [...new Set(graphData.nodes.map((n) => n.type))].sort();
  }, [graphData]);

  // Center camera on path
  const focusOnPath = useCallback(() => {
    if (!selectedPath || !graphRef.current) return;
    const firstNode = processedData.nodes.find((n) => n.id === selectedPath.nodes[0]?.id);
    if (firstNode && graphRef.current.centerAt) {
      graphRef.current.centerAt(firstNode.x, firstNode.y, 1000);
      graphRef.current.zoom(3, 1000);
    } else if (firstNode && graphRef.current.cameraPosition) {
      graphRef.current.cameraPosition(
        { x: firstNode.x || 0, y: firstNode.y || 0, z: 200 },
        { x: firstNode.x || 0, y: firstNode.y || 0, z: 0 },
        1000
      );
    }
  }, [selectedPath, processedData.nodes]);

  const selectPath = useCallback(
    (path: AttackPath) => {
      resetAnimation();
      setSelectedPath(path);
    },
    [resetAnimation]
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, height: '100%' }}>
      {/* ── Header ──────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <Title level={3} className="page-title" style={{ margin: 0 }}>
            Attack Surface Graph
          </Title>
          <Text type="secondary" style={{ fontSize: 12 }}>
            Infrastructure topology — hosts, IPs, ports, services, vulnerabilities
          </Text>
        </div>

        <Space wrap>
          <Segmented
            options={[
              { label: '2D', value: '2D' },
              { label: '3D', value: '3D' },
            ]}
            value={viewMode}
            onChange={(v) => setViewMode(v as ViewMode)}
          />
          <Select
            placeholder="Select Project"
            style={{ minWidth: 160 }}
            value={projectId}
            onChange={(value) => setSelectedProject(value)}
            options={projectsData?.items.map((p) => ({
              label: p.name,
              value: p.project_id,
            }))}
          />
          <Tooltip title="Attack Paths">
            <Button
              icon={<NodeIndexOutlined />}
              type={showPathPanel ? 'primary' : 'default'}
              onClick={() => setShowPathPanel(!showPathPanel)}
            />
          </Tooltip>
          <Button icon={<ReloadOutlined />} onClick={() => mutateGraph()}>
            Refresh
          </Button>
        </Space>
      </div>

      {/* ── Stats Row ───────────────────────────────────────────── */}
      {graphStats && (
        <Row gutter={[16, 16]}>
          <Col xs={12} sm={8} md={4}>
            <C2Panel title="NODES">
              <DataReadout label="Total" value={graphStats.total_nodes} valueColor={colors.accent.primary} />
            </C2Panel>
          </Col>
          <Col xs={12} sm={8} md={4}>
            <C2Panel title="EDGES">
              <DataReadout label="Total" value={graphStats.total_edges} valueColor={colors.accent.secondary} />
            </C2Panel>
          </Col>
          <Col xs={12} sm={8} md={4}>
            <C2Panel title="DISPLAYED">
              <DataReadout label="Nodes" value={processedData.nodes.length} />
            </C2Panel>
          </Col>
          <Col xs={12} sm={8} md={4}>
            <C2Panel title="DISPLAYED">
              <DataReadout label="Edges" value={processedData.links.length} />
            </C2Panel>
          </Col>
          <Col xs={12} sm={8} md={4}>
            <C2Panel title="VIEW">
              <DataReadout label="Mode" value={viewMode} valueColor={colors.accent.terminal} />
            </C2Panel>
          </Col>
          <Col xs={12} sm={8} md={4}>
            <C2Panel title="PATHS">
              <DataReadout label="Found" value={attackPaths?.length ?? 0} valueColor={colors.severity.high} />
            </C2Panel>
          </Col>
        </Row>
      )}

      {/* ── Controls ────────────────────────────────────────────── */}
      <C2Panel title="CONTROLS">
        <Space direction="vertical" style={{ width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <Text type="secondary">Node Limit:</Text>
            <Slider min={100} max={1000} step={100} value={nodeLimit} onChange={setNodeLimit} style={{ flex: 1, minWidth: 120, maxWidth: 300 }} />
            <Text>{nodeLimit}</Text>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <Text type="secondary">Show:</Text>
            {availableTypes.map((type) => (
              <Checkbox key={type} checked={visibleTypes.has(type)} onChange={handleTypeToggle(type)}>
                <span style={{ color: nodeTypeColors[type] || colors.text.muted }}>{type}</span>
              </Checkbox>
            ))}
          </div>
        </Space>
      </C2Panel>

      {/* ── Main Graph + Path Panel ─────────────────────────────── */}
      <div style={{ display: 'flex', flex: 1, gap: 16, minHeight: 0 }}>
        {/* Attack Path Panel — Drawer on narrow screens, inline panel on wide */}
        <Drawer
          title="ATTACK PATHS"
          open={showPathPanel}
          onClose={() => setShowPathPanel(false)}
          placement="left"
          width={340}
          className="attack-path-drawer"
          styles={{ body: { padding: '8px 12px', overflowY: 'auto' } }}
        >
            {!attackPaths || attackPaths.length === 0 ? (
              <Empty description="No attack paths discovered" image={Empty.PRESENTED_IMAGE_SIMPLE} />
            ) : (
              <List
                size="small"
                dataSource={attackPaths}
                renderItem={(path) => (
                  <List.Item
                    className={`attack-path-item ${selectedPath?.path_id === path.path_id ? 'attack-path-item--active' : ''}`}
                    onClick={() => selectPath(path)}
                    style={{ cursor: 'pointer', padding: '8px 4px', borderBottom: `1px solid ${colors.border.subtle}` }}
                  >
                    <div style={{ width: '100%' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                        <Text strong style={{ fontSize: 12 }}>
                          {path.name || `Path ${path.path_id.slice(0, 8)}`}
                        </Text>
                        <Tag color={getSeverityColor(path.risk_level)} style={{ margin: 0 }}>
                          {path.risk_level.toUpperCase()}
                        </Tag>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                        <Text type="secondary">{path.nodes.length} hops</Text>
                        <Text type="secondary">cost: {path.total_cost.toFixed(2)}</Text>
                      </div>
                      {path.mitre_techniques.length > 0 && (
                        <div style={{ marginTop: 4, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {path.mitre_techniques.slice(0, 3).map((t) => (
                            <Tag key={t} color="volcano" style={{ fontSize: 10, margin: 0, lineHeight: '18px' }}>
                              {t}
                            </Tag>
                          ))}
                          {path.mitre_techniques.length > 3 && (
                            <Tag style={{ fontSize: 10, margin: 0, lineHeight: '18px' }}>+{path.mitre_techniques.length - 3}</Tag>
                          )}
                        </div>
                      )}
                    </div>
                  </List.Item>
                )}
              />
            )}

            {/* Animation Controls */}
            {selectedPath && (
              <div
                style={{
                  borderTop: `1px solid ${colors.border.primary}`,
                  padding: '12px 0 4px',
                  marginTop: 8,
                }}
              >
                <Text strong style={{ fontSize: 11, display: 'block', marginBottom: 8 }}>
                  PATH ANIMATOR
                </Text>
                <Progress
                  percent={selectedPath ? Math.round(((animStep + 1) / selectedPath.nodes.length) * 100) : 0}
                  size="small"
                  strokeColor={colors.severity.high}
                  trailColor={colors.bg.tertiary}
                  format={() =>
                    animStep >= 0
                      ? `${animStep + 1}/${selectedPath.nodes.length}`
                      : `0/${selectedPath.nodes.length}`
                  }
                />
                <Space style={{ marginTop: 8 }}>
                  {animPlaying ? (
                    <Button size="small" icon={<PauseCircleOutlined />} onClick={stopAnimation}>
                      Pause
                    </Button>
                  ) : (
                    <Button size="small" icon={<PlayCircleOutlined />} onClick={startAnimation} type="primary">
                      {animStep >= 0 ? 'Resume' : 'Play'}
                    </Button>
                  )}
                  <Button size="small" icon={<StepForwardOutlined />} onClick={stepForward} disabled={animPlaying}>
                    Step
                  </Button>
                  <Button size="small" onClick={resetAnimation}>
                    Reset
                  </Button>
                  <Tooltip title="Focus camera on path">
                    <Button size="small" icon={<AimOutlined />} onClick={focusOnPath} />
                  </Tooltip>
                </Space>

                {/* Current step info */}
                {animStep >= 0 && selectedPath.nodes[animStep] && (
                  <div
                    style={{
                      marginTop: 8,
                      padding: 8,
                      background: colors.bg.tertiary,
                      borderRadius: 4,
                      border: `1px solid ${colors.border.primary}`,
                    }}
                  >
                    <Text style={{ fontSize: 11, color: '#ff8800', display: 'block' }}>
                      STEP {animStep + 1}: {selectedPath.nodes[animStep].label}
                    </Text>
                    <Text type="secondary" style={{ fontSize: 10 }}>
                      {selectedPath.nodes[animStep].type}
                    </Text>
                    {selectedPath.edges[animStep] && (
                      <Text style={{ fontSize: 10, color: colors.accent.terminal, display: 'block', marginTop: 2 }}>
                        {selectedPath.edges[animStep].technique || selectedPath.edges[animStep].type}
                      </Text>
                    )}
                  </div>
                )}
              </div>
            )}
        </Drawer>

        {/* ── Graph Canvas ─────────────────────────────────────── */}
        <C2Panel
          title={`ATTACK SURFACE — ${viewMode}`}
          style={{ flex: 1, minHeight: 360, position: 'relative', display: 'flex', flexDirection: 'column' }}
          bodyStyle={{ padding: 0, flex: 1, minHeight: 0 }}
          extra={
            <Button
              type="text"
              icon={fullscreen ? <FullscreenExitOutlined /> : <FullscreenOutlined />}
              onClick={toggleFullscreen}
            />
          }
        >
          <div ref={containerRef} style={{ width: '100%', height: '100%', minHeight: 360, position: 'relative' }}>
            {!projectId ? (
              <Empty
                description={
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ marginBottom: 8, fontWeight: 600 }}>Attack Surface Graph</div>
                    <div>Select a project to visualize its infrastructure — domains, subdomains, IPs, ports, services, and discovered vulnerabilities as an interactive network graph.</div>
                  </div>
                }
                style={{ padding: 40 }}
              />
            ) : graphLoading ? (
              <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 360 }}>
                <Spin size="large" />
              </div>
            ) : processedData.nodes.length === 0 ? (
              <Empty
                description="No graph data available. Run a scan to populate the attack surface."
                style={{ padding: 40 }}
              />
            ) : viewMode === '2D' ? (
              <ForceGraph2D
                ref={graphRef}
                graphData={processedData}
                nodeId="id"
                nodeCanvasObject={nodeCanvasObject}
                linkCanvasObject={linkCanvasObject}
                onNodeClick={handleNodeClick}
                onBackgroundClick={handleBackgroundClick}
                backgroundColor={colors.bg.primary}
                linkDirectionalArrowLength={3}
                linkDirectionalArrowRelPos={1}
                d3AlphaDecay={0.02}
                d3VelocityDecay={0.3}
                warmupTicks={100}
                cooldownTicks={0}
                width={graphSize.width}
                height={graphSize.height}
              />
            ) : (
              <ForceGraph3D
                ref={graphRef}
                graphData={processedData}
                nodeId="id"
                nodeColor={getNodeColor}
                nodeVal={getNodeVal}
                nodeLabel={getNodeLabel}
                linkColor={getLinkColor}
                linkWidth={getLinkWidth}
                linkDirectionalArrowLength={3}
                linkDirectionalArrowRelPos={1}
                linkDirectionalParticles={(link: any) => {
                  if (!selectedPath) return 0;
                  const sid = typeof link.source === 'object' ? link.source.id : link.source;
                  const tid = typeof link.target === 'object' ? link.target.id : link.target;
                  return visitedNodeIds.has(sid) && visitedNodeIds.has(tid) ? 4 : 0;
                }}
                linkDirectionalParticleWidth={2}
                linkDirectionalParticleColor={() => '#ff8800'}
                onNodeClick={handleNodeClick}
                onBackgroundClick={handleBackgroundClick}
                backgroundColor={colors.bg.primary}
                showNavInfo={false}
                width={graphSize.width}
                height={graphSize.height}
              />
            )}
          </div>
        </C2Panel>
      </div>

      {/* ── Node Details Drawer ─────────────────────────────────── */}
      <Drawer title={selectedNode?.label || 'Node Details'} open={drawerOpen} onClose={() => setDrawerOpen(false)} width={400}>
        {selectedNode && (
          <div>
            <Tag color={nodeTypeColors[selectedNode.type]}>{selectedNode.type}</Tag>

            {selectedNode.severity && (
              <Tag color={getSeverityColor(selectedNode.severity)}>{selectedNode.severity.toUpperCase()}</Tag>
            )}

            <Descriptions column={1} style={{ marginTop: 16 }} size="small" bordered>
              {Object.entries(selectedNode.properties)
                .filter(([key]) => !['project_id', 'created_at', 'updated_at'].includes(key))
                .map(([key, value]) => (
                  <Descriptions.Item key={key} label={key}>
                    {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
                  </Descriptions.Item>
                ))}
            </Descriptions>
          </div>
        )}
      </Drawer>
    </div>
  );
}
