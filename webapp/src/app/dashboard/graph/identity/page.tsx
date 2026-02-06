'use client';

import { useState, useCallback, useMemo, useRef, useEffect } from 'react';
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
  Segmented,
  Badge,
} from 'antd';
import {
  ReloadOutlined,
  FullscreenOutlined,
  FullscreenExitOutlined,
} from '@ant-design/icons';
import useSWR from 'swr';
import { api } from '@/lib/api';
import { useAppStore } from '@/store/provider';
import { colors } from '@/lib/theme';
import { C2Panel, DataReadout } from '@/components/c2';
import type { Project, IdentityNode, IdentityGraphData, IdentityNodeType } from '@/types';

const { Title, Text } = Typography;

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

// ── BloodHound-style color scheme for identity node types ──────────
const identityTypeConfig: Record<
  IdentityNodeType,
  { color: string; icon: string; shape: 'circle' | 'diamond' | 'square' | 'triangle' }
> = {
  ADUser: { color: '#22c55e', icon: 'U', shape: 'circle' },
  ADGroup: { color: '#f59e0b', icon: 'G', shape: 'diamond' },
  ADComputer: { color: '#3b82f6', icon: 'C', shape: 'square' },
  ADDomain: { color: '#dc2626', icon: 'D', shape: 'triangle' },
  ADOU: { color: '#8b5cf6', icon: 'O', shape: 'diamond' },
  ADGPO: { color: '#06b6d4', icon: 'P', shape: 'square' },
  ADCertTemplate: { color: '#f43f5e', icon: 'T', shape: 'diamond' },
  AzureUser: { color: '#10b981', icon: 'u', shape: 'circle' },
  AzureGroup: { color: '#d97706', icon: 'g', shape: 'diamond' },
  AzureApp: { color: '#6366f1', icon: 'A', shape: 'square' },
  AzureRole: { color: '#ef4444', icon: 'R', shape: 'triangle' },
  AzureServicePrincipal: { color: '#14b8a6', icon: 'S', shape: 'square' },
};

// Edge type colors (BloodHound relationship types)
const edgeTypeColors: Record<string, string> = {
  MemberOf: '#f59e0b',
  AdminTo: '#dc2626',
  HasSession: '#22c55e',
  CanRDP: '#3b82f6',
  GenericAll: '#ef4444',
  WriteDACL: '#f97316',
  WriteOwner: '#f97316',
  Owns: '#a855f7',
  ForceChangePassword: '#e11d48',
  CanPSRemote: '#3b82f6',
  HasSIDHistory: '#8b5cf6',
  AllExtendedRights: '#ef4444',
  AddMember: '#d97706',
  ExecuteDCOM: '#06b6d4',
  AllowedToDelegate: '#14b8a6',
  ReadLAPSPassword: '#f43f5e',
  Contains: '#525252',
  GPLink: '#06b6d4',
};

type IdentityFilter = 'all' | 'da_paths' | 'kerberoastable' | 'high_value' | 'owned';
type ViewMode = '2D' | '3D';

/**
 * BloodHound-style Identity Attack Graph
 */
export default function IdentityGraphPage() {
  const currentProject = useAppStore((state) => state.currentProject);
  const [selectedProject, setSelectedProject] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<IdentityNode | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [viewMode, setViewMode] = useState<ViewMode>('3D');
  const [filter, setFilter] = useState<IdentityFilter>('all');
  const [fullscreen, setFullscreen] = useState(false);

  const graphRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [graphSize, setGraphSize] = useState({ width: 800, height: 500 });

  // Responsive sizing
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

  const { data: projectsData } = useSWR<{ items: Project[] }>('/api/v1/projects', api.get.bind(api));
  const projectId = selectedProject || currentProject?.project_id;

  // Fetch identity graph
  const {
    data: identityData,
    isLoading,
    mutate,
  } = useSWR<IdentityGraphData>(
    projectId ? `/api/v1/intelligence/identity/graph?project_id=${projectId}&filter=${filter}` : null,
    api.get.bind(api)
  );

  // Process data for force graph
  const processedData = useMemo(() => {
    if (!identityData) return { nodes: [], links: [] };

    const nodes = identityData.nodes.map((n) => ({
      ...n,
      val: n.is_high_value ? 6 : n.is_admin ? 5 : n.is_owned ? 4 : 2,
    }));

    const links = identityData.edges.map((e) => ({
      source: e.source,
      target: e.target,
      type: e.type,
    }));

    return { nodes, links };
  }, [identityData]);

  const stats = identityData?.domain_stats;

  // ── Callbacks ────────────────────────────────────────────────

  const handleNodeClick = useCallback((node: unknown) => {
    setSelectedNode(node as IdentityNode);
    setDrawerOpen(true);
  }, []);

  const handleBackgroundClick = useCallback(() => {
    setSelectedNode(null);
    setDrawerOpen(false);
  }, []);

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

  // ── 2D node renderer (BloodHound style) ──────────────────────

  const nodeCanvasObject = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const cfg = identityTypeConfig[node.type as IdentityNodeType] || { color: '#525252', icon: '?', shape: 'circle' };
      const label = String(node.label || '');
      const fontSize = Math.max(8, 10 / globalScale);
      const size = node.is_high_value ? 8 : node.is_admin ? 7 : node.is_owned ? 6 : 5;

      ctx.font = `bold ${fontSize}px JetBrains Mono, monospace`;

      // Owned glow
      if (node.is_owned) {
        ctx.shadowColor = '#22c55e';
        ctx.shadowBlur = 15;
      } else if (node.is_high_value) {
        ctx.shadowColor = '#dc2626';
        ctx.shadowBlur = 12;
      }

      // Draw shape
      ctx.fillStyle = cfg.color;
      ctx.strokeStyle = selectedNode?.id === node.id ? '#ffffff' : 'transparent';
      ctx.lineWidth = 2 / globalScale;

      if (cfg.shape === 'diamond') {
        ctx.beginPath();
        ctx.moveTo(node.x, node.y - size);
        ctx.lineTo(node.x + size, node.y);
        ctx.lineTo(node.x, node.y + size);
        ctx.lineTo(node.x - size, node.y);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      } else if (cfg.shape === 'square') {
        ctx.fillRect(node.x - size, node.y - size, size * 2, size * 2);
        if (selectedNode?.id === node.id) ctx.strokeRect(node.x - size, node.y - size, size * 2, size * 2);
      } else if (cfg.shape === 'triangle') {
        ctx.beginPath();
        ctx.moveTo(node.x, node.y - size * 1.2);
        ctx.lineTo(node.x + size, node.y + size * 0.6);
        ctx.lineTo(node.x - size, node.y + size * 0.6);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      } else {
        ctx.beginPath();
        ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
        ctx.fill();
        ctx.stroke();
      }

      ctx.shadowColor = 'transparent';
      ctx.shadowBlur = 0;

      // High value / owned badge
      if (node.is_high_value) {
        ctx.fillStyle = '#dc2626';
        ctx.beginPath();
        ctx.arc(node.x + size, node.y - size, 3, 0, 2 * Math.PI);
        ctx.fill();
      }
      if (node.is_owned) {
        ctx.fillStyle = '#22c55e';
        ctx.beginPath();
        ctx.arc(node.x - size, node.y - size, 3, 0, 2 * Math.PI);
        ctx.fill();
      }

      // Label
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = colors.text.secondary;
      ctx.fillText(label, node.x, node.y + size + fontSize + 2);
    },
    [selectedNode]
  );

  const linkCanvasObject = useCallback(
    (link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const start = typeof link.source === 'object' ? link.source : { x: 0, y: 0 };
      const end = typeof link.target === 'object' ? link.target : { x: 0, y: 0 };

      const edgeColor = edgeTypeColors[link.type] || colors.border.primary;

      ctx.beginPath();
      ctx.moveTo(start.x, start.y);
      ctx.lineTo(end.x, end.y);
      ctx.strokeStyle = edgeColor;
      ctx.lineWidth = link.type === 'AdminTo' || link.type === 'GenericAll' ? 1.5 / globalScale : 0.5 / globalScale;
      ctx.stroke();

      // Label for high-impact edges
      if (['AdminTo', 'GenericAll', 'WriteDACL', 'ForceChangePassword', 'Owns'].includes(link.type)) {
        const midX = (start.x + end.x) / 2;
        const midY = (start.y + end.y) / 2;
        ctx.font = `${Math.max(6, 8 / globalScale)}px JetBrains Mono, monospace`;
        ctx.textAlign = 'center';
        ctx.fillStyle = edgeColor;
        ctx.fillText(link.type, midX, midY - 4);
      }
    },
    []
  );

  // 3D helpers
  const getNodeColor = useCallback((node: any) => {
    const cfg = identityTypeConfig[node.type as IdentityNodeType];
    return cfg?.color || '#525252';
  }, []);

  const getNodeVal = useCallback((node: any) => {
    return node.is_high_value ? 6 : node.is_admin ? 5 : node.is_owned ? 4 : 2;
  }, []);

  const getLinkColor = useCallback((link: any) => {
    return edgeTypeColors[link.type] || 'rgba(38,38,38,0.6)';
  }, []);

  const getLinkWidth = useCallback((link: any) => {
    return ['AdminTo', 'GenericAll', 'WriteDACL'].includes(link.type) ? 2 : 0.5;
  }, []);

  const getNodeLabel = useCallback((node: any) => {
    const cfg = identityTypeConfig[node.type as IdentityNodeType];
    const badges = [
      node.is_high_value ? '<span style="color:#dc2626">HIGH VALUE</span>' : '',
      node.is_owned ? '<span style="color:#22c55e">OWNED</span>' : '',
      node.is_admin ? '<span style="color:#f59e0b">ADMIN</span>' : '',
    ]
      .filter(Boolean)
      .join(' ');

    return `<div class="graph3d-tooltip">
      <div class="graph3d-tooltip__title" style="color:${cfg?.color || '#fff'}">${node.label}</div>
      <div class="graph3d-tooltip__type">${node.type}</div>
      ${badges ? `<div style="margin-top:4px">${badges}</div>` : ''}
    </div>`;
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, height: '100%' }}>
      {/* ── Header ────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Title level={3} className="page-title" style={{ margin: 0 }}>
              Identity Graph
            </Title>
            <Tag color="volcano" style={{ margin: 0 }}>BloodHound</Tag>
          </div>
          <Text type="secondary" style={{ fontSize: 12 }}>
            Active Directory &amp; Azure AD — users, groups, computers, privilege paths
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
            placeholder="Filter"
            style={{ minWidth: 160 }}
            value={filter}
            onChange={(v) => setFilter(v as IdentityFilter)}
            options={[
              { label: 'All Objects', value: 'all' },
              { label: 'DA Paths', value: 'da_paths' },
              { label: 'Kerberoastable', value: 'kerberoastable' },
              { label: 'High Value', value: 'high_value' },
              { label: 'Owned', value: 'owned' },
            ]}
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
          <Button icon={<ReloadOutlined />} onClick={() => mutate()}>
            Refresh
          </Button>
        </Space>
      </div>

      {/* ── Domain Stats ──────────────────────────────── */}
      {stats && (
        <Row gutter={[16, 16]}>
          <Col xs={12} sm={6} md={3}>
            <C2Panel title="USERS">
              <DataReadout label="" value={stats.users} valueColor="#22c55e" />
            </C2Panel>
          </Col>
          <Col xs={12} sm={6} md={3}>
            <C2Panel title="GROUPS">
              <DataReadout label="" value={stats.groups} valueColor="#f59e0b" />
            </C2Panel>
          </Col>
          <Col xs={12} sm={6} md={3}>
            <C2Panel title="COMPUTERS">
              <DataReadout label="" value={stats.computers} valueColor="#3b82f6" />
            </C2Panel>
          </Col>
          <Col xs={12} sm={6} md={3}>
            <C2Panel title="DOMAINS">
              <DataReadout label="" value={stats.domains} valueColor="#dc2626" />
            </C2Panel>
          </Col>
          <Col xs={12} sm={6} md={3}>
            <C2Panel title="DA COUNT" status="error">
              <DataReadout label="" value={stats.domain_admins} valueColor="#dc2626" />
            </C2Panel>
          </Col>
          <Col xs={12} sm={6} md={3}>
            <C2Panel title="KERBEROAST" status="warn">
              <DataReadout label="" value={stats.kerberoastable} valueColor="#f59e0b" />
            </C2Panel>
          </Col>
          <Col xs={12} sm={6} md={3}>
            <C2Panel title="AS-REP">
              <DataReadout label="" value={stats.asrep_roastable} valueColor="#f97316" />
            </C2Panel>
          </Col>
          <Col xs={12} sm={6} md={3}>
            <C2Panel title="UNCONSTR. DELEG" status="warn">
              <DataReadout label="" value={stats.unconstrained_delegation} valueColor="#f59e0b" />
            </C2Panel>
          </Col>
        </Row>
      )}

      {/* ── Legend ─────────────────────────────────────── */}
      <C2Panel title="LEGEND">
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
          {(Object.entries(identityTypeConfig) as [IdentityNodeType, typeof identityTypeConfig[IdentityNodeType]][]).map(
            ([type, cfg]) => (
              <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}>
                <div
                  style={{
                    width: 10,
                    height: 10,
                    background: cfg.color,
                    borderRadius: cfg.shape === 'circle' ? '50%' : cfg.shape === 'diamond' ? 0 : 2,
                    transform: cfg.shape === 'diamond' ? 'rotate(45deg) scale(0.8)' : undefined,
                  }}
                />
                <Text type="secondary">{type}</Text>
              </div>
            )
          )}
          <div style={{ borderLeft: `1px solid ${colors.border.primary}`, paddingLeft: 12, display: 'flex', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}>
              <Badge color="#dc2626" /> <Text type="secondary">High Value</Text>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}>
              <Badge color="#22c55e" /> <Text type="secondary">Owned</Text>
            </div>
          </div>
        </div>
      </C2Panel>

      {/* ── Graph ─────────────────────────────────────── */}
      <C2Panel
        title={`IDENTITY ATTACK GRAPH — ${viewMode}`}
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
                  <div style={{ marginBottom: 8, fontWeight: 600 }}>BloodHound-Style Identity Graph</div>
                  <div>Select a project to visualize Active Directory and Azure AD relationships — users, groups, computers, GPOs, privilege escalation paths, and Kerberoastable accounts.</div>
                </div>
              }
              style={{ padding: 40 }}
            />
          ) : isLoading ? (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 360 }}>
              <Spin size="large" />
            </div>
          ) : processedData.nodes.length === 0 ? (
            <Empty
              description={
                <div style={{ textAlign: 'center' }}>
                  <div style={{ marginBottom: 8, fontWeight: 600 }}>No Identity Data</div>
                  <div>Run BloodHound collection via the MCP tools to populate AD/Azure objects and their relationships.</div>
                </div>
              }
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
              linkDirectionalArrowLength={4}
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
              linkDirectionalArrowLength={4}
              linkDirectionalArrowRelPos={1}
              linkDirectionalParticles={(link: any) =>
                ['AdminTo', 'GenericAll', 'WriteDACL'].includes(link.type) ? 3 : 0
              }
              linkDirectionalParticleWidth={2}
              linkDirectionalParticleColor={getLinkColor}
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

      {/* ── Node Details Drawer ───────────────────────── */}
      <Drawer
        title={
          selectedNode ? (
            <Space>
              <div
                style={{
                  width: 12,
                  height: 12,
                  borderRadius: identityTypeConfig[selectedNode.type]?.shape === 'circle' ? '50%' : 2,
                  background: identityTypeConfig[selectedNode.type]?.color || '#525252',
                  display: 'inline-block',
                }}
              />
              {selectedNode.label}
            </Space>
          ) : (
            'Object Details'
          )
        }
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        width={420}
      >
        {selectedNode && (
          <div>
            <Space style={{ marginBottom: 16 }}>
              <Tag color={identityTypeConfig[selectedNode.type]?.color}>{selectedNode.type}</Tag>
              {selectedNode.is_high_value && <Tag color="red">HIGH VALUE</Tag>}
              {selectedNode.is_owned && <Tag color="green">OWNED</Tag>}
              {selectedNode.is_admin && <Tag color="orange">ADMIN</Tag>}
            </Space>

            <Descriptions column={1} size="small" bordered>
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
