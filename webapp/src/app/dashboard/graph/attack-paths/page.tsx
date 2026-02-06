'use client';

import { useState, useCallback, useMemo } from 'react';
import {
  Select,
  Space,
  Typography,
  Spin,
  Empty,
  Tag,
  Row,
  Col,
  Button,
  Table,
  Collapse,
  Timeline,
  Tooltip,
  Badge,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import {
  ReloadOutlined,
  AimOutlined,
  ThunderboltOutlined,
  NodeIndexOutlined,
  WarningOutlined,
  RightOutlined,
} from '@ant-design/icons';
import useSWR from 'swr';
import { api } from '@/lib/api';
import { useAppStore } from '@/store/provider';
import { colors, getSeverityColor } from '@/lib/theme';
import { C2Panel, DataReadout } from '@/components/c2';
import type { Project, AttackPath, ChokePoint } from '@/types';

const { Title, Text } = Typography;

/**
 * Attack Path Discovery & Analysis
 * Shows discovered attack chains, choke points, and blast radius data.
 */
export default function AttackPathsPage() {
  const currentProject = useAppStore((state) => state.currentProject);
  const [selectedProject, setSelectedProject] = useState<string | null>(null);
  const [expandedPath, setExpandedPath] = useState<string | null>(null);

  const { data: projectsData } = useSWR<{ items: Project[] }>('/api/v1/projects', api.get.bind(api));
  const projectId = selectedProject || currentProject?.project_id;

  // Fetch attack paths
  const {
    data: attackPaths,
    isLoading: pathsLoading,
    mutate: mutatePaths,
  } = useSWR<AttackPath[]>(
    projectId ? `/api/v1/intelligence/attack-paths?project_id=${projectId}` : null,
    api.get.bind(api),
    { fallbackData: [] }
  );

  // Fetch choke points
  const { data: chokePoints } = useSWR<ChokePoint[]>(
    projectId ? `/api/v1/intelligence/choke-points?project_id=${projectId}` : null,
    api.get.bind(api),
    { fallbackData: [] }
  );

  // Stats
  const stats = useMemo(() => {
    if (!attackPaths || attackPaths.length === 0) return null;
    const byRisk = { critical: 0, high: 0, medium: 0, low: 0 };
    let totalHops = 0;
    const techniques = new Set<string>();
    attackPaths.forEach((p) => {
      byRisk[p.risk_level]++;
      totalHops += p.nodes.length;
      p.mitre_techniques.forEach((t) => techniques.add(t));
    });
    return {
      total: attackPaths.length,
      ...byRisk,
      avgHops: Math.round(totalHops / attackPaths.length),
      uniqueTechniques: techniques.size,
    };
  }, [attackPaths]);

  // Choke point columns
  const chokeColumns: ColumnsType<ChokePoint> = [
    {
      title: 'NODE',
      dataIndex: 'label',
      key: 'label',
      render: (text: string, record) => (
        <Space>
          <Badge color={colors.severity.critical} />
          <Text strong style={{ fontSize: 12 }}>
            {text}
          </Text>
          <Tag style={{ fontSize: 10 }}>{record.type}</Tag>
        </Space>
      ),
    },
    {
      title: 'BETWEENNESS',
      dataIndex: 'betweenness_score',
      key: 'betweenness',
      width: 140,
      render: (v: number) => (
        <Text style={{ color: v > 0.5 ? colors.severity.critical : v > 0.3 ? colors.severity.high : colors.text.secondary }}>
          {v.toFixed(4)}
        </Text>
      ),
      sorter: (a, b) => b.betweenness_score - a.betweenness_score,
      defaultSortOrder: 'descend',
    },
    {
      title: 'PATHS THROUGH',
      dataIndex: 'paths_through',
      key: 'paths_through',
      width: 120,
      sorter: (a, b) => b.paths_through - a.paths_through,
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, height: '100%' }}>
      {/* ── Header ─────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Title level={3} className="page-title" style={{ margin: 0 }}>
            Attack Path Analysis
          </Title>
          <Tag color="red" style={{ margin: 0 }}>
            GDS
          </Tag>
        </div>
        <Space wrap>
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
          <Button icon={<ReloadOutlined />} onClick={() => mutatePaths()}>
            Refresh
          </Button>
        </Space>
      </div>

      {/* ── Stats ──────────────────────────────────────── */}
      {stats && (
        <Row gutter={[16, 16]}>
          <Col xs={12} sm={8} md={4}>
            <C2Panel title="TOTAL PATHS">
              <DataReadout label="" value={stats.total} valueColor={colors.accent.primary} />
            </C2Panel>
          </Col>
          <Col xs={12} sm={8} md={3}>
            <C2Panel title="CRITICAL" status="error">
              <DataReadout label="" value={stats.critical} valueColor={colors.severity.critical} />
            </C2Panel>
          </Col>
          <Col xs={12} sm={8} md={3}>
            <C2Panel title="HIGH">
              <DataReadout label="" value={stats.high} valueColor={colors.severity.high} />
            </C2Panel>
          </Col>
          <Col xs={12} sm={8} md={3}>
            <C2Panel title="MEDIUM">
              <DataReadout label="" value={stats.medium} valueColor={colors.severity.medium} />
            </C2Panel>
          </Col>
          <Col xs={12} sm={8} md={3}>
            <C2Panel title="LOW">
              <DataReadout label="" value={stats.low} valueColor={colors.severity.low} />
            </C2Panel>
          </Col>
          <Col xs={12} sm={8} md={4}>
            <C2Panel title="AVG HOPS">
              <DataReadout label="" value={stats.avgHops} />
            </C2Panel>
          </Col>
          <Col xs={12} sm={8} md={4}>
            <C2Panel title="ATT&CK TECHNIQUES">
              <DataReadout label="" value={stats.uniqueTechniques} valueColor={colors.severity.high} />
            </C2Panel>
          </Col>
        </Row>
      )}

      {/* ── Two-column layout: Paths + Choke Points ───── */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, flex: 1, minHeight: 0, overflow: 'hidden' }}>
        {/* Attack Paths */}
        <C2Panel
          title="DISCOVERED ATTACK PATHS"
          style={{ flex: 2, display: 'flex', flexDirection: 'column' }}
          bodyStyle={{ flex: 1, overflowY: 'auto', padding: '8px 16px' }}
        >
          {pathsLoading ? (
            <Spin style={{ display: 'block', margin: '40px auto' }} />
          ) : !attackPaths || attackPaths.length === 0 ? (
            <Empty description="No attack paths discovered yet. Run path analysis to discover routes." />
          ) : (
            <Collapse
              accordion
              activeKey={expandedPath ?? undefined}
              onChange={(key) => setExpandedPath(typeof key === 'string' ? key : key?.[0] ?? null)}
              ghost
              items={attackPaths.map((path) => ({
                key: path.path_id,
                label: (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                    <Space>
                      <ThunderboltOutlined style={{ color: getSeverityColor(path.risk_level) }} />
                      <Text strong style={{ fontSize: 13 }}>
                        {path.name || `Path ${path.path_id.slice(0, 8)}`}
                      </Text>
                    </Space>
                    <Space>
                      <Tag color={getSeverityColor(path.risk_level)}>{path.risk_level.toUpperCase()}</Tag>
                      <Text type="secondary" style={{ fontSize: 11 }}>
                        {path.nodes.length} hops
                      </Text>
                      <Text type="secondary" style={{ fontSize: 11 }}>
                        cost: {path.total_cost.toFixed(2)}
                      </Text>
                    </Space>
                  </div>
                ),
                children: (
                  <div style={{ padding: '8px 0' }}>
                    {/* Path chain visualization */}
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        flexWrap: 'wrap',
                        marginBottom: 16,
                        padding: '12px 16px',
                        background: colors.bg.tertiary,
                        borderRadius: 4,
                        border: `1px solid ${colors.border.primary}`,
                      }}
                    >
                      {path.nodes.map((node, i) => (
                        <span key={node.id} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                          <Tooltip title={`${node.type} — risk: ${node.risk_score}`}>
                            <Tag
                              color={i === 0 ? 'green' : i === path.nodes.length - 1 ? 'red' : 'default'}
                              style={{ cursor: 'pointer', fontSize: 11 }}
                            >
                              {node.label}
                            </Tag>
                          </Tooltip>
                          {i < path.nodes.length - 1 && (
                            <Tooltip title={path.edges[i]?.technique || path.edges[i]?.type}>
                              <RightOutlined
                                style={{
                                  fontSize: 10,
                                  color: path.edges[i]?.technique ? colors.severity.high : colors.text.muted,
                                }}
                              />
                            </Tooltip>
                          )}
                        </span>
                      ))}
                    </div>

                    {/* Timeline of steps */}
                    <Timeline
                      items={path.nodes.map((node, i) => ({
                        color: i === 0 ? 'green' : i === path.nodes.length - 1 ? 'red' : 'blue',
                        children: (
                          <div>
                            <Text strong style={{ fontSize: 12 }}>
                              {node.label}
                            </Text>
                            <Text type="secondary" style={{ fontSize: 11, marginLeft: 8 }}>
                              ({node.type})
                            </Text>
                            {path.edges[i] && (
                              <div style={{ marginTop: 2 }}>
                                <Text style={{ fontSize: 11, color: colors.accent.terminal }}>
                                  {path.edges[i].technique || path.edges[i].type}
                                </Text>
                                {path.edges[i].description && (
                                  <Text type="secondary" style={{ fontSize: 10, display: 'block' }}>
                                    {path.edges[i].description}
                                  </Text>
                                )}
                                <Text type="secondary" style={{ fontSize: 10, display: 'block' }}>
                                  cost: {path.edges[i].cost.toFixed(2)}
                                </Text>
                              </div>
                            )}
                          </div>
                        ),
                      }))}
                    />

                    {/* MITRE ATT&CK techniques */}
                    {path.mitre_techniques.length > 0 && (
                      <div style={{ marginTop: 8 }}>
                        <Text type="secondary" style={{ fontSize: 11, display: 'block', marginBottom: 4 }}>
                          MITRE ATT&CK Techniques:
                        </Text>
                        <Space wrap>
                          {path.mitre_techniques.map((t) => (
                            <Tag key={t} color="volcano" style={{ fontSize: 10 }}>
                              {t}
                            </Tag>
                          ))}
                        </Space>
                      </div>
                    )}
                  </div>
                ),
              }))}
            />
          )}
        </C2Panel>

        {/* Choke Points */}
        <C2Panel
          title="CHOKE POINTS"
          style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 'min(320px, 100%)' }}
          bodyStyle={{ flex: 1, overflowY: 'auto', padding: 0 }}
        >
          {!chokePoints || chokePoints.length === 0 ? (
            <Empty description="No choke points identified" style={{ padding: 40 }} />
          ) : (
            <Table
              scroll={{ x: 500 }}
              dataSource={chokePoints}
              columns={chokeColumns}
              rowKey="node_id"
              size="small"
              pagination={false}
              style={{ fontSize: 12 }}
            />
          )}
        </C2Panel>
      </div>
    </div>
  );
}
