'use client';

import { Row, Col, Typography, Progress, Tag, Skeleton } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import useSWR from 'swr';
import { api } from '@/lib/api';
import { useAppStore } from '@/store/provider';
import { colors, getSeverityColor, getStatusColor } from '@/lib/theme';
import { C2Panel, DataReadout, C2Table } from '@/components/c2';
import type { Scan, Vulnerability, ProjectStats, PaginatedResponse } from '@/types';

const { Title, Text } = Typography;

/**
 * Dashboard overview page
 */
export default function DashboardPage() {
  const currentProject = useAppStore((state) => state.currentProject);
  const setCurrentProject = useAppStore((state) => state.setCurrentProject);

  const onProjectScopeError = (err: { status?: number }) => {
    if (err?.status === 404) setCurrentProject(null);
  };
  const swrOptions = {
    refreshInterval: 10000,
    onError: onProjectScopeError,
  };

  const { data: stats, isLoading: statsLoading } = useSWR<ProjectStats>(
    currentProject ? `/api/v1/projects/${currentProject.project_id}/stats` : null,
    api.get,
    swrOptions
  );

  const { data: recentScans, isLoading: scansLoading } = useSWR<PaginatedResponse<Scan>>(
    currentProject
      ? `/api/v1/scans?project_id=${currentProject.project_id}&page_size=5`
      : null,
    api.get,
    swrOptions
  );

  const { data: recentVulns, isLoading: vulnsLoading } = useSWR<PaginatedResponse<Vulnerability>>(
    currentProject
      ? `/api/v1/vulnerabilities?project_id=${currentProject.project_id}&page_size=5`
      : null,
    api.get,
    swrOptions
  );

  const scanColumns: ColumnsType<Scan> = [
    { title: 'Target', dataIndex: 'target', key: 'target' },
    {
      title: 'Type',
      dataIndex: 'scan_type',
      key: 'scan_type',
      render: (type: string) => (
        <Text style={{ textTransform: 'capitalize' }}>{type.replace(/_/g, ' ')}</Text>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => (
        <Tag color={getStatusColor(status)} style={{ textTransform: 'uppercase' }}>
          {status}
        </Tag>
      ),
    },
    {
      title: 'Progress',
      dataIndex: 'progress',
      key: 'progress',
      width: 120,
      render: (progress: number, record: Scan) =>
        record.status === 'running' ? (
          <Progress percent={Math.round(progress)} size="small" strokeColor={colors.accent.primary} />
        ) : (
          <Text type="secondary">{progress}%</Text>
        ),
    },
    { title: 'Findings', dataIndex: 'findings_count', key: 'findings_count', width: 80, align: 'right' },
  ];

  const vulnColumns: ColumnsType<Vulnerability> = [
    { title: 'Vulnerability', dataIndex: 'name', key: 'name' },
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (severity: string) => (
        <Tag color={getSeverityColor(severity)} style={{ textTransform: 'uppercase' }}>
          {severity}
        </Tag>
      ),
    },
    {
      title: 'Target',
      dataIndex: 'matched_at',
      key: 'matched_at',
      render: (url: string) => (
        <Text style={{ fontSize: 12 }}>{url}</Text>
      ),
    },
  ];

  if (!currentProject) {
    return (
      <C2Panel title="DASHBOARD" style={{ maxWidth: 560, margin: '48px auto' }}>
        <div style={{ textAlign: 'center', padding: '24px 0' }}>
          <Title level={4} style={{ color: colors.text.secondary, marginBottom: 8 }}>
            Select a project to view the dashboard
          </Title>
          <Text type="secondary">
            Choose a project from the Projects page or create a new one.
          </Text>
        </div>
      </C2Panel>
    );
  }

  const mediumVulns = Math.max(
    0,
    (stats?.vulnerabilities ?? 0) - (stats?.critical_vulns ?? 0) - (stats?.high_vulns ?? 0)
  );

  return (
    <div>
      <Title level={3} className="page-title" style={{ marginBottom: 24 }}>
        {currentProject.name}
      </Title>

      <C2Panel title="PROJECT STATS" style={{ marginBottom: 24 }}>
        {statsLoading ? (
          <Skeleton active />
        ) : (
          <Row gutter={[24, 16]}>
            <Col xs={12} sm={8} md={6}>
              <DataReadout label="Subdomains" value={stats?.subdomains ?? 0} />
            </Col>
            <Col xs={12} sm={8} md={6}>
              <DataReadout label="Open Ports" value={stats?.ports ?? 0} />
            </Col>
            <Col xs={12} sm={8} md={6}>
              <DataReadout label="Live URLs" value={stats?.urls ?? 0} />
            </Col>
            <Col xs={12} sm={8} md={6}>
              <DataReadout
                label="Vulnerabilities"
                value={stats?.vulnerabilities ?? 0}
                valueColor={colors.severity.critical}
              />
            </Col>
            <Col xs={12} sm={8} md={6}>
              <DataReadout
                label="Critical"
                value={stats?.critical_vulns ?? 0}
                valueColor={colors.severity.critical}
              />
            </Col>
            <Col xs={12} sm={8} md={6}>
              <DataReadout
                label="High"
                value={stats?.high_vulns ?? 0}
                valueColor={colors.severity.high}
              />
            </Col>
            <Col xs={12} sm={8} md={6}>
              <DataReadout
                label="Medium"
                value={mediumVulns}
                valueColor={colors.severity.medium}
              />
            </Col>
            <Col xs={12} sm={8} md={6}>
              <DataReadout label="Scans completed" value={stats?.scans_completed ?? 0} />
            </Col>
          </Row>
        )}
      </C2Panel>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <C2Panel title="RECENT SCANS" style={{ marginBottom: 24 }}>
            <C2Table<Scan>
              scroll={{ x: 600 }}
              columns={scanColumns}
              dataSource={recentScans?.items ?? []}
              rowKey="scan_id"
              pagination={false}
              loading={scansLoading}
              size="small"
              locale={{ emptyText: 'No recent scans' }}
            />
          </C2Panel>
        </Col>
        <Col xs={24} lg={12}>
          <C2Panel title="RECENT VULNERABILITIES" style={{ marginBottom: 24 }}>
            <C2Table<Vulnerability>
              scroll={{ x: 550 }}
              columns={vulnColumns}
              dataSource={recentVulns?.items ?? []}
              rowKey={(record, idx) => `${record.template_id}-${record.matched_at}-${idx}`}
              pagination={false}
              loading={vulnsLoading}
              size="small"
              locale={{ emptyText: 'No vulnerabilities found' }}
            />
          </C2Panel>
        </Col>
      </Row>
    </div>
  );
}
