'use client';

import { useState, useCallback, useMemo } from 'react';
import {
  Typography,
  Space,
  Tag,
  Button,
  Empty,
  Spin,
  Row,
  Col,
  Descriptions,
  Modal,
  Input,
  Table,
  Tooltip,
  Segmented,
  Badge,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  ClockCircleOutlined,
  ThunderboltOutlined,
  SafetyOutlined,
  ReloadOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import useSWR from 'swr';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { api } from '@/lib/api';
import { colors, getSeverityColor } from '@/lib/theme';
import { C2Panel, DataReadout } from '@/components/c2';
import type { ApprovalRequest, ApprovalStatus, RiskLevel } from '@/types';

dayjs.extend(relativeTime);

const { Title, Text } = Typography;
const { TextArea } = Input;

const riskIcons: Record<RiskLevel, React.ReactNode> = {
  critical: <ExclamationCircleOutlined style={{ color: colors.severity.critical }} />,
  high: <WarningOutlined style={{ color: colors.severity.high }} />,
  medium: <ThunderboltOutlined style={{ color: colors.severity.medium }} />,
  low: <SafetyOutlined style={{ color: colors.severity.low }} />,
};

const statusConfig: Record<
  ApprovalStatus,
  { color: string; icon: React.ReactNode; label: string }
> = {
  pending: { color: '#f59e0b', icon: <ClockCircleOutlined />, label: 'PENDING' },
  approved: { color: '#22c55e', icon: <CheckCircleOutlined />, label: 'APPROVED' },
  denied: { color: '#ef4444', icon: <CloseCircleOutlined />, label: 'DENIED' },
  expired: { color: '#6b7280', icon: <ClockCircleOutlined />, label: 'EXPIRED' },
};

type FilterTab = 'pending' | 'all' | 'approved' | 'denied';

/**
 * Human-in-the-Loop Approval Queue
 */
export default function ApprovalsPage() {
  const [filterTab, setFilterTab] = useState<FilterTab>('pending');
  const [selectedRequest, setSelectedRequest] = useState<ApprovalRequest | null>(null);
  const [denyReason, setDenyReason] = useState('');
  const [denyModalOpen, setDenyModalOpen] = useState(false);
  const [loadingId, setLoadingId] = useState<string | null>(null);

  // Fetch approval requests
  const {
    data: approvals,
    isLoading,
    mutate,
  } = useSWR<ApprovalRequest[]>(
    `/api/v1/agents/approvals?status=${filterTab === 'all' ? '' : filterTab}`,
    api.get.bind(api),
    { refreshInterval: 5000, fallbackData: [] }
  );

  // Stats
  const stats = useMemo(() => {
    if (!approvals) return { pending: 0, approved: 0, denied: 0, expired: 0, critical: 0, high: 0 };
    return {
      pending: approvals.filter((a) => a.status === 'pending').length,
      approved: approvals.filter((a) => a.status === 'approved').length,
      denied: approvals.filter((a) => a.status === 'denied').length,
      expired: approvals.filter((a) => a.status === 'expired').length,
      critical: approvals.filter((a) => a.risk_level === 'critical' && a.status === 'pending').length,
      high: approvals.filter((a) => a.risk_level === 'high' && a.status === 'pending').length,
    };
  }, [approvals]);

  // ── Actions ────────────────────────────────────────────────

  const handleApprove = useCallback(
    async (approvalId: string) => {
      setLoadingId(approvalId);
      try {
        await api.post(`/api/v1/agents/approvals/${approvalId}/approve`, {});
        mutate();
      } catch (err) {
        console.error('Approval failed:', err);
      } finally {
        setLoadingId(null);
      }
    },
    [mutate]
  );

  const handleDeny = useCallback(
    async (approvalId: string) => {
      setLoadingId(approvalId);
      try {
        await api.post(`/api/v1/agents/approvals/${approvalId}/deny`, { reason: denyReason });
        setDenyModalOpen(false);
        setDenyReason('');
        mutate();
      } catch (err) {
        console.error('Denial failed:', err);
      } finally {
        setLoadingId(null);
      }
    },
    [mutate, denyReason]
  );

  const openDenyModal = useCallback((request: ApprovalRequest) => {
    setSelectedRequest(request);
    setDenyReason('');
    setDenyModalOpen(true);
  }, []);

  // ── Columns ────────────────────────────────────────────────

  const columns: ColumnsType<ApprovalRequest> = [
    {
      title: 'RISK',
      dataIndex: 'risk_level',
      key: 'risk',
      width: 80,
      render: (risk: RiskLevel) => (
        <Tooltip title={risk.toUpperCase()}>
          <Tag
            icon={riskIcons[risk]}
            color={getSeverityColor(risk)}
            style={{ fontSize: 10, margin: 0 }}
          >
            {risk.toUpperCase()}
          </Tag>
        </Tooltip>
      ),
      filters: [
        { text: 'Critical', value: 'critical' },
        { text: 'High', value: 'high' },
        { text: 'Medium', value: 'medium' },
        { text: 'Low', value: 'low' },
      ],
      onFilter: (value, record) => record.risk_level === value,
      sorter: (a, b) => {
        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        return (order[a.risk_level] ?? 4) - (order[b.risk_level] ?? 4);
      },
      defaultSortOrder: 'ascend',
    },
    {
      title: 'AGENT',
      dataIndex: 'agent_name',
      key: 'agent',
      width: 140,
      render: (name: string) => (
        <Text style={{ fontSize: 12 }}>{name}</Text>
      ),
    },
    {
      title: 'ACTION',
      dataIndex: 'action',
      key: 'action',
      render: (action: string, record) => (
        <div>
          <Text strong style={{ fontSize: 12, display: 'block' }}>
            {action}
          </Text>
          <Text type="secondary" style={{ fontSize: 11 }}>
            {record.tool_name}
          </Text>
          {record.target_info && (
            <Text type="secondary" style={{ fontSize: 10, display: 'block' }}>
              Target: {record.target_info}
            </Text>
          )}
        </div>
      ),
    },
    {
      title: 'MITRE',
      dataIndex: 'mitre_technique',
      key: 'mitre',
      width: 120,
      render: (tech?: string) =>
        tech ? (
          <Tag color="volcano" style={{ fontSize: 10, margin: 0 }}>
            {tech}
          </Tag>
        ) : (
          <Text type="secondary">—</Text>
        ),
    },
    {
      title: 'STATUS',
      dataIndex: 'status',
      key: 'status',
      width: 110,
      render: (status: ApprovalStatus) => {
        const cfg = statusConfig[status];
        return (
          <Tag icon={cfg.icon} color={cfg.color} style={{ fontSize: 10, margin: 0 }}>
            {cfg.label}
          </Tag>
        );
      },
    },
    {
      title: 'REQUESTED',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 130,
      render: (date: string) => (
        <Tooltip title={dayjs(date).format('YYYY-MM-DD HH:mm:ss')}>
          <Text type="secondary" style={{ fontSize: 11 }}>
            {dayjs(date).fromNow()}
          </Text>
        </Tooltip>
      ),
      sorter: (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    },
    {
      title: 'EXPIRES',
      dataIndex: 'expires_at',
      key: 'expires_at',
      width: 130,
      render: (date: string, record) => {
        if (record.status !== 'pending') return <Text type="secondary">—</Text>;
        const isExpiring = dayjs(date).diff(dayjs(), 'minute') < 10;
        return (
          <Tooltip title={dayjs(date).format('YYYY-MM-DD HH:mm:ss')}>
            <Text type={isExpiring ? 'danger' : 'secondary'} style={{ fontSize: 11 }}>
              {dayjs(date).fromNow()}
            </Text>
          </Tooltip>
        );
      },
    },
    {
      title: 'ACTIONS',
      key: 'actions',
      width: 160,
      fixed: 'right',
      render: (_, record) => {
        if (record.status !== 'pending') {
          return (
            <Text type="secondary" style={{ fontSize: 11 }}>
              {record.reviewed_by ? `by ${record.reviewed_by}` : '—'}
            </Text>
          );
        }
        return (
          <Space>
            <Button
              type="primary"
              size="small"
              icon={<CheckCircleOutlined />}
              loading={loadingId === record.approval_id}
              onClick={() => handleApprove(record.approval_id)}
              style={{ background: colors.status.success, borderColor: colors.status.success }}
            >
              Approve
            </Button>
            <Button
              danger
              size="small"
              icon={<CloseCircleOutlined />}
              loading={loadingId === record.approval_id}
              onClick={() => openDenyModal(record)}
            >
              Deny
            </Button>
          </Space>
        );
      },
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, height: '100%' }}>
      {/* ── Header ────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Title level={3} className="page-title" style={{ margin: 0 }}>
            Approval Queue
          </Title>
          {stats.pending > 0 && (
            <Badge count={stats.pending} overflowCount={99} style={{ backgroundColor: colors.severity.high }} />
          )}
        </div>
        <Space>
          <Segmented
            options={[
              { label: `Pending (${stats.pending})`, value: 'pending' },
              { label: 'Approved', value: 'approved' },
              { label: 'Denied', value: 'denied' },
              { label: 'All', value: 'all' },
            ]}
            value={filterTab}
            onChange={(v) => setFilterTab(v as FilterTab)}
          />
          <Button icon={<ReloadOutlined />} onClick={() => mutate()}>
            Refresh
          </Button>
        </Space>
      </div>

      {/* ── Stats Row ─────────────────────────────────── */}
      <Row gutter={[16, 16]}>
        <Col xs={12} sm={8} md={4}>
          <C2Panel title="PENDING" status={stats.pending > 0 ? 'warn' : 'ok'}>
            <DataReadout label="" value={stats.pending} valueColor={colors.status.warning} />
          </C2Panel>
        </Col>
        <Col xs={12} sm={8} md={4}>
          <C2Panel title="CRITICAL PENDING" status={stats.critical > 0 ? 'error' : undefined}>
            <DataReadout label="" value={stats.critical} valueColor={colors.severity.critical} />
          </C2Panel>
        </Col>
        <Col xs={12} sm={8} md={4}>
          <C2Panel title="HIGH PENDING">
            <DataReadout label="" value={stats.high} valueColor={colors.severity.high} />
          </C2Panel>
        </Col>
        <Col xs={12} sm={8} md={4}>
          <C2Panel title="APPROVED">
            <DataReadout label="" value={stats.approved} valueColor={colors.status.success} />
          </C2Panel>
        </Col>
        <Col xs={12} sm={8} md={4}>
          <C2Panel title="DENIED">
            <DataReadout label="" value={stats.denied} valueColor={colors.status.error} />
          </C2Panel>
        </Col>
        <Col xs={12} sm={8} md={4}>
          <C2Panel title="EXPIRED">
            <DataReadout label="" value={stats.expired} valueColor={colors.text.muted} />
          </C2Panel>
        </Col>
      </Row>

      {/* ── Table ─────────────────────────────────────── */}
      <C2Panel
        title="AGENT ACTION REQUESTS"
        style={{ flex: 1, display: 'flex', flexDirection: 'column' }}
        bodyStyle={{ flex: 1, padding: 0, overflow: 'auto' }}
      >
        {isLoading ? (
          <Spin style={{ display: 'block', margin: '40px auto' }} />
        ) : !approvals || approvals.length === 0 ? (
          <Empty
            description={
              filterTab === 'pending'
                ? 'No pending approvals. Agents are waiting for tasks.'
                : 'No approval records found.'
            }
            style={{ padding: 40 }}
          />
        ) : (
          <Table
            dataSource={approvals}
            columns={columns}
            rowKey="approval_id"
            size="small"
            pagination={{ pageSize: 20, showSizeChanger: true, size: 'small' }}
            scroll={{ x: 1000 }}
            rowClassName={(record) =>
              record.status === 'pending' && record.risk_level === 'critical'
                ? 'approval-row--critical'
                : record.status === 'pending' && record.risk_level === 'high'
                  ? 'approval-row--high'
                  : ''
            }
            expandable={{
              expandedRowRender: (record) => (
                <div style={{ padding: '8px 16px' }}>
                  <Descriptions column={{ xs: 1, sm: 2 }} size="small" bordered style={{ marginBottom: 12 }}>
                    <Descriptions.Item label="Reason" span={2}>
                      {record.reason}
                    </Descriptions.Item>
                    <Descriptions.Item label="Agent ID">{record.agent_id}</Descriptions.Item>
                    <Descriptions.Item label="Tool">{record.tool_name}</Descriptions.Item>
                    {record.mitre_technique && (
                      <Descriptions.Item label="MITRE Technique">
                        <Tag color="volcano">{record.mitre_technique}</Tag>
                      </Descriptions.Item>
                    )}
                    {record.target_info && (
                      <Descriptions.Item label="Target">{record.target_info}</Descriptions.Item>
                    )}
                  </Descriptions>

                  <Text type="secondary" style={{ fontSize: 11, display: 'block', marginBottom: 4 }}>
                    Tool Arguments:
                  </Text>
                  <pre
                    style={{
                      background: colors.bg.tertiary,
                      border: `1px solid ${colors.border.primary}`,
                      borderRadius: 4,
                      padding: 12,
                      fontSize: 11,
                      color: colors.accent.terminal,
                      maxHeight: 200,
                      overflow: 'auto',
                      margin: 0,
                    }}
                  >
                    {JSON.stringify(record.tool_args, null, 2)}
                  </pre>
                </div>
              ),
            }}
          />
        )}
      </C2Panel>

      {/* ── Deny Modal ────────────────────────────────── */}
      <Modal
        title={
          <Space>
            <CloseCircleOutlined style={{ color: colors.status.error }} />
            <span>Deny Action</span>
          </Space>
        }
        open={denyModalOpen}
        onCancel={() => setDenyModalOpen(false)}
        onOk={() => selectedRequest && handleDeny(selectedRequest.approval_id)}
        okText="Deny Action"
        okButtonProps={{ danger: true, loading: loadingId === selectedRequest?.approval_id }}
        cancelText="Cancel"
      >
        {selectedRequest && (
          <div>
            <Descriptions column={1} size="small" style={{ marginBottom: 16 }}>
              <Descriptions.Item label="Agent">{selectedRequest.agent_name}</Descriptions.Item>
              <Descriptions.Item label="Action">{selectedRequest.action}</Descriptions.Item>
              <Descriptions.Item label="Tool">{selectedRequest.tool_name}</Descriptions.Item>
              <Descriptions.Item label="Risk">
                <Tag color={getSeverityColor(selectedRequest.risk_level)}>
                  {selectedRequest.risk_level.toUpperCase()}
                </Tag>
              </Descriptions.Item>
            </Descriptions>

            <Text type="secondary" style={{ display: 'block', marginBottom: 8 }}>
              Reason for denial (optional):
            </Text>
            <TextArea
              rows={3}
              placeholder="Provide a reason for denying this action..."
              value={denyReason}
              onChange={(e) => setDenyReason(e.target.value)}
            />
          </div>
        )}
      </Modal>
    </div>
  );
}
