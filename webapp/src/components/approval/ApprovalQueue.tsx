'use client';

import { Button, Tag, Typography, Space, Empty } from 'antd';
import { CheckOutlined, CloseOutlined, ExclamationCircleOutlined } from '@ant-design/icons';
import { colors } from '@/lib/theme';

const { Text, Paragraph } = Typography;

export interface ApprovalRequest {
  id: string;
  type: string;
  description: string;
  risk_level: string;
  from_phase?: string;
  to_phase?: string;
  details?: Record<string, unknown>;
  timestamp?: string;
}

export interface ApprovalQueueProps {
  requests: ApprovalRequest[];
  onApprove: (id: string) => void;
  onDeny: (id: string) => void;
  loading?: boolean;
}

const RISK_COLORS: Record<string, string> = {
  critical: colors.severity.critical,
  high: colors.severity.high,
  medium: colors.severity.medium,
  low: colors.severity.low,
};

export function ApprovalQueue({ requests, onApprove, onDeny, loading }: ApprovalQueueProps) {
  if (requests.length === 0) {
    return (
      <Empty
        description={<Text style={{ color: colors.text.muted }}>No pending approvals</Text>}
        style={{ padding: 40 }}
      />
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {requests.map((req) => (
        <div
          key={req.id}
          style={{
            padding: '14px 18px',
            background: colors.bg.surface,
            border: `1px solid ${colors.border.primary}`,
            borderLeft: `3px solid ${RISK_COLORS[req.risk_level] ?? colors.border.primary}`,
            borderRadius: 6,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
            <div>
              <Space size="small">
                <ExclamationCircleOutlined style={{ color: RISK_COLORS[req.risk_level] ?? colors.status.warning }} />
                <Text strong style={{ color: colors.text.primary, fontSize: 14 }}>
                  {req.type.replace(/_/g, ' ').toUpperCase()}
                </Text>
                <Tag color={req.risk_level === 'critical' ? 'error' : req.risk_level === 'high' ? 'warning' : 'default'}>
                  {req.risk_level}
                </Tag>
              </Space>
            </div>
            {req.timestamp && (
              <Text style={{ color: colors.text.muted, fontSize: 11 }}>
                {new Date(req.timestamp).toLocaleTimeString()}
              </Text>
            )}
          </div>

          <Paragraph style={{ color: colors.text.secondary, margin: '8px 0', fontSize: 13 }}>
            {req.description}
          </Paragraph>

          {req.from_phase && req.to_phase && (
            <div style={{ marginBottom: 8 }}>
              <Tag>{req.from_phase}</Tag>
              <span style={{ color: colors.text.muted }}> → </span>
              <Tag color="blue">{req.to_phase}</Tag>
            </div>
          )}

          <Space>
            <Button
              type="primary"
              size="small"
              icon={<CheckOutlined />}
              onClick={() => onApprove(req.id)}
              loading={loading}
              style={{ background: colors.status.success, borderColor: colors.status.success }}
            >
              Approve
            </Button>
            <Button
              danger
              size="small"
              icon={<CloseOutlined />}
              onClick={() => onDeny(req.id)}
              loading={loading}
            >
              Deny
            </Button>
          </Space>
        </div>
      ))}
    </div>
  );
}
