'use client';

import { Tag, Typography, Progress } from 'antd';
import { ToolOutlined, CheckCircleOutlined, CloseCircleOutlined, LoadingOutlined } from '@ant-design/icons';
import { colors } from '@/lib/theme';

const { Text, Paragraph } = Typography;

export type ToolStatus = 'running' | 'success' | 'error' | 'pending';

export interface ToolExecutionProps {
  toolName: string;
  status: ToolStatus;
  output?: string;
  duration?: number;   // ms
  progress?: number;   // 0-100
}

const STATUS_CONFIG: Record<ToolStatus, { color: string; icon: React.ReactNode; label: string }> = {
  pending: { color: colors.text.muted, icon: <ToolOutlined />, label: 'Pending' },
  running: { color: colors.status.info, icon: <LoadingOutlined spin />, label: 'Running' },
  success: { color: colors.status.success, icon: <CheckCircleOutlined />, label: 'Complete' },
  error: { color: colors.status.error, icon: <CloseCircleOutlined />, label: 'Failed' },
};

export function ToolExecution({ toolName, status, output, duration, progress }: ToolExecutionProps) {
  const config = STATUS_CONFIG[status];

  return (
    <div
      style={{
        padding: '10px 14px',
        background: colors.bg.surface,
        border: `1px solid ${colors.border.primary}`,
        borderLeft: `3px solid ${config.color}`,
        borderRadius: 4,
        marginBottom: 8,
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ color: config.color }}>{config.icon}</span>
          <Text strong style={{ color: colors.text.primary, fontFamily: 'monospace', fontSize: 13 }}>
            {toolName}
          </Text>
          <Tag
            color={status === 'success' ? 'success' : status === 'error' ? 'error' : status === 'running' ? 'processing' : 'default'}
            style={{ fontSize: 10, margin: 0 }}
          >
            {config.label}
          </Tag>
        </div>
        {duration !== undefined && (
          <Text style={{ color: colors.text.muted, fontSize: 11 }}>
            {duration < 1000 ? `${duration}ms` : `${(duration / 1000).toFixed(1)}s`}
          </Text>
        )}
      </div>

      {/* Progress bar */}
      {status === 'running' && progress !== undefined && (
        <Progress percent={progress} size="small" strokeColor={colors.accent.primary} style={{ marginBottom: 6 }} />
      )}

      {/* Output */}
      {output && (
        <div
          style={{
            background: colors.bg.primary,
            padding: '6px 10px',
            borderRadius: 4,
            maxHeight: 120,
            overflowY: 'auto',
            marginTop: 4,
          }}
        >
          <Paragraph
            style={{
              color: colors.text.secondary,
              fontFamily: 'monospace',
              fontSize: 11,
              margin: 0,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
            }}
          >
            {output}
          </Paragraph>
        </div>
      )}
    </div>
  );
}
