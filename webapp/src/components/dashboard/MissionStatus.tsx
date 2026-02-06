'use client';

import { Tag, Typography, Progress, Space } from 'antd';
import { RocketOutlined, ClockCircleOutlined, CheckCircleOutlined } from '@ant-design/icons';
import { colors } from '@/lib/theme';

const { Text } = Typography;

export interface MissionSummary {
  mission_id: string;
  name?: string;
  status: string;
  current_phase: string;
  progress?: number;
  target: string;
  started_at?: string;
  vulns_found?: number;
  hosts_discovered?: number;
}

export interface MissionStatusProps {
  mission: MissionSummary;
  onClick?: () => void;
}

const STATUS_COLOR: Record<string, string> = {
  running: colors.status.info,
  completed: colors.status.success,
  paused: colors.status.warning,
  failed: colors.status.error,
  pending: colors.text.muted,
};

export function MissionStatus({ mission, onClick }: MissionStatusProps) {
  const statusColor = STATUS_COLOR[mission.status] ?? colors.text.muted;

  return (
    <div
      onClick={onClick}
      style={{
        padding: '14px 18px',
        background: colors.bg.surface,
        border: `1px solid ${colors.border.primary}`,
        borderRadius: 8,
        cursor: onClick ? 'pointer' : 'default',
        transition: 'border-color 0.2s',
      }}
      onMouseEnter={(e) => { if (onClick) e.currentTarget.style.borderColor = colors.border.focus; }}
      onMouseLeave={(e) => { e.currentTarget.style.borderColor = colors.border.primary; }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <Space size="small">
          <RocketOutlined style={{ color: colors.accent.primary }} />
          <Text strong style={{ color: colors.text.primary, fontSize: 14 }}>
            {mission.name || mission.mission_id}
          </Text>
        </Space>
        <Tag color={mission.status === 'running' ? 'processing' : mission.status === 'completed' ? 'success' : 'default'}>
          {mission.status}
        </Tag>
      </div>

      <Text style={{ color: colors.text.muted, fontSize: 12, display: 'block', marginBottom: 8 }}>
        Target: <span style={{ color: colors.text.secondary }}>{mission.target}</span>
      </Text>

      {/* Phase */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <Text style={{ color: colors.text.muted, fontSize: 11 }}>Phase:</Text>
        <Tag color="blue" style={{ margin: 0, fontSize: 11 }}>
          {mission.current_phase.replace(/_/g, ' ')}
        </Tag>
      </div>

      {/* Progress */}
      {mission.progress !== undefined && (
        <Progress
          percent={mission.progress}
          size="small"
          strokeColor={statusColor}
          trailColor={colors.border.primary}
          style={{ marginBottom: 8 }}
        />
      )}

      {/* Stats */}
      <div style={{ display: 'flex', gap: 16 }}>
        {mission.hosts_discovered !== undefined && (
          <Text style={{ color: colors.text.muted, fontSize: 11 }}>
            Hosts: <span style={{ color: colors.text.primary }}>{mission.hosts_discovered}</span>
          </Text>
        )}
        {mission.vulns_found !== undefined && (
          <Text style={{ color: colors.text.muted, fontSize: 11 }}>
            Vulns: <span style={{ color: colors.severity.high }}>{mission.vulns_found}</span>
          </Text>
        )}
        {mission.started_at && (
          <Text style={{ color: colors.text.muted, fontSize: 11 }}>
            <ClockCircleOutlined /> {new Date(mission.started_at).toLocaleString()}
          </Text>
        )}
      </div>
    </div>
  );
}
