'use client';

import { Typography, Tooltip } from 'antd';
import { CheckCircleFilled, SyncOutlined, ClockCircleOutlined } from '@ant-design/icons';
import { colors } from '@/lib/theme';

const { Text } = Typography;

export interface PhaseInfo {
  name: string;
  label: string;
  status: 'completed' | 'active' | 'pending';
}

export interface AttackProgressProps {
  phases: PhaseInfo[];
  currentPhase?: string;
}

const STATUS_STYLES: Record<string, { color: string; bg: string; border: string; icon: React.ReactNode }> = {
  completed: {
    color: colors.status.success,
    bg: colors.status.success + '20',
    border: colors.status.success + '44',
    icon: <CheckCircleFilled style={{ fontSize: 14 }} />,
  },
  active: {
    color: colors.accent.primary,
    bg: colors.accent.primary + '20',
    border: colors.accent.primary,
    icon: <SyncOutlined spin style={{ fontSize: 14 }} />,
  },
  pending: {
    color: colors.text.muted,
    bg: 'transparent',
    border: colors.border.primary,
    icon: <ClockCircleOutlined style={{ fontSize: 14 }} />,
  },
};

export function AttackProgress({ phases, currentPhase }: AttackProgressProps) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 0, overflowX: 'auto', padding: '4px 0' }}>
      {phases.map((phase, idx) => {
        const isActive = currentPhase ? phase.name === currentPhase : phase.status === 'active';
        const effectiveStatus = isActive ? 'active' : phase.status;
        const style = STATUS_STYLES[effectiveStatus] ?? STATUS_STYLES.pending;

        return (
          <div key={phase.name} style={{ display: 'flex', alignItems: 'center' }}>
            <Tooltip title={`${phase.label} — ${effectiveStatus}`}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '6px 14px',
                  borderRadius: 20,
                  border: `1px solid ${style.border}`,
                  background: style.bg,
                  whiteSpace: 'nowrap',
                }}
              >
                <span style={{ color: style.color }}>{style.icon}</span>
                <Text style={{ color: style.color, fontSize: 12, fontWeight: isActive ? 600 : 400 }}>
                  {phase.label}
                </Text>
              </div>
            </Tooltip>

            {/* Connector line */}
            {idx < phases.length - 1 && (
              <div
                style={{
                  width: 24,
                  height: 1,
                  background: phase.status === 'completed' ? colors.status.success + '66' : colors.border.primary,
                  flexShrink: 0,
                }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
