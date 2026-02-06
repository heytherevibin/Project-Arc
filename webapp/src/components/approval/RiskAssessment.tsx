'use client';

import { Tag, Typography, Tooltip } from 'antd';
import { WarningOutlined, ThunderboltOutlined, AimOutlined } from '@ant-design/icons';
import { colors } from '@/lib/theme';

const { Text, Paragraph } = Typography;

export interface RiskAssessmentProps {
  riskLevel: string;
  blastRadius?: number;
  mitreTechnique?: string;
  description: string;
}

const RISK_DISPLAY: Record<string, { color: string; bg: string; label: string }> = {
  critical: { color: colors.severity.critical, bg: colors.severity.critical + '15', label: 'CRITICAL' },
  high:     { color: colors.severity.high, bg: colors.severity.high + '15', label: 'HIGH' },
  medium:   { color: colors.severity.medium, bg: colors.severity.medium + '15', label: 'MEDIUM' },
  low:      { color: colors.severity.low, bg: colors.severity.low + '15', label: 'LOW' },
};

export function RiskAssessment({
  riskLevel,
  blastRadius,
  mitreTechnique,
  description,
}: RiskAssessmentProps) {
  const display = RISK_DISPLAY[riskLevel] ?? RISK_DISPLAY.medium;

  return (
    <div
      style={{
        padding: '14px 18px',
        background: display.bg,
        border: `1px solid ${display.color}33`,
        borderRadius: 8,
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <WarningOutlined style={{ color: display.color, fontSize: 18 }} />
        <Text strong style={{ color: display.color, fontSize: 14 }}>
          Risk Assessment: {display.label}
        </Text>
      </div>

      {/* Description */}
      <Paragraph style={{ color: colors.text.primary, margin: '0 0 12px', fontSize: 13 }}>
        {description}
      </Paragraph>

      {/* Metrics */}
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        {blastRadius !== undefined && (
          <Tooltip title="Number of assets potentially affected">
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <ThunderboltOutlined style={{ color: colors.status.warning }} />
              <Text style={{ color: colors.text.secondary, fontSize: 12 }}>
                Blast radius: <strong style={{ color: colors.text.primary }}>{blastRadius}</strong> assets
              </Text>
            </div>
          </Tooltip>
        )}

        {mitreTechnique && (
          <Tooltip title="MITRE ATT&CK technique">
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <AimOutlined style={{ color: colors.status.info }} />
              <Tag style={{ margin: 0, fontSize: 11 }}>{mitreTechnique}</Tag>
            </div>
          </Tooltip>
        )}
      </div>
    </div>
  );
}
