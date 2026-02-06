'use client';

import { Tooltip, Typography } from 'antd';
import { colors } from '@/lib/theme';

const { Text } = Typography;

export interface HeatmapData {
  label: string;
  count: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export interface RiskHeatmapProps {
  data: HeatmapData[];
  title?: string;
  columns?: number;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: colors.severity.critical,
  high: colors.severity.high,
  medium: colors.severity.medium,
  low: colors.severity.low,
  info: colors.status.info,
};

export function RiskHeatmap({ data, title, columns = 4 }: RiskHeatmapProps) {
  const maxCount = Math.max(...data.map((d) => d.count), 1);

  return (
    <div>
      {title && (
        <Text style={{ color: colors.text.secondary, fontSize: 12, display: 'block', marginBottom: 10 }}>
          {title}
        </Text>
      )}

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: `repeat(${columns}, 1fr)`,
          gap: 6,
        }}
      >
        {data.map((item) => {
          const baseColor = SEVERITY_COLORS[item.severity] ?? colors.text.muted;
          const intensity = Math.max(0.15, item.count / maxCount);
          const bg = `${baseColor}${Math.round(intensity * 255).toString(16).padStart(2, '0')}`;

          return (
            <Tooltip key={item.label} title={`${item.label}: ${item.count}`}>
              <div
                style={{
                  background: bg,
                  border: `1px solid ${baseColor}33`,
                  borderRadius: 4,
                  padding: '10px 8px',
                  textAlign: 'center',
                  cursor: 'default',
                  transition: 'transform 0.15s',
                }}
                onMouseEnter={(e) => { e.currentTarget.style.transform = 'scale(1.05)'; }}
                onMouseLeave={(e) => { e.currentTarget.style.transform = 'scale(1)'; }}
              >
                <Text
                  strong
                  style={{ color: baseColor, fontSize: 18, display: 'block', lineHeight: 1 }}
                >
                  {item.count}
                </Text>
                <Text style={{ color: colors.text.secondary, fontSize: 10, display: 'block', marginTop: 4 }}>
                  {item.label}
                </Text>
              </div>
            </Tooltip>
          );
        })}
      </div>
    </div>
  );
}
