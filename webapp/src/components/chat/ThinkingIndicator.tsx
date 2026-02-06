'use client';

import { Typography, Space, Tag } from 'antd';
import { LoadingOutlined, ThunderboltOutlined, ToolOutlined } from '@ant-design/icons';
import { colors } from '@/lib/theme';

const { Text } = Typography;

export interface ThinkingIndicatorProps {
  thinking: boolean;
  phase?: string;
  tool?: string;
  message?: string;
}

export function ThinkingIndicator({ thinking, phase, tool, message }: ThinkingIndicatorProps) {
  if (!thinking) return null;

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        padding: '8px 14px',
        background: colors.bg.surface,
        border: `1px solid ${colors.border.primary}`,
        borderRadius: 6,
      }}
    >
      <LoadingOutlined spin style={{ color: colors.accent.primary, fontSize: 16 }} />
      <Space size="small">
        <Text style={{ color: colors.text.secondary, fontSize: 12 }}>
          {message || 'AI is reasoning...'}
        </Text>
        {phase && (
          <Tag
            icon={<ThunderboltOutlined />}
            color="processing"
            style={{ fontSize: 10, margin: 0 }}
          >
            {phase}
          </Tag>
        )}
        {tool && (
          <Tag
            icon={<ToolOutlined />}
            color="warning"
            style={{ fontSize: 10, margin: 0 }}
          >
            {tool}
          </Tag>
        )}
      </Space>

      {/* Animated dots */}
      <span style={{ color: colors.text.muted, letterSpacing: 2, fontSize: 16 }}>
        <span className="thinking-dot" style={{ animationDelay: '0s' }}>.</span>
        <span className="thinking-dot" style={{ animationDelay: '0.2s' }}>.</span>
        <span className="thinking-dot" style={{ animationDelay: '0.4s' }}>.</span>
      </span>

      <style jsx>{`
        @keyframes blink {
          0%, 20% { opacity: 0; }
          50% { opacity: 1; }
          100% { opacity: 0; }
        }
        .thinking-dot {
          animation: blink 1.4s infinite;
        }
      `}</style>
    </div>
  );
}
