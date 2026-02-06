'use client';

import { useState, useRef, useEffect } from 'react';
import { Input, Button, Typography, Space, Avatar, Spin } from 'antd';
import { SendOutlined, RobotOutlined, UserOutlined } from '@ant-design/icons';
import { colors } from '@/lib/theme';

const { Text } = Typography;

export interface ChatMessage {
  id: string;
  role: 'user' | 'agent' | 'system';
  content: string;
  timestamp?: string;
  agent_id?: string;
  tool_name?: string;
}

export interface AgentChatProps {
  messages: ChatMessage[];
  onSend: (message: string) => void;
  loading?: boolean;
  placeholder?: string;
  suggestions?: string[];
}

export function AgentChat({
  messages,
  onSend,
  loading = false,
  placeholder = 'Type a command or question...',
  suggestions,
}: AgentChatProps) {
  const [input, setInput] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = () => {
    const trimmed = input.trim();
    if (!trimmed) return;
    onSend(trimmed);
    setInput('');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Messages */}
      <div
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '12px 16px',
          display: 'flex',
          flexDirection: 'column',
          gap: 12,
        }}
      >
        {messages.map((msg) => (
          <div
            key={msg.id}
            style={{
              display: 'flex',
              gap: 10,
              flexDirection: msg.role === 'user' ? 'row-reverse' : 'row',
              alignItems: 'flex-start',
            }}
          >
            <Avatar
              size="small"
              icon={msg.role === 'user' ? <UserOutlined /> : <RobotOutlined />}
              style={{
                backgroundColor:
                  msg.role === 'user' ? colors.accent.primary : colors.bg.elevated,
                flexShrink: 0,
              }}
            />
            <div
              style={{
                maxWidth: '75%',
                padding: '8px 12px',
                borderRadius: 8,
                background: msg.role === 'user' ? colors.accent.primary + '22' : colors.bg.surface,
                border: `1px solid ${msg.role === 'user' ? colors.accent.primary + '44' : colors.border.primary}`,
              }}
            >
              {msg.agent_id && (
                <Text style={{ fontSize: 10, color: colors.accent.secondary, display: 'block', marginBottom: 2 }}>
                  {msg.agent_id}
                </Text>
              )}
              <Text style={{ color: colors.text.primary, fontSize: 13, whiteSpace: 'pre-wrap' }}>
                {msg.content}
              </Text>
              {msg.timestamp && (
                <Text style={{ fontSize: 10, color: colors.text.muted, display: 'block', marginTop: 4 }}>
                  {new Date(msg.timestamp).toLocaleTimeString()}
                </Text>
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <Avatar size="small" icon={<RobotOutlined />} style={{ backgroundColor: colors.bg.elevated }} />
            <Spin size="small" />
            <Text style={{ color: colors.text.muted, fontSize: 12 }}>Thinking...</Text>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Suggestions */}
      {suggestions && suggestions.length > 0 && messages.length === 0 && (
        <div style={{ padding: '4px 16px', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {suggestions.map((s) => (
            <Button
              key={s}
              size="small"
              onClick={() => onSend(s)}
              style={{
                fontSize: 11,
                color: colors.text.secondary,
                borderColor: colors.border.primary,
                background: colors.bg.surface,
              }}
            >
              {s}
            </Button>
          ))}
        </div>
      )}

      {/* Input */}
      <div
        style={{
          padding: '12px 16px',
          borderTop: `1px solid ${colors.border.primary}`,
          display: 'flex',
          gap: 8,
        }}
      >
        <Input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onPressEnter={handleSend}
          placeholder={placeholder}
          disabled={loading}
          style={{
            background: colors.bg.surface,
            borderColor: colors.border.primary,
            color: colors.text.primary,
          }}
        />
        <Button
          type="primary"
          icon={<SendOutlined />}
          onClick={handleSend}
          disabled={!input.trim() || loading}
        />
      </div>
    </div>
  );
}
