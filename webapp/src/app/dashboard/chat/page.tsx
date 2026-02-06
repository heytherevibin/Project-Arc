'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import { Typography, Input, Button, Space, App, Empty, Spin } from 'antd';
import { SendOutlined, RobotOutlined, UserOutlined, BulbOutlined } from '@ant-design/icons';
import { api } from '@/lib/api';
import { useAppStore } from '@/store/provider';
import { colors } from '@/lib/theme';
import { C2Panel, CommandBar } from '@/components/c2';
import type { ChatMessage, ChatResponse } from '@/types';

const { Title, Text, Paragraph } = Typography;

export default function ChatPage() {
  const currentProject = useAppStore((s) => s.currentProject);
  const { message: antMessage } = App.useApp();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [suggestions, setSuggestions] = useState<string[]>([
    'Scan a target domain',
    'List discovered vulnerabilities',
    'Plan an attack strategy',
    'What tools are available?',
  ]);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages]);

  const sendMessage = useCallback(async (text?: string) => {
    const content = (text || input).trim();
    if (!content) return;

    const userMsg: ChatMessage = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content,
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const resp = await api.post<ChatResponse>('/api/v1/agents/chat', {
        message: content,
        project_id: currentProject?.project_id || null,
      });

      const assistantMsg: ChatMessage = {
        id: `msg-${Date.now()}-resp`,
        role: 'assistant',
        content: resp.response,
        timestamp: new Date().toISOString(),
        agent_id: resp.agent_id,
        suggestions: resp.suggestions,
      };
      setMessages((prev) => [...prev, assistantMsg]);
      if (resp.suggestions?.length) setSuggestions(resp.suggestions);
    } catch (err: any) {
      antMessage.error(err?.message || 'Failed to get response');
      setMessages((prev) => [...prev, {
        id: `msg-${Date.now()}-err`,
        role: 'assistant',
        content: 'Sorry, I encountered an error. Please try again.',
        timestamp: new Date().toISOString(),
        agent_id: 'system',
      }]);
    } finally {
      setLoading(false);
    }
  }, [input, currentProject, antMessage]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: 16 }}>
      <CommandBar>
        <Title level={3} style={{ margin: 0, color: colors.text.primary }}>AI Operator</Title>
        <Text style={{ color: colors.text.secondary, fontSize: 12 }}>
          {currentProject ? `Project: ${currentProject.name}` : 'No project selected'}
        </Text>
      </CommandBar>

      <div style={{ display: 'flex', gap: 16, flex: 1, minHeight: 0, flexWrap: 'wrap' }}>
        <C2Panel title="Chat" style={{ flex: 1, minWidth: 'min(400px, 100%)', display: 'flex', flexDirection: 'column' }}>
          <div ref={scrollRef} style={{
            flex: 1, overflowY: 'auto', padding: '12px 0',
            display: 'flex', flexDirection: 'column', gap: 16,
            minHeight: 300, maxHeight: 'calc(100vh - 380px)',
          }}>
            {messages.length === 0 && (
              <Empty
                image={<RobotOutlined style={{ fontSize: 48, color: colors.accent.primary }} />}
                description={
                  <div>
                    <Text style={{ color: colors.text.secondary }}>
                      Start a conversation with the Arc AI operator.
                    </Text>
                    <br />
                    <Text style={{ color: colors.text.secondary, fontSize: 12 }}>
                      Ask about targets, plan attacks, or get help with tools.
                    </Text>
                  </div>
                }
              />
            )}
            {messages.map((msg) => (
              <div key={msg.id} style={{
                display: 'flex', gap: 10,
                justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start',
              }}>
                {msg.role === 'assistant' && (
                  <div style={{
                    width: 32, height: 32, borderRadius: '50%',
                    background: colors.accent.primary, display: 'flex',
                    alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                  }}>
                    <RobotOutlined style={{ color: colors.bg.primary, fontSize: 16 }} />
                  </div>
                )}
                <div style={{
                  maxWidth: '75%', padding: '10px 14px', borderRadius: 8,
                  background: msg.role === 'user' ? colors.accent.primary : colors.bg.secondary,
                  color: msg.role === 'user' ? colors.bg.primary : colors.text.primary,
                }}>
                  <Paragraph style={{
                    margin: 0, whiteSpace: 'pre-wrap',
                    color: msg.role === 'user' ? colors.bg.primary : colors.text.primary,
                    fontSize: 13,
                  }}>
                    {msg.content}
                  </Paragraph>
                  <Text style={{
                    fontSize: 10, opacity: 0.6,
                    color: msg.role === 'user' ? colors.bg.primary : colors.text.secondary,
                  }}>
                    {new Date(msg.timestamp).toLocaleTimeString()}
                    {msg.agent_id && ` · ${msg.agent_id}`}
                  </Text>
                </div>
                {msg.role === 'user' && (
                  <div style={{
                    width: 32, height: 32, borderRadius: '50%',
                    background: colors.bg.tertiary, display: 'flex',
                    alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                  }}>
                    <UserOutlined style={{ color: colors.text.primary, fontSize: 14 }} />
                  </div>
                )}
              </div>
            ))}
            {loading && (
              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <div style={{
                  width: 32, height: 32, borderRadius: '50%',
                  background: colors.accent.primary, display: 'flex',
                  alignItems: 'center', justifyContent: 'center',
                }}>
                  <RobotOutlined style={{ color: colors.bg.primary, fontSize: 16 }} />
                </div>
                <Spin size="small" />
                <Text style={{ color: colors.text.secondary, fontSize: 12 }}>Thinking...</Text>
              </div>
            )}
          </div>

          <div style={{ borderTop: `1px solid ${colors.border.primary}`, paddingTop: 12, marginTop: 8 }}>
            <div style={{ display: 'flex', gap: 8 }}>
              <Input.TextArea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask the AI operator..."
                autoSize={{ minRows: 1, maxRows: 4 }}
                style={{ flex: 1 }}
                disabled={loading}
              />
              <Button
                type="primary"
                icon={<SendOutlined />}
                onClick={() => sendMessage()}
                loading={loading}
                disabled={!input.trim()}
              />
            </div>
          </div>
        </C2Panel>

        <C2Panel title="Suggestions" style={{ width: 260, flexShrink: 0 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {suggestions.map((s, i) => (
              <Button
                key={i}
                type="text"
                size="small"
                icon={<BulbOutlined />}
                onClick={() => sendMessage(s)}
                style={{
                  textAlign: 'left', whiteSpace: 'normal', height: 'auto',
                  padding: '6px 8px', color: colors.text.primary,
                }}
              >
                {s}
              </Button>
            ))}
          </div>
        </C2Panel>
      </div>
    </div>
  );
}
