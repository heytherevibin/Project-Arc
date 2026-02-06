'use client';

import { useState, useEffect } from 'react';
import {
  Typography,
  Form,
  Input,
  Button,
  App,
  Space,
  Descriptions,
  Tag,
  Row,
  Col,
  Checkbox,
} from 'antd';
import { useAuthStore, useAppStore } from '@/store/provider';
import { api, getMcpHealth, type McpEndpointStatus } from '@/lib/api';
import { C2Panel, IndicatorLight } from '@/components/c2';

const { Text, Paragraph } = Typography;

const PIPELINE_TOOL_OPTIONS: { id: string; label: string }[] = [
  { id: 'whois', label: 'Whois' },
  { id: 'gau', label: 'GAU (URL discovery)' },
  { id: 'wappalyzer', label: 'Wappalyzer' },
  { id: 'shodan', label: 'Shodan' },
  { id: 'knockpy', label: 'Knockpy (subdomain brute-force)' },
  { id: 'kiterunner', label: 'Kiterunner (API discovery)' },
  { id: 'github_recon', label: 'GitHub recon' },
];

interface PasswordChange {
  current_password: string;
  new_password: string;
  confirm_password: string;
}

/**
 * Settings page — Sentinel-style layout: left sidebar (system/status), main grid (cards).
 */
export default function SettingsPage() {
  const { message } = App.useApp();
  const [loading, setLoading] = useState(false);
  const [mcpLoading, setMcpLoading] = useState(false);
  const [mcpEndpoints, setMcpEndpoints] = useState<McpEndpointStatus[] | null>(null);
  const [pipelineTools, setPipelineTools] = useState<string[]>([]);
  const [pipelineToolsLoading, setPipelineToolsLoading] = useState(false);
  const [pipelineToolsSaving, setPipelineToolsSaving] = useState(false);
  const [passwordForm] = Form.useForm();

  const user = useAuthStore((state) => state.user);
  const wsConnected = useAppStore((state) => state.wsConnected);

  useEffect(() => {
    let cancelled = false;
    setPipelineToolsLoading(true);
    api.get<{ tools: string[] }>('/api/v1/settings/pipeline-tools')
      .then((res) => {
        if (!cancelled) setPipelineTools(res.tools ?? []);
      })
      .catch(() => {
        if (!cancelled) setPipelineTools(['whois', 'gau', 'wappalyzer', 'shodan']);
      })
      .finally(() => {
        if (!cancelled) setPipelineToolsLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  const handleCheckMcp = async () => {
    setMcpLoading(true);
    setMcpEndpoints(null);
    try {
      const res = await getMcpHealth();
      setMcpEndpoints(res.endpoints);
      const healthy = res.endpoints.filter((e) => e.status === 'healthy').length;
      message.success(`${healthy}/${res.endpoints.length} MCP endpoints healthy`);
    } catch (e: unknown) {
      message.error(e instanceof Error ? e.message : 'MCP check failed');
      setMcpEndpoints([]);
    } finally {
      setMcpLoading(false);
    }
  };

  const handlePipelineToolToggle = (id: string, checked: boolean) => {
    if (checked) {
      setPipelineTools((prev) => (prev.includes(id) ? prev : [...prev, id]));
    } else {
      setPipelineTools((prev) => prev.filter((t) => t !== id));
    }
  };

  const handleSavePipelineTools = async () => {
    setPipelineToolsSaving(true);
    try {
      await api.put('/api/v1/settings/pipeline-tools', { tools: pipelineTools });
      message.success('Pipeline tools saved');
    } catch (e: unknown) {
      message.error(e instanceof Error ? e.message : 'Failed to save');
    } finally {
      setPipelineToolsSaving(false);
    }
  };

  const handleChangePassword = async (values: PasswordChange) => {
    if (values.new_password !== values.confirm_password) {
      message.error('Passwords do not match');
      return;
    }
    setLoading(true);
    try {
      await api.post('/api/v1/auth/change-password', {
        current_password: values.current_password,
        new_password: values.new_password,
      });
      message.success('Password changed successfully');
      passwordForm.resetFields();
    } catch (error: unknown) {
      message.error(error instanceof Error ? error.message : 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="settings-page">
      <div className="settings-page__grid">
        {/* Left sidebar — system / connection (Sentinel: 3–4 cols) */}
        <aside className="settings-page__sidebar">
          <C2Panel title="SYSTEM" status={wsConnected ? 'ok' : 'error'}>
            <Descriptions column={1} size="small">
              <Descriptions.Item label="WebSocket">
                <Space size="small">
                  <IndicatorLight status={wsConnected ? 'ok' : 'error'} />
                  <Text type={wsConnected ? 'success' : 'danger'}>
                    {wsConnected ? 'Connected' : 'Disconnected'}
                  </Text>
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label="API">
                <Text type="secondary" style={{ wordBreak: 'break-all' }}>
                  {process.env.NEXT_PUBLIC_API_URL ?? '—'}
                </Text>
              </Descriptions.Item>
            </Descriptions>
          </C2Panel>

          <C2Panel title="ABOUT" style={{ marginTop: 16 }}>
            <Paragraph type="secondary" style={{ marginBottom: 12, fontSize: 11 }}>
              Enterprise autonomous AI red team framework for reconnaissance, vulnerability discovery, and penetration testing.
            </Paragraph>
            <Descriptions column={1} size="small">
              <Descriptions.Item label="Version">0.1.0</Descriptions.Item>
              <Descriptions.Item label="Env">{process.env.NODE_ENV}</Descriptions.Item>
            </Descriptions>
          </C2Panel>
        </aside>

        {/* Main content — cards in 12-col grid (Sentinel: 8–9 cols, two tiers) */}
        <main className="settings-page__main">
          {/* Tier 1: Profile (connection is in sidebar SYSTEM card) */}
          <Row gutter={[16, 16]}>
            <Col span={24}>
              <C2Panel title="PROFILE">
                <Descriptions column={1} size="small">
                  <Descriptions.Item label="Email">{user?.email || '—'}</Descriptions.Item>
                  <Descriptions.Item label="User ID">
                    <Text copyable type="secondary" style={{ fontSize: 11 }}>
                      {user?.user_id || '—'}
                    </Text>
                  </Descriptions.Item>
                  <Descriptions.Item label="Roles">{user?.roles?.join(', ') || '—'}</Descriptions.Item>
                </Descriptions>
              </C2Panel>
            </Col>
          </Row>

          {/* Tier 2: Security (full width) */}
          <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
            <Col span={24}>
              <C2Panel title="SECURITY">
                <Form
                  form={passwordForm}
                  layout="vertical"
                  onFinish={handleChangePassword}
                  style={{ maxWidth: 400 }}
                >
                  <Form.Item name="current_password" label="Current Password" rules={[{ required: true, message: 'Required' }]}>
                    <Input.Password placeholder="••••••••" />
                  </Form.Item>
                  <Form.Item
                    name="new_password"
                    label="New Password"
                    rules={[
                      { required: true, message: 'Required' },
                      { min: 8, message: 'Minimum 8 characters' },
                    ]}
                  >
                    <Input.Password placeholder="••••••••" />
                  </Form.Item>
                  <Form.Item
                    name="confirm_password"
                    label="Confirm New Password"
                    rules={[
                      { required: true, message: 'Required' },
                      ({ getFieldValue }) => ({
                        validator(_, value) {
                          if (!value || getFieldValue('new_password') === value) return Promise.resolve();
                          return Promise.reject(new Error('Passwords do not match'));
                        },
                      }),
                    ]}
                  >
                    <Input.Password placeholder="••••••••" />
                  </Form.Item>
                  <Form.Item>
                    <Button type="primary" htmlType="submit" loading={loading}>
                      Change Password
                    </Button>
                  </Form.Item>
                </Form>
              </C2Panel>
            </Col>
          </Row>

          {/* Tier 3: Pipeline tools + MCP servers (side by side) */}
          <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
            <Col xs={24} lg={12}>
              <C2Panel title="PIPELINE EXTENDED TOOLS">
                <Paragraph type="secondary" style={{ marginBottom: 16, fontSize: 11 }}>
                  Choose which extended recon tools run during a full scan. Only tools with a configured MCP URL will execute.
                </Paragraph>
                {pipelineToolsLoading ? (
                  <Text type="secondary">Loading…</Text>
                ) : (
                  <Space direction="vertical" style={{ width: '100%' }}>
                    {PIPELINE_TOOL_OPTIONS.map((opt) => (
                      <Checkbox
                        key={opt.id}
                        checked={pipelineTools.includes(opt.id)}
                        onChange={(e) => handlePipelineToolToggle(opt.id, e.target.checked)}
                      >
                        {opt.label}
                      </Checkbox>
                    ))}
                    <Button type="primary" onClick={handleSavePipelineTools} loading={pipelineToolsSaving} style={{ marginTop: 8 }}>
                      Save pipeline tools
                    </Button>
                  </Space>
                )}
              </C2Panel>
            </Col>
            <Col xs={24} lg={12}>
              <C2Panel title="MCP TOOL SERVERS">
                <Paragraph type="secondary" style={{ marginBottom: 16, fontSize: 11 }}>
                  Check that each MCP recon URL is reachable and returns a healthy status.
                </Paragraph>
                <Space direction="vertical" style={{ width: '100%' }}>
                  <Button type="primary" onClick={handleCheckMcp} loading={mcpLoading}>
                    Check MCP URLs
                  </Button>
                  {mcpEndpoints !== null && (
                    <Descriptions column={1} size="small" bordered style={{ marginTop: 8 }}>
                      {mcpEndpoints.map((e) => (
                        <Descriptions.Item key={e.name} label={e.name}>
                          <Space wrap size="small">
                            <Tag color={e.status === 'healthy' ? 'green' : 'red'}>{e.status}</Tag>
                            {e.url && <Text type="secondary" style={{ fontSize: 10 }}>{e.url}</Text>}
                            {e.latency_ms != null && <Text type="secondary">{e.latency_ms} ms</Text>}
                            {e.message && <Text type="danger">{e.message}</Text>}
                          </Space>
                        </Descriptions.Item>
                      ))}
                    </Descriptions>
                  )}
                </Space>
              </C2Panel>
            </Col>
          </Row>
        </main>
      </div>
    </div>
  );
}
