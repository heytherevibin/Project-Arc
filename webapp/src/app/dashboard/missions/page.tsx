'use client';

import { useState, useCallback } from 'react';
import {
  Row, Col, Typography, Tag, Button, Modal, Form, Input, Select, Space,
  Descriptions, App, Empty, Skeleton,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import {
  PlusOutlined, PlayCircleOutlined, StopOutlined,
  CheckCircleOutlined,
} from '@ant-design/icons';
import useSWR, { mutate as globalMutate } from 'swr';
import { api } from '@/lib/api';
import { useAppStore } from '@/store/provider';
import { colors } from '@/lib/theme';
import { C2Panel, DataReadout, C2Table, CommandBar } from '@/components/c2';
import type { Mission, MissionCreateResponse } from '@/types';

const { Title, Text } = Typography;

const statusColors: Record<string, string> = {
  created: colors.text.muted,
  planning: colors.status.info,
  running: colors.status.success,
  paused: colors.status.warning,
  completed: colors.status.success,
  failed: colors.status.error,
  cancelled: colors.text.muted,
};

const phaseLabels: Record<string, string> = {
  recon: 'Reconnaissance',
  vuln_analysis: 'Vulnerability Analysis',
  exploitation: 'Exploitation',
  post_exploitation: 'Post-Exploitation',
  lateral_movement: 'Lateral Movement',
  persistence: 'Persistence',
  exfiltration: 'Exfiltration',
  reporting: 'Reporting',
};

export default function MissionsPage() {
  const currentProject = useAppStore((s) => s.currentProject);
  const { message } = App.useApp();
  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [selectedMission, setSelectedMission] = useState<Mission | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [form] = Form.useForm();

  const listKey = currentProject
    ? `/api/v1/missions?project_id=${currentProject.project_id}`
    : null;

  const { data, isLoading } = useSWR<{ items: Mission[]; total: number }>(
    listKey, api.get, { refreshInterval: 5000 },
  );

  const missions = data?.items ?? [];
  const running = missions.filter((m) => m.status === 'running').length;
  const paused = missions.filter((m) => m.status === 'paused').length;
  const completed = missions.filter((m) => m.status === 'completed').length;

  const handleCreate = useCallback(async () => {
    try {
      const values = await form.validateFields();
      setCreating(true);
      await api.post<MissionCreateResponse>('/api/v1/missions', {
        project_id: currentProject?.project_id,
        ...values,
      });
      message.success('Mission created');
      setCreateOpen(false);
      form.resetFields();
      globalMutate(listKey);
    } catch (err: any) {
      if (err?.errorFields) return;
      message.error(err?.message || 'Failed to create mission');
    } finally {
      setCreating(false);
    }
  }, [form, currentProject, listKey, message]);

  const handleAction = useCallback(async (missionId: string, action: string) => {
    setActionLoading(missionId);
    try {
      if (action === 'start') {
        await api.post(`/api/v1/missions/${missionId}/start`);
        message.success('Mission started');
      } else if (action === 'step') {
        await api.post(`/api/v1/missions/${missionId}/step`);
        message.success('Step executed');
      } else if (action === 'approve') {
        await api.post(`/api/v1/missions/${missionId}/approve`, { approved_by: 'operator' });
        message.success('Approved and continued');
      } else if (action === 'cancel') {
        await api.post(`/api/v1/missions/${missionId}/cancel`);
        message.success('Mission cancelled');
      }
      globalMutate(listKey);
    } catch (err: any) {
      message.error(err?.message || `Failed to ${action}`);
    } finally {
      setActionLoading(null);
    }
  }, [listKey, message]);

  const columns: ColumnsType<Mission> = [
    {
      title: 'Name', dataIndex: 'name', key: 'name',
      render: (name: string, record: Mission) => (
        <a onClick={() => { setSelectedMission(record); setDetailOpen(true); }}>{name}</a>
      ),
    },
    { title: 'Target', dataIndex: 'target', key: 'target', ellipsis: true },
    {
      title: 'Status', dataIndex: 'status', key: 'status', width: 110,
      render: (s: string) => (
        <Tag color={statusColors[s] || colors.text.muted} style={{ textTransform: 'capitalize' }}>{s}</Tag>
      ),
    },
    {
      title: 'Phase', dataIndex: 'current_phase', key: 'phase', width: 160,
      render: (p: string) => <Text style={{ fontSize: 12 }}>{phaseLabels[p] || p}</Text>,
    },
    {
      title: 'Hosts', dataIndex: 'discovered_hosts_count', key: 'hosts', width: 70, align: 'center',
    },
    {
      title: 'Vulns', dataIndex: 'discovered_vulns_count', key: 'vulns', width: 70, align: 'center',
    },
    {
      title: 'Sessions', dataIndex: 'active_sessions_count', key: 'sessions', width: 80, align: 'center',
    },
    {
      title: 'Actions', key: 'actions', width: 160, fixed: 'right',
      render: (_: unknown, record: Mission) => {
        const loading = actionLoading === record.mission_id;
        return (
          <Space size={4}>
            {record.status === 'planning' && (
              <Button size="small" type="primary" icon={<PlayCircleOutlined />}
                loading={loading} onClick={() => handleAction(record.mission_id, 'start')}>
                Start
              </Button>
            )}
            {record.status === 'running' && (
              <Button size="small" icon={<PlayCircleOutlined />}
                loading={loading} onClick={() => handleAction(record.mission_id, 'step')}>
                Step
              </Button>
            )}
            {record.status === 'paused' && (
              <Button size="small" type="primary" icon={<CheckCircleOutlined />}
                loading={loading} onClick={() => handleAction(record.mission_id, 'approve')}>
                Approve
              </Button>
            )}
            {['running', 'paused', 'planning'].includes(record.status) && (
              <Button size="small" danger icon={<StopOutlined />}
                loading={loading} onClick={() => handleAction(record.mission_id, 'cancel')}>
                Cancel
              </Button>
            )}
          </Space>
        );
      },
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <CommandBar>
        <Title level={3} style={{ margin: 0, color: colors.text.primary }}>Missions</Title>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}
          disabled={!currentProject}>
          New Mission
        </Button>
      </CommandBar>

      <Row gutter={[16, 16]}>
        <Col xs={12} sm={8} md={4}>
          <C2Panel title="Total"><DataReadout label="Missions" value={missions.length} /></C2Panel>
        </Col>
        <Col xs={12} sm={8} md={4}>
          <C2Panel title="Running" status={running > 0 ? 'active' : 'ok'}><DataReadout label="Active" value={running} /></C2Panel>
        </Col>
        <Col xs={12} sm={8} md={4}>
          <C2Panel title="Awaiting Approval" status={paused > 0 ? 'warn' : 'ok'}><DataReadout label="Paused" value={paused} /></C2Panel>
        </Col>
        <Col xs={12} sm={8} md={4}>
          <C2Panel title="Completed"><DataReadout label="Done" value={completed} /></C2Panel>
        </Col>
      </Row>

      <C2Panel title="Mission Queue">
        {!currentProject ? (
          <Empty description="Select a project to view missions" />
        ) : isLoading ? (
          <Skeleton active />
        ) : (
          <C2Table<Mission>
            dataSource={missions}
            columns={columns}
            rowKey="mission_id"
            scroll={{ x: 900 }}
          />
        )}
      </C2Panel>

      <Modal title="Create Mission" open={createOpen} onCancel={() => setCreateOpen(false)}
        onOk={handleCreate} confirmLoading={creating}
        width="90vw" style={{ maxWidth: 560 }}>
        <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="name" label="Mission Name" rules={[{ required: true }]}>
            <Input placeholder="e.g. Q1 External Pentest" />
          </Form.Item>
          <Form.Item name="target" label="Primary Target" rules={[{ required: true }]}>
            <Input placeholder="e.g. example.com or 10.0.0.0/24" />
          </Form.Item>
          <Form.Item name="objective" label="Objective" rules={[{ required: true }]}>
            <Input.TextArea rows={3} placeholder="Describe the penetration testing objective..." />
          </Form.Item>
          <Form.Item name="target_type" label="Target Type" initialValue="web_application_pentest">
            <Select options={[
              { value: 'web_application_pentest', label: 'Web Application Pentest' },
              { value: 'network_pentest', label: 'Network Pentest' },
              { value: 'active_directory_attack', label: 'Active Directory Attack' },
            ]} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal title={selectedMission?.name || 'Mission Details'} open={detailOpen}
        onCancel={() => setDetailOpen(false)} footer={null}
        width="90vw" style={{ maxWidth: 700 }}>
        {selectedMission && (
          <Descriptions bordered column={{ xs: 1, sm: 2 }} size="small" style={{ marginTop: 16 }}>
            <Descriptions.Item label="ID">{selectedMission.mission_id}</Descriptions.Item>
            <Descriptions.Item label="Status">
              <Tag color={statusColors[selectedMission.status]}>{selectedMission.status}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Target">{selectedMission.target}</Descriptions.Item>
            <Descriptions.Item label="Phase">{phaseLabels[selectedMission.current_phase] || selectedMission.current_phase}</Descriptions.Item>
            <Descriptions.Item label="Objective" span={2}>{selectedMission.objective}</Descriptions.Item>
            <Descriptions.Item label="Hosts Discovered">{selectedMission.discovered_hosts_count}</Descriptions.Item>
            <Descriptions.Item label="Vulns Found">{selectedMission.discovered_vulns_count}</Descriptions.Item>
            <Descriptions.Item label="Active Sessions">{selectedMission.active_sessions_count}</Descriptions.Item>
            <Descriptions.Item label="Compromised Hosts">{selectedMission.compromised_hosts_count}</Descriptions.Item>
            <Descriptions.Item label="Created">{new Date(selectedMission.created_at).toLocaleString()}</Descriptions.Item>
            <Descriptions.Item label="Updated">{new Date(selectedMission.updated_at).toLocaleString()}</Descriptions.Item>
          </Descriptions>
        )}
      </Modal>
    </div>
  );
}
