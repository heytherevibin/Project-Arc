'use client';

import { useState } from 'react';
import {
  Button,
  Typography,
  Modal,
  Form,
  Input,
  Select,
  Tag,
  Space,
  App,
  Popconfirm,
  Row,
  Col,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons';
import useSWR from 'swr';
import { api } from '@/lib/api';
import { useAppStore } from '@/store/provider';
import { colors } from '@/lib/theme';
import { C2Panel, CommandBar, C2Table, DataReadout } from '@/components/c2';
import type { Target, TargetDetails, PaginatedResponse, TargetType } from '@/types';

const { Title, Text } = Typography;
const { TextArea } = Input;

const targetTypeOptions = [
  { value: 'domain', label: 'Domain' },
  { value: 'ip', label: 'IP Address' },
  { value: 'url', label: 'URL' },
  { value: 'cidr', label: 'CIDR Range' },
];

export default function TargetsPage() {
  const { message } = App.useApp();
  const [modalOpen, setModalOpen] = useState(false);
  const [detailsModalOpen, setDetailsModalOpen] = useState(false);
  const [selectedTarget, setSelectedTarget] = useState<TargetDetails | null>(null);
  const [loading, setLoading] = useState(false);
  const [form] = Form.useForm();
  
  const currentProject = useAppStore((state) => state.currentProject);
  
  const { data, isLoading, mutate: refreshTargets } = useSWR<PaginatedResponse<Target>>(
    currentProject
      ? `/api/v1/targets?project_id=${currentProject.project_id}`
      : null,
    api.get
  );
  
  const handleAddTarget = async (values: { value: string; target_type: TargetType; description?: string }) => {
    if (!currentProject) return;
    
    setLoading(true);
    try {
      await api.post(`/api/v1/targets?project_id=${currentProject.project_id}`, values);
      message.success('Target added');
      setModalOpen(false);
      form.resetFields();
      refreshTargets();
    } catch (error: any) {
      message.error(error.message || 'Failed to add target');
    } finally {
      setLoading(false);
    }
  };
  
  const handleDeleteTarget = async (targetId: string) => {
    if (!currentProject) return;
    
    try {
      await api.delete(`/api/v1/targets/${targetId}?project_id=${currentProject.project_id}`);
      message.success('Target deleted');
      refreshTargets();
    } catch (error: any) {
      message.error(error.message || 'Failed to delete target');
    }
  };
  
  const handleViewDetails = async (target: Target) => {
    if (!currentProject) return;
    
    try {
      const details = await api.get<TargetDetails>(
        `/api/v1/targets/${target.target_id}?project_id=${currentProject.project_id}`
      );
      setSelectedTarget(details);
      setDetailsModalOpen(true);
    } catch (error: any) {
      message.error(error.message || 'Failed to load details');
    }
  };
  
  const columns: ColumnsType<Target> = [
    {
      title: 'Target',
      dataIndex: 'value',
      key: 'value',
      render: (value: string | undefined, record: Target) => (
        <Button type="link" onClick={() => handleViewDetails(record)} style={{ padding: 0 }}>
          {value ?? record?.value ?? '—'}
        </Button>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'target_type',
      key: 'target_type',
      width: 100,
      render: (type: string | undefined) => (
        <Tag>{(type ?? '').toUpperCase()}</Tag>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: string | undefined) => (
        <Text type="secondary" style={{ textTransform: 'capitalize' }}>
          {status ?? '—'}
        </Text>
      ),
    },
    {
      title: 'Findings',
      dataIndex: 'findings_count',
      key: 'findings_count',
      width: 100,
      align: 'right',
    },
    {
      title: 'Last Scanned',
      dataIndex: 'last_scanned_at',
      key: 'last_scanned_at',
      width: 140,
      render: (date: string | null) => (
        <Text type="secondary">
          {date ? new Date(date).toLocaleDateString() : 'Never'}
        </Text>
      ),
    },
    {
      title: '',
      key: 'actions',
      width: 60,
      render: (_, record: Target) => (
        <Popconfirm
          title="Delete target?"
          description="This will remove all associated data."
          onConfirm={() => { if (record?.target_id) handleDeleteTarget(record.target_id); }}
          okText="Delete"
          cancelText="Cancel"
          okButtonProps={{ danger: true }}
        >
          <Button type="text" icon={<DeleteOutlined />} danger />
        </Popconfirm>
      ),
    },
  ];
  
  if (!currentProject) {
    return (
      <C2Panel title="TARGETS" style={{ maxWidth: 560, margin: '48px auto' }}>
        <div style={{ textAlign: 'center', padding: '24px 0' }}>
          <Title level={4} style={{ color: colors.text.secondary, margin: 0 }}>
            Select a project to view targets
          </Title>
        </div>
      </C2Panel>
    );
  }
  
  return (
    <div>
      <CommandBar style={{ marginBottom: 24 }}>
        <Title level={3} className="page-title" style={{ margin: 0 }}>Targets</Title>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>
          Add Target
        </Button>
      </CommandBar>

      <C2Panel title="TARGETS">
        <C2Table<Target>
          columns={columns}
          dataSource={data?.items ?? []}
          rowKey="target_id"
          loading={isLoading}
          scroll={{ x: 700 }}
          pagination={{
            total: data?.total ?? 0,
            pageSize: 20,
            showSizeChanger: false,
          }}
          locale={{ emptyText: 'No targets yet. Add one to start reconnaissance.' }}
        />
      </C2Panel>

      {/* Add Target Modal */}
      <Modal
        title="Add Target"
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        footer={null}
        destroyOnClose
        width="90vw"
        style={{ maxWidth: 480 }}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleAddTarget}
          initialValues={{ target_type: 'domain' }}
          style={{ marginTop: 24 }}
        >
          <Form.Item
            name="value"
            label="Target"
            rules={[{ required: true, message: 'Target is required' }]}
          >
            <Input placeholder="example.com or 192.168.1.0/24" />
          </Form.Item>
          
          <Form.Item
            name="target_type"
            label="Type"
            rules={[{ required: true }]}
          >
            <Select options={targetTypeOptions} />
          </Form.Item>
          
          <Form.Item name="description" label="Description">
            <TextArea rows={2} placeholder="Optional description" />
          </Form.Item>
          
          <Form.Item style={{ marginBottom: 0, marginTop: 24 }}>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={() => setModalOpen(false)}>Cancel</Button>
              <Button type="primary" htmlType="submit" loading={loading}>
                Add Target
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
      
      {/* Target Details Modal */}
      <Modal
        title={selectedTarget?.value || 'Target Details'}
        open={detailsModalOpen}
        onCancel={() => setDetailsModalOpen(false)}
        footer={null}
        width="90vw"
        style={{ maxWidth: 600 }}
      >
        {selectedTarget && (
          <>
            <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
              <Col xs={24} sm={12} md={8}>
                <DataReadout label="Subdomains" value={selectedTarget.subdomains_count ?? 0} />
              </Col>
              <Col xs={24} sm={12} md={8}>
                <DataReadout label="IPs" value={selectedTarget.ips_count ?? 0} />
              </Col>
              <Col xs={24} sm={12} md={8}>
                <DataReadout label="Ports" value={selectedTarget.ports_count ?? 0} />
              </Col>
            </Row>
            
            <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
              <Col xs={24} sm={12} md={8}>
                <DataReadout label="URLs" value={selectedTarget.urls_count ?? 0} />
              </Col>
              <Col xs={24} sm={12} md={8}>
                <DataReadout
                  label="Vulnerabilities"
                  value={selectedTarget.vulnerabilities_count ?? 0}
                  valueColor={(selectedTarget.vulnerabilities_count ?? 0) > 0 ? colors.severity.high : undefined}
                />
              </Col>
              <Col xs={24} sm={12} md={8}>
                <DataReadout label="Technologies" value={(selectedTarget.technologies ?? []).length} />
              </Col>
            </Row>
            
            {(selectedTarget.technologies ?? []).length > 0 && (
              <div style={{ marginBottom: 16 }}>
                <Text strong>Detected Technologies</Text>
                <div style={{ marginTop: 8 }}>
                  {(selectedTarget.technologies ?? []).map((tech, i) => (
                    <Tag key={i} style={{ marginBottom: 4 }}>{tech}</Tag>
                  ))}
                </div>
              </div>
            )}
            
            {selectedTarget.last_scanned_at && (
              <Text type="secondary">
                Last scanned: {new Date(selectedTarget.last_scanned_at).toLocaleString()}
              </Text>
            )}
          </>
        )}
      </Modal>
    </div>
  );
}
