'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Button,
  Space,
  Typography,
  Modal,
  Form,
  Input,
  Tag,
  App,
  Dropdown,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { PlusOutlined, MoreOutlined, DeleteOutlined, EditOutlined, ExclamationCircleOutlined } from '@ant-design/icons';
import useSWR, { mutate } from 'swr';
import { api } from '@/lib/api';
import { useAppStore } from '@/store/provider';
import { getStatusColor } from '@/lib/theme';
import { C2Panel, CommandBar, C2Table } from '@/components/c2';
import type { Project, ProjectCreate, PaginatedResponse } from '@/types';

const { Title, Text } = Typography;
const { TextArea } = Input;

export default function ProjectsPage() {
  const router = useRouter();
  const { message, modal } = App.useApp();
  const [modalOpen, setModalOpen] = useState(false);
  const [editingProject, setEditingProject] = useState<Project | null>(null);
  const [loading, setLoading] = useState(false);
  const [form] = Form.useForm();
  
  const setCurrentProject = useAppStore((state) => state.setCurrentProject);
  const currentProject = useAppStore((state) => state.currentProject);

  const { data, isLoading } = useSWR<PaginatedResponse<Project>>(
    '/api/v1/projects',
    api.get
  );

  const normalizeScope = (v: string | string[]) =>
    (Array.isArray(v) ? v : (v || '').toString().split('\n').filter(Boolean));

  const handleCreate = async (values: ProjectCreate) => {
    setLoading(true);
    try {
      const project = await api.post<Project>('/api/v1/projects', {
        ...values,
        scope: normalizeScope(values.scope ?? ''),
      });

      message.success('Project created');
      setModalOpen(false);
      form.resetFields();
      setEditingProject(null);
      await mutate('/api/v1/projects');

      setCurrentProject(project);
      router.push('/dashboard');
    } catch (error: any) {
      message.error(error.message || 'Failed to create project');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdate = async (values: ProjectCreate & { scope?: string | string[] }) => {
    if (!editingProject) return;
    setLoading(true);
    try {
      const project = await api.patch<Project>(
        `/api/v1/projects/${editingProject.project_id}`,
        {
          name: values.name,
          description: values.description ?? null,
          scope: normalizeScope(values.scope ?? ''),
          out_of_scope: editingProject.out_of_scope,
          tags: editingProject.tags,
        }
      );

      message.success('Project updated');
      setModalOpen(false);
      form.resetFields();
      setEditingProject(null);
      await mutate('/api/v1/projects');

      if (currentProject?.project_id === editingProject.project_id) {
        setCurrentProject(project);
      }
    } catch (error: any) {
      message.error(error.message || 'Failed to update project');
    } finally {
      setLoading(false);
    }
  };
  
  const handleDelete = async (projectId: string) => {
    try {
      await api.delete(`/api/v1/projects/${projectId}`);
      message.success('Project deleted');
      mutate('/api/v1/projects');
    } catch (error: any) {
      message.error(error.message || 'Failed to delete project');
    }
  };
  
  const handleSelectProject = (project: Project) => {
    setCurrentProject(project);
    router.push('/dashboard');
  };
  
  const columns: ColumnsType<Project> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: Project) => (
        <Button type="link" onClick={() => handleSelectProject(record)} style={{ padding: 0 }}>
          {name}
        </Button>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: string) => (
        <Tag color={getStatusColor(status)} style={{ textTransform: 'uppercase' }}>
          {status}
        </Tag>
      ),
    },
    {
      title: 'Scope',
      dataIndex: 'scope',
      key: 'scope',
      render: (scope: string[]) => (
        <Text type="secondary">{scope.length} target(s)</Text>
      ),
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (date: string) => (
        <Text type="secondary">{new Date(date).toLocaleDateString()}</Text>
      ),
    },
    {
      title: '',
      key: 'actions',
      width: 60,
      render: (_, record: Project) => (
        <Dropdown
          menu={{
            items: [
              {
                key: 'edit',
                icon: <EditOutlined />,
                label: 'Edit',
                onClick: () => {
                  setEditingProject(record);
                  form.setFieldsValue({
                    ...record,
                    scope: record.scope.join('\n'),
                  });
                  setModalOpen(true);
                },
              },
              {
                key: 'delete',
                icon: <DeleteOutlined />,
                label: 'Delete',
                danger: true,
                onClick: () => {
                  modal.confirm({
                    title: 'Delete project?',
                    icon: <ExclamationCircleOutlined />,
                    content: 'This will delete all associated data.',
                    okText: 'Delete',
                    cancelText: 'Cancel',
                    okButtonProps: { danger: true },
                    onOk: () => handleDelete(record.project_id),
                  });
                },
              },
            ],
          }}
          trigger={['click']}
        >
          <Button type="text" icon={<MoreOutlined />} />
        </Dropdown>
      ),
    },
  ];
  
  return (
    <div>
      <CommandBar style={{ marginBottom: 24 }}>
        <Title level={3} className="page-title" style={{ margin: 0 }}>Projects</Title>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => {
            setEditingProject(null);
            form.resetFields();
            setModalOpen(true);
          }}
        >
          New Project
        </Button>
      </CommandBar>

      <C2Panel title="PROJECTS">
        <C2Table<Project>
          columns={columns}
          dataSource={data?.items ?? []}
          rowKey="project_id"
          loading={isLoading}
          scroll={{ x: 600 }}
          pagination={{
            total: data?.total ?? 0,
            pageSize: 20,
            showSizeChanger: false,
          }}
          locale={{ emptyText: 'No projects yet. Create one to get started.' }}
        />
      </C2Panel>
      
      <Modal
        title={editingProject ? 'Edit Project' : 'New Project'}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        footer={null}
        destroyOnClose
        width="90vw"
        style={{ maxWidth: 520 }}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={editingProject ? handleUpdate : handleCreate}
          style={{ marginTop: 24 }}
        >
          <Form.Item
            name="name"
            label="Project Name"
            rules={[{ required: true, message: 'Name is required' }]}
          >
            <Input placeholder="My Security Assessment" />
          </Form.Item>
          
          <Form.Item name="description" label="Description">
            <TextArea rows={2} placeholder="Optional description" />
          </Form.Item>
          
          <Form.Item
            name="scope"
            label="Scope"
            help="Enter one target per line (domains, IPs, or CIDRs)"
          >
            <TextArea rows={4} placeholder="example.com&#10;*.example.com&#10;192.168.1.0/24" />
          </Form.Item>
          
          <Form.Item style={{ marginBottom: 0, marginTop: 24 }}>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={() => setModalOpen(false)}>Cancel</Button>
              <Button type="primary" htmlType="submit" loading={loading}>
                {editingProject ? 'Save Changes' : 'Create Project'}
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
