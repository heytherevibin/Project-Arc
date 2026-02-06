'use client';

import { useState } from 'react';
import {
  Typography,
  Tag,
  Space,
  Select,
  Input,
  Modal,
  Descriptions,
  Button,
  Row,
  Col,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { SearchOutlined, LinkOutlined } from '@ant-design/icons';
import useSWR from 'swr';
import { api } from '@/lib/api';
import { useAppStore } from '@/store/provider';
import { colors, getSeverityColor } from '@/lib/theme';
import { C2Panel, CommandBar, C2Table, DataReadout } from '@/components/c2';
import type { Vulnerability, PaginatedResponse } from '@/types';

const { Title, Text, Paragraph } = Typography;

const severityOptions = [
  { value: '', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

export default function VulnerabilitiesPage() {
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchText, setSearchText] = useState('');
  
  const currentProject = useAppStore((state) => state.currentProject);
  
  const buildQueryString = () => {
    const params = new URLSearchParams();
    if (currentProject) {
      params.set('project_id', currentProject.project_id);
    }
    if (severityFilter) {
      params.set('severity', severityFilter);
    }
    if (searchText) {
      params.set('search', searchText);
    }
    return params.toString();
  };
  
  const { data, isLoading } = useSWR<PaginatedResponse<Vulnerability>>(
    currentProject
      ? `/api/v1/vulnerabilities?${buildQueryString()}`
      : null,
    api.get,
    { refreshInterval: 10000 }
  );
  
  const handleViewDetails = (vuln: Vulnerability) => {
    setSelectedVuln(vuln);
    setModalOpen(true);
  };
  
  // Calculate severity counts
  const severityCounts = {
    critical: data?.items?.filter(v => v.severity === 'critical').length || 0,
    high: data?.items?.filter(v => v.severity === 'high').length || 0,
    medium: data?.items?.filter(v => v.severity === 'medium').length || 0,
    low: data?.items?.filter(v => v.severity === 'low').length || 0,
  };
  
  const columns: ColumnsType<Vulnerability> = [
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      width: 110,
      render: (severity: string) => (
        <Tag color={getSeverityColor(severity)} style={{ textTransform: 'uppercase' }}>
          {severity}
        </Tag>
      ),
      sorter: (a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return (order[a.severity as keyof typeof order] || 5) - (order[b.severity as keyof typeof order] || 5);
      },
    },
    {
      title: 'Vulnerability',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: Vulnerability) => (
        <Button type="link" onClick={() => handleViewDetails(record)} style={{ padding: 0 }}>
          {name}
        </Button>
      ),
    },
    {
      title: 'CVE',
      dataIndex: 'cve_id',
      key: 'cve_id',
      width: 150,
      render: (cve: string) => (
        cve ? (
          <a
            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
            target="_blank"
            rel="noopener noreferrer"
          >
            {cve}
          </a>
        ) : (
          <Text type="secondary">-</Text>
        )
      ),
    },
    {
      title: 'CVSS',
      dataIndex: 'cvss_score',
      key: 'cvss_score',
      width: 90,
      render: (score: number | null) => (
        score ? (
          <Text strong style={{ color: score >= 9 ? colors.severity.critical : score >= 7 ? colors.severity.high : colors.text.primary }}>
            {score.toFixed(1)}
          </Text>
        ) : (
          <Text type="secondary">-</Text>
        )
      ),
      sorter: (a, b) => (a.cvss_score || 0) - (b.cvss_score || 0),
    },
    {
      title: 'Target',
      dataIndex: 'matched_at',
      key: 'matched_at',
      render: (url: string) => (
        <Text style={{ fontSize: 12 }}>{url}</Text>
      ),
    },
    {
      title: 'Found',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 100,
      render: (date: string) => (
        <Text type="secondary" style={{ fontSize: 12 }}>
          {new Date(date).toLocaleDateString()}
        </Text>
      ),
    },
  ];
  
  if (!currentProject) {
    return (
      <C2Panel title="VULNERABILITIES" style={{ maxWidth: 560, margin: '48px auto' }}>
        <div style={{ textAlign: 'center', padding: '24px 0' }}>
          <Title level={4} style={{ color: colors.text.secondary, margin: 0 }}>
            Select a project to view vulnerabilities
          </Title>
        </div>
      </C2Panel>
    );
  }
  
  return (
    <div>
      <CommandBar style={{ marginBottom: 24 }}>
        <Title level={3} className="page-title" style={{ margin: 0 }}>Vulnerabilities</Title>
      </CommandBar>
      
      <C2Panel title="SEVERITY SUMMARY (this page)" style={{ marginBottom: 16 }}>
        <Row gutter={[16, 16]}>
          <Col xs={12} sm={12} md={6}>
            <DataReadout
              label="Critical"
              value={severityCounts.critical}
              valueColor={colors.severity.critical}
            />
          </Col>
          <Col xs={12} sm={12} md={6}>
            <DataReadout
              label="High"
              value={severityCounts.high}
              valueColor={colors.severity.high}
            />
          </Col>
          <Col xs={12} sm={12} md={6}>
            <DataReadout
              label="Medium"
              value={severityCounts.medium}
              valueColor={colors.severity.medium}
            />
          </Col>
          <Col xs={12} sm={12} md={6}>
            <DataReadout label="Low" value={severityCounts.low} valueColor={colors.severity.low} />
          </Col>
        </Row>
      </C2Panel>

      <C2Panel title="FILTERS" style={{ marginBottom: 16 }}>
        <Space wrap>
          <Select
            value={severityFilter}
            onChange={setSeverityFilter}
            options={severityOptions}
            style={{ minWidth: 180 }}
            placeholder="Severity"
          />
          <Input
            placeholder="Search vulnerabilities..."
            prefix={<SearchOutlined />}
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            style={{ minWidth: 200, flex: 1, maxWidth: 400 }}
            allowClear
          />
        </Space>
      </C2Panel>

      <C2Panel title="VULNERABILITIES">
        <C2Table<Vulnerability>
          columns={columns}
          dataSource={data?.items ?? []}
          rowKey={(record) => `${record.template_id}-${record.matched_at}`}
          loading={isLoading}
          scroll={{ x: 900 }}
          pagination={{
            total: data?.total ?? 0,
            pageSize: 20,
            showSizeChanger: false,
          }}
          locale={{ emptyText: 'No vulnerabilities found. Run a vulnerability scan to discover issues.' }}
        />
      </C2Panel>

      {/* Details Modal */}
      <Modal
        title={selectedVuln?.name || 'Vulnerability Details'}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        footer={null}
        width="90vw"
        style={{ maxWidth: 700 }}
      >
        {selectedVuln && (
          <>
            <Tag
              color={getSeverityColor(selectedVuln.severity)}
              style={{ marginBottom: 16, textTransform: 'uppercase' }}
            >
              {selectedVuln.severity}
            </Tag>
            
            <Descriptions column={{ xs: 1, sm: 2 }} style={{ marginBottom: 16 }}>
              <Descriptions.Item label="Template ID">
                <code>{selectedVuln.template_id}</code>
              </Descriptions.Item>
              <Descriptions.Item label="CVE">
                {selectedVuln.cve_id ? (
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${selectedVuln.cve_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    {selectedVuln.cve_id} <LinkOutlined />
                  </a>
                ) : (
                  '-'
                )}
              </Descriptions.Item>
              <Descriptions.Item label="CVSS Score">
                {selectedVuln.cvss_score?.toFixed(1) || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="CWE">
                {selectedVuln.cwe_id || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="Target" span={2}>
                <Text copyable style={{ wordBreak: 'break-all' }}>
                  {selectedVuln.matched_at}
                </Text>
              </Descriptions.Item>
            </Descriptions>
            
            {selectedVuln.description && (
              <div style={{ marginBottom: 16 }}>
                <Text strong>Description</Text>
                <Paragraph type="secondary" style={{ marginTop: 8 }}>
                  {selectedVuln.description}
                </Paragraph>
              </div>
            )}
            
            {selectedVuln.evidence && (
              <div style={{ marginBottom: 16 }}>
                <Text strong>Evidence</Text>
                <pre style={{
                  backgroundColor: colors.bg.tertiary,
                  padding: 12,
                  borderRadius: 6,
                  marginTop: 8,
                  overflow: 'auto',
                  maxHeight: 200,
                }}>
                  {selectedVuln.evidence}
                </pre>
              </div>
            )}
            
            {selectedVuln.remediation && (
              <div style={{ marginBottom: 16 }}>
                <Text strong>Remediation</Text>
                <Paragraph type="secondary" style={{ marginTop: 8 }}>
                  {selectedVuln.remediation}
                </Paragraph>
              </div>
            )}
            
            {selectedVuln.references && selectedVuln.references.length > 0 && (
              <div>
                <Text strong>References</Text>
                <ul style={{ marginTop: 8, paddingLeft: 20 }}>
                  {selectedVuln.references.map((ref, i) => (
                    <li key={i}>
                      <a href={ref} target="_blank" rel="noopener noreferrer">
                        {ref}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </Modal>
    </div>
  );
}
