'use client';

import { useState } from 'react';
import { Typography, Tag, Select, Empty, Skeleton, Space, Timeline as AntTimeline } from 'antd';
import {
  ClockCircleOutlined, CheckCircleOutlined, WarningOutlined,
  PlayCircleOutlined, StopOutlined, ToolOutlined, AuditOutlined,
} from '@ant-design/icons';
import useSWR from 'swr';
import { api } from '@/lib/api';
import { useAppStore } from '@/store/provider';
import { colors } from '@/lib/theme';
import { C2Panel, CommandBar } from '@/components/c2';
import type { Mission, MissionEvent } from '@/types';

const { Title, Text, Paragraph } = Typography;

const eventIcons: Record<string, React.ReactNode> = {
  mission_created: <PlayCircleOutlined style={{ color: colors.status.info }} />,
  status_change: <AuditOutlined style={{ color: colors.accent.primary }} />,
  phase_change: <ClockCircleOutlined style={{ color: colors.status.warning }} />,
  tool_execution: <ToolOutlined style={{ color: colors.status.success }} />,
  approval: <CheckCircleOutlined style={{ color: colors.status.success }} />,
  finding: <WarningOutlined style={{ color: colors.status.error }} />,
  error: <StopOutlined style={{ color: colors.status.error }} />,
};

const eventColors: Record<string, string> = {
  mission_created: colors.status.info,
  status_change: colors.accent.primary,
  phase_change: colors.status.warning,
  tool_execution: colors.status.success,
  approval: colors.status.success,
  finding: colors.status.error,
  error: colors.status.error,
};

export default function TimelinePage() {
  const currentProject = useAppStore((s) => s.currentProject);
  const [selectedMissionId, setSelectedMissionId] = useState<string | null>(null);

  const { data: missionsData, isLoading: missionsLoading } = useSWR<{ items: Mission[]; total: number }>(
    currentProject ? `/api/v1/missions?project_id=${currentProject.project_id}` : null,
    api.get, { refreshInterval: 10000 },
  );

  const missions = missionsData?.items ?? [];

  const { data: timelineData, isLoading: timelineLoading } = useSWR<{ events: MissionEvent[] }>(
    selectedMissionId ? `/api/v1/missions/${selectedMissionId}/timeline?limit=200` : null,
    api.get, { refreshInterval: 5000 },
  );

  const events = timelineData?.events ?? [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <CommandBar>
        <Title level={3} style={{ margin: 0, color: colors.text.primary }}>Mission Timeline</Title>
        <Space wrap>
          <Select
            placeholder="Select a mission"
            style={{ minWidth: 250 }}
            value={selectedMissionId}
            onChange={setSelectedMissionId}
            allowClear
            loading={missionsLoading}
            options={missions.map((m) => ({
              value: m.mission_id,
              label: `${m.name} (${m.status})`,
            }))}
          />
        </Space>
      </CommandBar>

      {!currentProject ? (
        <C2Panel title="Timeline">
          <Empty description="Select a project to view mission timelines" />
        </C2Panel>
      ) : !selectedMissionId ? (
        <C2Panel title="Timeline">
          <Empty description="Select a mission above to view its timeline" />
        </C2Panel>
      ) : timelineLoading ? (
        <C2Panel title="Timeline"><Skeleton active /></C2Panel>
      ) : events.length === 0 ? (
        <C2Panel title="Timeline">
          <Empty description="No events recorded yet for this mission" />
        </C2Panel>
      ) : (
        <C2Panel title={`Timeline — ${events.length} events`}>
          <AntTimeline
            mode="left"
            style={{ marginTop: 16, paddingLeft: 8 }}
            items={events.map((evt) => ({
              key: evt.event_id,
              color: eventColors[evt.event_type] || colors.text.muted,
              dot: eventIcons[evt.event_type] || <ClockCircleOutlined />,
              children: (
                <div style={{ paddingBottom: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <Tag
                      color={eventColors[evt.event_type] || colors.text.muted}
                      style={{ margin: 0, fontSize: 11, textTransform: 'capitalize' }}
                    >
                      {evt.event_type.replace(/_/g, ' ')}
                    </Tag>
                    {evt.phase && (
                      <Tag style={{ margin: 0, fontSize: 11 }}>{evt.phase}</Tag>
                    )}
                    {evt.agent_id && (
                      <Text style={{ fontSize: 11, color: colors.text.secondary }}>
                        Agent: {evt.agent_id}
                      </Text>
                    )}
                  </div>
                  <Paragraph style={{ margin: '4px 0 0', color: colors.text.primary, fontSize: 13 }}>
                    {evt.summary}
                  </Paragraph>
                  <Text style={{ fontSize: 11, color: colors.text.secondary }}>
                    {new Date(evt.timestamp).toLocaleString()}
                  </Text>
                </div>
              ),
            }))}
          />
        </C2Panel>
      )}
    </div>
  );
}
