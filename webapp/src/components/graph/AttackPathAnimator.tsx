'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { Button, Slider, Space, Tag, Typography } from 'antd';
import { CaretRightOutlined, PauseOutlined, StepForwardOutlined, StepBackwardOutlined } from '@ant-design/icons';
import { colors } from '@/lib/theme';

const { Text } = Typography;

export interface PathStep {
  nodeId: string;
  label: string;
  type: string;
  technique?: string;
}

export interface AttackPathAnimatorProps {
  path: PathStep[];
  playing?: boolean;
  speed?: number;         // ms between steps
  onStepChange?: (stepIndex: number, step: PathStep) => void;
  onPlayingChange?: (playing: boolean) => void;
}

export function AttackPathAnimator({
  path,
  playing: externalPlaying,
  speed = 1500,
  onStepChange,
  onPlayingChange,
}: AttackPathAnimatorProps) {
  const [currentStep, setCurrentStep] = useState(0);
  const [isPlaying, setIsPlaying] = useState(externalPlaying ?? false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const totalSteps = path.length;

  const updatePlaying = useCallback(
    (val: boolean) => {
      setIsPlaying(val);
      onPlayingChange?.(val);
    },
    [onPlayingChange],
  );

  // Auto-advance when playing
  useEffect(() => {
    if (isPlaying && totalSteps > 0) {
      timerRef.current = setInterval(() => {
        setCurrentStep((prev) => {
          const next = prev + 1;
          if (next >= totalSteps) {
            updatePlaying(false);
            return prev;
          }
          return next;
        });
      }, speed);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, speed, totalSteps, updatePlaying]);

  // Notify parent of step changes
  useEffect(() => {
    if (path[currentStep]) {
      onStepChange?.(currentStep, path[currentStep]);
    }
  }, [currentStep, path, onStepChange]);

  // Sync external playing prop
  useEffect(() => {
    if (externalPlaying !== undefined) setIsPlaying(externalPlaying);
  }, [externalPlaying]);

  const step = path[currentStep];

  return (
    <div style={{ padding: 12, background: colors.bg.surface, borderRadius: 6, border: `1px solid ${colors.border.primary}` }}>
      {/* Controls */}
      <Space size="small" style={{ marginBottom: 8 }}>
        <Button
          size="small"
          icon={<StepBackwardOutlined />}
          disabled={currentStep === 0}
          onClick={() => setCurrentStep((p) => Math.max(0, p - 1))}
        />
        <Button
          size="small"
          type={isPlaying ? 'default' : 'primary'}
          icon={isPlaying ? <PauseOutlined /> : <CaretRightOutlined />}
          onClick={() => updatePlaying(!isPlaying)}
        />
        <Button
          size="small"
          icon={<StepForwardOutlined />}
          disabled={currentStep >= totalSteps - 1}
          onClick={() => setCurrentStep((p) => Math.min(totalSteps - 1, p + 1))}
        />
        <Text style={{ color: colors.text.secondary, fontSize: 12 }}>
          Step {currentStep + 1} / {totalSteps}
        </Text>
      </Space>

      {/* Slider */}
      <Slider
        min={0}
        max={Math.max(0, totalSteps - 1)}
        value={currentStep}
        onChange={(v) => setCurrentStep(v)}
        tooltip={{ formatter: (v) => `Step ${(v ?? 0) + 1}` }}
        style={{ margin: '4px 0' }}
      />

      {/* Current step info */}
      {step && (
        <div style={{ marginTop: 8 }}>
          <Tag color={colors.accent.primary}>{step.type}</Tag>
          <Text style={{ color: colors.text.primary }}>{step.label}</Text>
          {step.technique && (
            <Tag color={colors.severity.medium} style={{ marginLeft: 8 }}>
              {step.technique}
            </Tag>
          )}
        </div>
      )}
    </div>
  );
}
