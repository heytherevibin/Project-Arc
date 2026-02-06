'use client';

import { colors } from '@/lib/theme';

export type IndicatorStatus = 'ok' | 'warn' | 'error' | 'active';

const statusConfig: Record<IndicatorStatus, { color: string; pulse?: boolean }> = {
  ok: { color: colors.status.success },
  warn: { color: colors.status.warning },
  error: { color: colors.status.error },
  active: { color: colors.accent.primary, pulse: true },
};

export interface IndicatorLightProps {
  status: IndicatorStatus;
  'aria-label'?: string;
}

export function IndicatorLight({ status, 'aria-label': ariaLabel }: IndicatorLightProps) {
  const { color, pulse } = statusConfig[status];
  return (
    <span
      className={pulse ? 'c2-indicator c2-indicator--pulse' : 'c2-indicator'}
      style={{ backgroundColor: color }}
      role="status"
      aria-label={ariaLabel ?? `${status} status`}
    />
  );
}
