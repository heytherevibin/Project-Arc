'use client';

import { forwardRef } from 'react';
import { IndicatorLight, type IndicatorStatus } from './IndicatorLight';

export interface C2PanelProps {
  title?: string;
  status?: IndicatorStatus;
  extra?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
  bodyStyle?: React.CSSProperties;
}

export const C2Panel = forwardRef<HTMLDivElement, C2PanelProps>(
  ({ title, status, extra, children, className, style, bodyStyle }, ref) => {
    const hasHead = title != null || extra != null || status != null;
    const headClass = status != null ? `c2-panel__head c2-panel__head--status-${status}` : 'c2-panel__head';
    return (
      <div ref={ref} className={`c2-panel ${className ?? ''}`.trim()} style={style}>
        <div className="c2-panel__accent" />
        {hasHead && (
          <div className={headClass}>
            {status != null && <div className="c2-panel__status-bar" aria-hidden />}
            <div className="c2-panel__title">
              {status != null && <IndicatorLight status={status} />}
              {title != null && <span>{title}</span>}
            </div>
            {extra != null && <div className="c2-panel__extra">{extra}</div>}
          </div>
        )}
        <div className="c2-panel__body" style={bodyStyle}>
          {children}
        </div>
      </div>
    );
  }
);
C2Panel.displayName = 'C2Panel';
