'use client';

import { IndicatorLight } from './IndicatorLight';

export interface StatusStripProps {
  connection: boolean;
  projectName?: string | null;
  activeScans?: number;
  /** Use when embedding in header so strip has no bar styling */
  inline?: boolean;
}

export function StatusStrip({ connection, projectName, activeScans = 0, inline }: StatusStripProps) {
  return (
    <div className={`c2-status-strip ${inline ? 'c2-status-strip--inline' : ''}`.trim()}>
      <span className="c2-status-strip__item">
        <IndicatorLight status={connection ? 'ok' : 'error'} aria-label={connection ? 'Connected' : 'Disconnected'} />
        {connection ? 'Connected' : 'Disconnected'}
      </span>
      {projectName != null && projectName !== '' && (
        <>
          <span className="c2-status-strip__divider" />
          <span className="c2-status-strip__item">{projectName}</span>
        </>
      )}
      {activeScans > 0 && (
        <>
          <span className="c2-status-strip__divider" />
          <span className="c2-status-strip__item">
            <IndicatorLight status="active" aria-label="Active scans" />
            {activeScans} active scan{activeScans !== 1 ? 's' : ''}
          </span>
        </>
      )}
    </div>
  );
}
