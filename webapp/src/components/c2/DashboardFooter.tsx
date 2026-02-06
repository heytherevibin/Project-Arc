'use client';

import { IndicatorLight } from './IndicatorLight';

export interface DashboardFooterProps {
  /** Connection status — shown as Connected/Disconnected with indicator in footer */
  connection?: boolean;
}

/**
 * Dashboard footer – Sentinel-style TechFooter (paper bg, left: brand + Connected, right: version).
 */
export function DashboardFooter({ connection }: DashboardFooterProps) {
  const year = new Date().getFullYear();

  return (
    <footer className="dashboard-footer">
      <div className="dashboard-footer__accent" />
      <div className="dashboard-footer__inner">
        <span className="dashboard-footer__brand font-mono">Project ARC</span>
        <span className="dashboard-footer__divider" />
        <span className={`dashboard-footer__connection ${connection ? 'dashboard-footer__connection--ok' : 'dashboard-footer__connection--error'}`}>
          <IndicatorLight status={connection ? 'ok' : 'error'} aria-label={connection ? 'Connected' : 'Disconnected'} />
          {connection ? 'Connected' : 'Disconnected'}
        </span>
        <span className="dashboard-footer__divider dashboard-footer__divider--hide-mobile" />
        <span className="dashboard-footer__status dashboard-footer__status--hide-mobile">SYSTEM ONLINE</span>
        <span className="dashboard-footer__divider dashboard-footer__divider--hide-mobile" />
        <span className="dashboard-footer__tagline dashboard-footer__tagline--hide-mobile">
          Enterprise Autonomous AI Red Team Framework
        </span>
        <span className="dashboard-footer__divider dashboard-footer__divider--hide-mobile" />
        <span className="dashboard-footer__encrypted dashboard-footer__encrypted--hide-mobile">ENCRYPTED</span>
        <span className="dashboard-footer__divider dashboard-footer__divider--spacer" />
        <span className="dashboard-footer__meta">v0.1.0</span>
        <span className="dashboard-footer__copy">© {year}</span>
      </div>
    </footer>
  );
}
