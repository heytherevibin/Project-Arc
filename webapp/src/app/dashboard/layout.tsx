'use client';

import { useEffect, type ReactNode } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';
import { Layout, Dropdown, Avatar, type MenuProps } from 'antd';
import { LogoutOutlined, UserOutlined, EllipsisOutlined } from '@ant-design/icons';
import { useAuthStore, useAppStore } from '@/store/provider';
import { useWebSocket } from '@/hooks/useWebSocket';
import { colors } from '@/lib/theme';
import { DashboardFooter } from '@/components/c2';

const { Header, Content } = Layout;

/**
 * Nav items for Sentinel-style center navbar (labels only, no icons; active gets hazard stripes)
 */
const allNavItems: { key: string; href: string; label: string }[] = [
  { key: '/dashboard', href: '/dashboard', label: 'Overview' },
  { key: '/dashboard/projects', href: '/dashboard/projects', label: 'Projects' },
  { key: '/dashboard/missions', href: '/dashboard/missions', label: 'Missions' },
  { key: '/dashboard/targets', href: '/dashboard/targets', label: 'Targets' },
  { key: '/dashboard/scans', href: '/dashboard/scans', label: 'Scans' },
  { key: '/dashboard/vulnerabilities', href: '/dashboard/vulnerabilities', label: 'Vulnerabilities' },
  { key: '/dashboard/graph', href: '/dashboard/graph', label: 'Attack Graph' },
  { key: '/dashboard/graph/attack-paths', href: '/dashboard/graph/attack-paths', label: 'Attack Paths' },
  { key: '/dashboard/graph/identity', href: '/dashboard/graph/identity', label: 'Identity' },
  { key: '/dashboard/approvals', href: '/dashboard/approvals', label: 'Approvals' },
  { key: '/dashboard/chat', href: '/dashboard/chat', label: 'AI Chat' },
  { key: '/dashboard/timeline', href: '/dashboard/timeline', label: 'Timeline' },
  { key: '/dashboard/reports', href: '/dashboard/reports', label: 'Reports' },
  { key: '/dashboard/settings', href: '/dashboard/settings', label: 'Settings' },
];

/** Items shown inline; remainder goes into "More..." dropdown */
const INLINE_COUNT = 10;

/**
 * Dashboard layout — Sentinel-style top header with center navbar (no sidebar)
 */
export default function DashboardLayout({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();

  const user = useAuthStore((state) => state.user);
  const logout = useAuthStore((state) => state.logout);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const wsConnected = useAppStore((state) => state.wsConnected);
  const currentProject = useAppStore((state) => state.currentProject);

  useWebSocket({
    projectId: currentProject?.project_id,
  });

  // Pick the single most-specific nav key that matches the current pathname.
  // This prevents "/dashboard/graph" from lighting up when visiting
  // "/dashboard/graph/identity" — because the latter is a longer match.
  const activeKey = (() => {
    let best = '';
    for (const item of allNavItems) {
      const k = item.key;
      const matches =
        k === '/dashboard'
          ? pathname === '/dashboard'
          : pathname === k || pathname.startsWith(k + '/');
      if (matches && k.length > best.length) best = k;
    }
    return best;
  })();

  const isItemActive = (key: string) => key === activeKey;

  const inlineItems = allNavItems.slice(0, INLINE_COUNT);
  const overflowItems = allNavItems.slice(INLINE_COUNT);
  const overflowHasActive = overflowItems.some((item) => isItemActive(item.key));

  useEffect(() => {
    if (!isAuthenticated) {
      router.replace('/login');
    }
  }, [isAuthenticated, router]);

  const handleLogout = () => {
    logout();
    router.replace('/login');
  };

  const userMenuItems: MenuProps['items'] = [
    {
      key: 'profile',
      icon: <UserOutlined />,
      label: 'Profile',
      onClick: () => router.push('/dashboard/settings'),
    },
    { type: 'divider' },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: 'Logout',
      onClick: handleLogout,
    },
  ];

  const userInitial = (user?.email?.[0] ?? 'U').toUpperCase();

  return (
    <Layout style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <Header className="dashboard-header-bar dashboard-header-sticky">
        <div className="dashboard-header-bar__inner">
          {/* Left: Logo block (Sentinel-style) */}
          <div className="dashboard-logo-block">
            <span className="dashboard-logo-block__badge" style={{ background: `${colors.accent.primary}1a`, borderColor: `${colors.accent.primary}33` }}>
              ARC-01
            </span>
            <div className="dashboard-logo-block__text">
              <span className="dashboard-logo-block__title">PROJECT ARC</span>
              <span className="dashboard-logo-block__subtitle">MISSION_CONTROL</span>
            </div>
          </div>

          {/* Center: Nav pills (labels only; active has mustard hazard stripes) */}
          <nav className="dashboard-nav" aria-label="Main navigation">
            {inlineItems.map((item) => {
              const active = isItemActive(item.key);
              return (
                <Link
                  key={item.key}
                  href={item.href}
                  className={`dashboard-nav-pill ${active ? 'dashboard-nav-pill--active' : ''}`}
                  style={{
                    background: active ? `${colors.accent.primary}1a` : 'rgba(38,38,38,0.3)',
                    borderColor: active ? `${colors.accent.primary}80` : colors.border.primary,
                    color: active ? colors.accent.primary : colors.text.muted,
                  }}
                >
                  {active && (
                    <span className="dashboard-nav-pill__stripes" aria-hidden>
                      <span className="dashboard-nav-pill__stripe" />
                      <span className="dashboard-nav-pill__stripe" />
                      <span className="dashboard-nav-pill__stripe" />
                    </span>
                  )}
                  <span className="dashboard-nav-pill__label">{item.label}</span>
                </Link>
              );
            })}
            {overflowItems.length > 0 && (
              <Dropdown
                menu={{
                  items: overflowItems.map((item) => ({
                    key: item.key,
                    label: item.label,
                    onClick: () => router.push(item.href),
                    style: isItemActive(item.key)
                      ? { color: colors.accent.primary, fontWeight: 700 }
                      : undefined,
                  })),
                }}
                trigger={['click']}
              >
                <button
                  type="button"
                  className={`dashboard-nav-pill ${overflowHasActive ? 'dashboard-nav-pill--active' : ''}`}
                  style={{
                    background: overflowHasActive ? `${colors.accent.primary}1a` : 'rgba(38,38,38,0.3)',
                    borderColor: overflowHasActive ? `${colors.accent.primary}80` : colors.border.primary,
                    color: overflowHasActive ? colors.accent.primary : colors.text.muted,
                    cursor: 'pointer',
                  }}
                >
                  <span className="dashboard-nav-pill__label">More<EllipsisOutlined style={{ marginLeft: 4 }} /></span>
                </button>
              </Dropdown>
            )}
          </nav>

          {/* Right: User avatar only */}
          <div className="dashboard-status-cluster">
            <Dropdown menu={{ items: userMenuItems }} placement="bottomRight">
              <button type="button" className="dashboard-header-avatar-trigger" aria-label="User menu">
                <Avatar
                  size="small"
                  style={{ backgroundColor: colors.accent.primary, fontFamily: 'var(--font-mono)', fontWeight: 700 }}
                >
                  {userInitial}
                </Avatar>
              </button>
            </Dropdown>
          </div>
        </div>
      </Header>

      <Content className="dashboard-content">{children}</Content>
      <DashboardFooter connection={wsConnected} />
    </Layout>
  );
}
