/**
 * App Store Tests
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

beforeEach(() => {
  vi.resetModules();
});

describe('App Store', () => {
  it('should initialize with default values', async () => {
    const { useAppStore } = await import('@/store/app-store');
    const state = useAppStore.getState();

    expect(state.wsConnected).toBe(false);
    expect(state.activeScans).toEqual([]);
    expect(state.currentProject).toBeNull();
    expect(state.sidebarCollapsed).toBe(false);
  });

  it('should set WebSocket connection status', async () => {
    const { useAppStore } = await import('@/store/app-store');

    useAppStore.getState().setWsConnected(true);
    expect(useAppStore.getState().wsConnected).toBe(true);

    useAppStore.getState().setWsConnected(false);
    expect(useAppStore.getState().wsConnected).toBe(false);
  });

  it('should set current project', async () => {
    const { useAppStore } = await import('@/store/app-store');

    const project = {
      project_id: 'test-id',
      name: 'Test Project',
      description: 'Test description',
      status: 'active' as const,
      scope: ['example.com'],
      out_of_scope: [],
      tags: [],
      created_at: '2024-01-01T00:00:00Z',
      owner_id: 'user-id',
    };

    useAppStore.getState().setCurrentProject(project);
    expect(useAppStore.getState().currentProject).toEqual(project);
  });

  it('should add active scan', async () => {
    const { useAppStore } = await import('@/store/app-store');

    const scan = {
      scan_id: 'scan-1',
      project_id: 'project-1',
      target: 'example.com',
      scan_type: 'full_recon' as const,
      status: 'running' as const,
      progress: 50,
      phase: 'enumeration' as const,
      created_at: '2024-01-01T00:00:00Z',
    };

    useAppStore.getState().addActiveScan(scan);
    expect(useAppStore.getState().activeScans).toContainEqual(scan);
  });

  it('should update active scan', async () => {
    const { useAppStore } = await import('@/store/app-store');

    const scan = {
      scan_id: 'scan-1',
      project_id: 'project-1',
      target: 'example.com',
      scan_type: 'full_recon' as const,
      status: 'running' as const,
      progress: 50,
      phase: 'enumeration' as const,
      created_at: '2024-01-01T00:00:00Z',
    };

    useAppStore.getState().addActiveScan(scan);
    useAppStore.getState().updateActiveScan('scan-1', { progress: 75 });

    const updatedScan = useAppStore.getState().activeScans.find(
      (s) => s.scan_id === 'scan-1'
    );
    expect(updatedScan?.progress).toBe(75);
  });

  it('should remove active scan', async () => {
    const { useAppStore } = await import('@/store/app-store');

    const scan = {
      scan_id: 'scan-1',
      project_id: 'project-1',
      target: 'example.com',
      scan_type: 'full_recon' as const,
      status: 'running' as const,
      progress: 50,
      phase: 'enumeration' as const,
      created_at: '2024-01-01T00:00:00Z',
    };

    useAppStore.getState().addActiveScan(scan);
    useAppStore.getState().removeScan('scan-1');

    expect(useAppStore.getState().activeScans).toHaveLength(0);
  });

  it('should toggle sidebar', async () => {
    const { useAppStore } = await import('@/store/app-store');

    expect(useAppStore.getState().sidebarCollapsed).toBe(false);

    useAppStore.getState().toggleSidebar();
    expect(useAppStore.getState().sidebarCollapsed).toBe(true);

    useAppStore.getState().toggleSidebar();
    expect(useAppStore.getState().sidebarCollapsed).toBe(false);
  });
});
