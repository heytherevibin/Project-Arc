import { createStore } from 'zustand/vanilla';
import { createJSONStorage, persist } from 'zustand/middleware';
import type { Project, Scan, Target } from '@/types';

/**
 * Application state store
 */
export interface AppStore {
  // Current project
  currentProject: Project | null;
  setCurrentProject: (project: Project | null) => void;
  
  // Projects list
  projects: Project[];
  setProjects: (projects: Project[]) => void;
  
  // Scans
  activeScans: Scan[];
  addActiveScan: (scan: Scan) => void;
  updateScan: (scanId: string, updates: Partial<Scan>) => void;
  removeScan: (scanId: string) => void;
  
  // Targets
  targets: Target[];
  setTargets: (targets: Target[]) => void;
  addTarget: (target: Target) => void;
  
  // UI State
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  
  // WebSocket connection
  wsConnected: boolean;
  setWsConnected: (connected: boolean) => void;
  
  // Notifications
  notifications: Notification[];
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp'>) => void;
  dismissNotification: (id: string) => void;
  clearNotifications: () => void;
}

interface Notification {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message: string;
  timestamp: number;
}

/**
 * Create the app store with persisted current project
 */
export function createAppStore() {
  return createStore<AppStore>()(
    persist(
      (set) => ({
        currentProject: null,
        setCurrentProject: (project) => set({ currentProject: project }),
        projects: [],
        setProjects: (projects) => set({ projects }),
        activeScans: [],
        addActiveScan: (scan) => set((state) => ({
          activeScans: [...state.activeScans, scan],
        })),
        updateScan: (scanId, updates) => set((state) => ({
          activeScans: state.activeScans.map((scan) =>
            scan.scan_id === scanId ? { ...scan, ...updates } : scan
          ),
        })),
        removeScan: (scanId) => set((state) => ({
          activeScans: state.activeScans.filter((scan) => scan.scan_id !== scanId),
        })),
        targets: [],
        setTargets: (targets) => set({ targets }),
        addTarget: (target) => set((state) => ({
          targets: [...state.targets, target],
        })),
        sidebarCollapsed: false,
        toggleSidebar: () => set((state) => ({
          sidebarCollapsed: !state.sidebarCollapsed,
        })),
        wsConnected: false,
        setWsConnected: (connected) => set({ wsConnected: connected }),
        notifications: [],
        addNotification: (notification) => set((state) => ({
          notifications: [
            ...state.notifications,
            {
              ...notification,
              id: crypto.randomUUID(),
              timestamp: Date.now(),
            },
          ],
        })),
        dismissNotification: (id) => set((state) => ({
          notifications: state.notifications.filter((n) => n.id !== id),
        })),
        clearNotifications: () => set({ notifications: [] }),
      }),
      {
        name: 'arc-app',
        storage: createJSONStorage(() => localStorage),
        partialize: (state) => ({ currentProject: state.currentProject }),
        merge: (persisted, current) => ({
          ...current,
          ...(persisted ?? {}),
        }),
        skipHydration: true,
      }
    )
  );
}
