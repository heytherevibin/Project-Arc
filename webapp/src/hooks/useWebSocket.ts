/**
 * WebSocket Hook
 *
 * Manages WebSocket connection for real-time updates.
 * On scan_completed/scan_failed, revalidates SWR caches so Overview, Scans, and Vulnerabilities update immediately.
 */

import { useEffect, useRef, useCallback } from 'react';
import { mutate } from 'swr';
import { useAppStore, useAuthStore } from '@/store/provider';
import type { WSMessage } from '@/types';

// Prefer explicit WS URL; fallback to API URL with ws scheme so status shows Connected when API is set
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? '';
const WS_URL =
  (process.env.NEXT_PUBLIC_WS_URL ?? '').trim() ||
  (API_URL ? API_URL.replace(/^http/, 'ws') : '');
const RECONNECT_DELAY = 3000; // 3 seconds
const PING_INTERVAL = 30000; // 30 seconds

interface UseWebSocketOptions {
  onMessage?: (message: WSMessage) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  projectId?: string;
  scanId?: string;
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const wsRef = useRef<WebSocket | null>(null);
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const connectRef = useRef<() => void>(() => {});
  const optionsRef = useRef(options);
  optionsRef.current = options;

  const accessToken = useAuthStore((state) => state.accessToken);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const setWsConnected = useAppStore((state) => state.setWsConnected);
  const updateScan = useAppStore((state) => state.updateScan);
  const addNotification = useAppStore((state) => state.addNotification);

  const connect = useCallback(() => {
    if (!accessToken || !isAuthenticated) {
      return;
    }
    if (!WS_URL) {
      console.warn('WebSocket disabled: set NEXT_PUBLIC_WS_URL or NEXT_PUBLIC_API_URL');
      return;
    }

    // Close existing connection
    if (wsRef.current) {
      wsRef.current.close();
    }

    const base = WS_URL.startsWith('ws') ? WS_URL : WS_URL.replace(/^http/, 'ws');
    const url = `${base}${base.endsWith('/') ? '' : '/'}ws?token=${encodeURIComponent(accessToken)}`;
    const ws = new WebSocket(url);

    ws.onopen = () => {
      const opts = optionsRef.current;
      console.log('WebSocket connected');
      setWsConnected(true);
      opts.onConnect?.();

      pingIntervalRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'ping' }));
        }
      }, PING_INTERVAL);

      if (opts.projectId) {
        ws.send(JSON.stringify({ type: 'subscribe_project', project_id: opts.projectId }));
      }
      if (opts.scanId) {
        ws.send(JSON.stringify({ type: 'subscribe_scan', scan_id: opts.scanId }));
      }
    };

    ws.onmessage = (event) => {
      try {
        const message: WSMessage = JSON.parse(event.data);
        const opts = optionsRef.current;

        switch (message.event) {
          case 'scan_progress': {
            const progressData = message.data as any;
            updateScan(progressData.scan_id, {
              progress: progressData.progress,
              phase: progressData.phase,
            });
            break;
          }
          case 'scan_completed': {
            const completedData = message.data as { scan_id?: string; project_id?: string; target?: string };
            updateScan(completedData.scan_id!, { status: 'completed', progress: 100 });
            addNotification({
              type: 'success',
              title: 'Scan Completed',
              message: `Scan for ${completedData.target || 'target'} has completed.`,
            });
            const pid = completedData.project_id;
            if (pid) {
              mutate(`/api/v1/projects/${pid}/stats`);
              mutate(`/api/v1/scans?project_id=${pid}`);
              mutate(`/api/v1/scans?project_id=${pid}&page_size=5`);
              mutate(`/api/v1/vulnerabilities?project_id=${pid}`);
              mutate(`/api/v1/vulnerabilities?project_id=${pid}&page_size=5`);
            }
            break;
          }
          case 'scan_failed': {
            const failedData = message.data as { scan_id?: string; project_id?: string; error?: string };
            updateScan(failedData.scan_id!, { status: 'failed' });
            addNotification({
              type: 'error',
              title: 'Scan Failed',
              message: failedData.error || 'An error occurred during the scan.',
            });
            const pid = failedData.project_id;
            if (pid) {
              mutate(`/api/v1/projects/${pid}/stats`);
              mutate(`/api/v1/scans?project_id=${pid}`);
              mutate(`/api/v1/scans?project_id=${pid}&page_size=5`);
            }
            break;
          }
          case 'vulnerability_found': {
            const vulnData = message.data as { project_id?: string; vulnerability?: { severity?: string; name?: string } };
            addNotification({
              type: 'warning',
              title: `${vulnData.vulnerability?.severity?.toUpperCase() || 'New'} Vulnerability Found`,
              message: vulnData.vulnerability?.name || 'A new vulnerability was discovered.',
            });
            const pid = vulnData.project_id;
            if (pid) {
              mutate(`/api/v1/projects/${pid}/stats`);
              mutate(`/api/v1/vulnerabilities?project_id=${pid}`);
              mutate(`/api/v1/vulnerabilities?project_id=${pid}&page_size=5`);
            }
            break;
          }
        }
        opts.onMessage?.(message);
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error);
      }
    };

    ws.onclose = (event) => {
      const opts = optionsRef.current;
      setWsConnected(false);
      opts.onDisconnect?.();

      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = null;
      }

      // Only reconnect if we had a successful connection before (code 1000 = normal close)
      // Don't reconnect on initial connection failures to avoid spam when backend is offline
      if (isAuthenticated && event.wasClean) {
        reconnectTimeoutRef.current = setTimeout(() => {
          connectRef.current();
        }, RECONNECT_DELAY);
      }
    };

    ws.onerror = () => {
      // Silently handle - connection errors are expected when backend is offline
    };

    wsRef.current = ws;
  }, [accessToken, isAuthenticated, setWsConnected, updateScan, addNotification]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current);
      pingIntervalRef.current = null;
    }
    
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);
  
  const subscribeToScan = useCallback((scanId: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'subscribe_scan',
        scan_id: scanId,
      }));
    }
  }, []);
  
  const unsubscribeFromScan = useCallback((scanId: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'unsubscribe_scan',
        scan_id: scanId,
      }));
    }
  }, []);
  
  // Keep connectRef updated so reconnect timeout can call latest connect
  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  // Connect on mount when authenticated; disconnect on unmount
  useEffect(() => {
    if (isAuthenticated && accessToken) {
      connect();
    }
    return () => {
      disconnect();
    };
  }, [isAuthenticated, accessToken, connect, disconnect]);
  
  // Update subscriptions when project/scan changes
  useEffect(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      if (options.projectId) {
        wsRef.current.send(JSON.stringify({
          type: 'subscribe_project',
          project_id: options.projectId,
        }));
      }
    }
  }, [options.projectId]);
  
  useEffect(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      if (options.scanId) {
        wsRef.current.send(JSON.stringify({
          type: 'subscribe_scan',
          scan_id: options.scanId,
        }));
      }
    }
  }, [options.scanId]);
  
  return {
    connect,
    disconnect,
    subscribeToScan,
    unsubscribeFromScan,
  };
}
