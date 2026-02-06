'use client';

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { useStore } from 'zustand';
import { createAppStore, type AppStore } from './app-store';
import { createAuthStore, type AuthStore } from './auth-store';

/**
 * Store context for Zustand stores
 */
interface StoreContext {
  appStore: ReturnType<typeof createAppStore>;
  authStore: ReturnType<typeof createAuthStore>;
}

const StoreContext = createContext<StoreContext | null>(null);

/**
 * Store provider component (lazy init so stores are created once).
 * Triggers auth rehydration on client mount so persisted login survives reload.
 */
export function StoreProvider({ children }: { children: ReactNode }) {
  const [contextValue] = useState<StoreContext>(() => ({
    appStore: createAppStore(),
    authStore: createAuthStore(),
  }));

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const authStore = contextValue.authStore as { persist?: { rehydrate: () => void } };
    const appStore = contextValue.appStore as { persist?: { rehydrate: () => void } };
    authStore.persist?.rehydrate?.();
    appStore.persist?.rehydrate?.();
  }, [contextValue.authStore, contextValue.appStore]);

  return (
    <StoreContext.Provider value={contextValue}>
      {children}
    </StoreContext.Provider>
  );
}

/**
 * Hook to access the app store
 */
export function useAppStore<T>(selector: (state: AppStore) => T): T {
  const context = useContext(StoreContext);
  if (!context) {
    throw new Error('useAppStore must be used within StoreProvider');
  }
  return useStore(context.appStore, selector);
}

/**
 * Hook to access the auth store
 */
export function useAuthStore<T>(selector: (state: AuthStore) => T): T {
  const context = useContext(StoreContext);
  if (!context) {
    throw new Error('useAuthStore must be used within StoreProvider');
  }
  return useStore(context.authStore, selector);
}
