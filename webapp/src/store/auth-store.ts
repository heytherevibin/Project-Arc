import { createStore } from 'zustand/vanilla';
import { persist, createJSONStorage } from 'zustand/middleware';

/**
 * User information
 */
export interface User {
  user_id: string;
  email: string;
  roles: string[];
}

/**
 * Authentication state store
 */
export interface AuthStore {
  // User state
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  
  // Authentication status
  isAuthenticated: boolean;
  isLoading: boolean;
  
  // Actions
  setUser: (user: User | null) => void;
  setTokens: (accessToken: string, refreshToken: string) => void;
  setLoading: (loading: boolean) => void;
  logout: () => void;
}

/**
 * Create the auth store with persistence
 */
export function createAuthStore() {
  return createStore<AuthStore>()(
    persist(
      (set) => ({
        // User state
        user: null,
        accessToken: null,
        refreshToken: null,
        
        // Authentication status
        isAuthenticated: false,
        isLoading: true,
        
        // Actions
        setUser: (user) => set({
          user,
          isAuthenticated: user !== null,
        }),
        
        setTokens: (accessToken, refreshToken) => set({
          accessToken,
          refreshToken,
          isAuthenticated: true,
        }),
        
        setLoading: (loading) => set({ isLoading: loading }),
        
        logout: () => set({
          user: null,
          accessToken: null,
          refreshToken: null,
          isAuthenticated: false,
        }),
      }),
      {
        name: 'arc-auth',
        storage: createJSONStorage(() => localStorage),
        partialize: (state) => ({
          accessToken: state.accessToken,
          refreshToken: state.refreshToken,
          user: state.user,
          isAuthenticated: state.isAuthenticated,
        }),
        merge: (persisted, current) => ({
          ...current,
          ...(persisted ?? {}),
          isLoading: false,
        }),
        // Defer hydration until client mount so we never run getItem on server
        skipHydration: true,
      }
    )
  );
}
