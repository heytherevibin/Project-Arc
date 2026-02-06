/**
 * Auth Store Tests
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Reset modules before each test to get fresh store
beforeEach(() => {
  vi.resetModules();
  localStorage.clear();
});

describe('Auth Store', () => {
  it('should initialize with no user', async () => {
    const { useAuthStore } = await import('@/store/auth-store');
    const state = useAuthStore.getState();

    expect(state.user).toBeNull();
    expect(state.accessToken).toBeNull();
    expect(state.isAuthenticated).toBe(false);
  });

  it('should set user and mark as authenticated', async () => {
    const { useAuthStore } = await import('@/store/auth-store');

    const testUser = {
      user_id: 'test-id',
      email: 'test@example.com',
      name: 'Test User',
      roles: ['user'],
    };

    useAuthStore.getState().setUser(testUser);

    const state = useAuthStore.getState();
    expect(state.user).toEqual(testUser);
    expect(state.isAuthenticated).toBe(true);
  });

  it('should set tokens', async () => {
    const { useAuthStore } = await import('@/store/auth-store');

    useAuthStore.getState().setTokens('access-token', 'refresh-token');

    const state = useAuthStore.getState();
    expect(state.accessToken).toBe('access-token');
    expect(state.refreshToken).toBe('refresh-token');
  });

  it('should clear state on logout', async () => {
    const { useAuthStore } = await import('@/store/auth-store');

    // Set up authenticated state
    useAuthStore.getState().setUser({
      user_id: 'test-id',
      email: 'test@example.com',
      name: 'Test User',
      roles: ['user'],
    });
    useAuthStore.getState().setTokens('access', 'refresh');

    // Logout
    useAuthStore.getState().logout();

    const state = useAuthStore.getState();
    expect(state.user).toBeNull();
    expect(state.accessToken).toBeNull();
    expect(state.refreshToken).toBeNull();
    expect(state.isAuthenticated).toBe(false);
  });
});
