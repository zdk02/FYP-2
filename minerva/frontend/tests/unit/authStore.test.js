/**
 * Unit tests for src/stores/authStore.js (Zustand auth store).
 *
 * Covers the pure logic of role checks and the state transitions for
 * login / logout / updateUser / refresh. The axios layer is mocked so
 * no network is actually touched.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'

// Mock the api module BEFORE importing the store.
vi.mock('../../src/services/api', () => {
  const post = vi.fn()
  return {
    default: {
      post,
      defaults: { headers: { common: {} } },
    },
  }
})

import api from '../../src/services/api'
import { useAuthStore } from '../../src/stores/authStore'


function resetStore() {
  useAuthStore.setState({
    user: null,
    accessToken: null,
    refreshToken: null,
    isAuthenticated: false,
    isLoading: false,
    error: null,
  })
}


describe('authStore — role helpers', () => {
  beforeEach(() => {
    resetStore()
  })

  it('hasRole returns false when no user is set', () => {
    expect(useAuthStore.getState().hasRole('admin')).toBe(false)
  })

  it('hasRole accepts a single role string', () => {
    useAuthStore.setState({ user: { role: 'admin' } })
    expect(useAuthStore.getState().hasRole('admin')).toBe(true)
    expect(useAuthStore.getState().hasRole('manager')).toBe(false)
  })

  it('hasRole accepts a list of allowed roles', () => {
    useAuthStore.setState({ user: { role: 'manager' } })
    expect(useAuthStore.getState().hasRole(['admin', 'manager'])).toBe(true)
    expect(useAuthStore.getState().hasRole(['admin', 'analyst'])).toBe(false)
  })

  it('isAdmin is true only for admin role', () => {
    useAuthStore.setState({ user: { role: 'admin' } })
    expect(useAuthStore.getState().isAdmin()).toBe(true)

    useAuthStore.setState({ user: { role: 'manager' } })
    expect(useAuthStore.getState().isAdmin()).toBe(false)
  })

  it('isManager is true for admin and manager roles', () => {
    useAuthStore.setState({ user: { role: 'admin' } })
    expect(useAuthStore.getState().isManager()).toBe(true)

    useAuthStore.setState({ user: { role: 'manager' } })
    expect(useAuthStore.getState().isManager()).toBe(true)

    useAuthStore.setState({ user: { role: 'analyst' } })
    expect(useAuthStore.getState().isManager()).toBe(false)
  })

  it('isAdmin is false when no user is set', () => {
    expect(useAuthStore.getState().isAdmin()).toBe(false)
  })
})


describe('authStore — login flow', () => {
  beforeEach(() => {
    resetStore()
    api.post.mockReset()
    api.defaults.headers.common = {}
  })

  it('login success sets user, tokens, and isAuthenticated', async () => {
    api.post.mockResolvedValueOnce({
      data: {
        user: { id: 1, email: 'admin@minerva.local', role: 'admin' },
        access_token: 'access-abc',
        refresh_token: 'refresh-xyz',
      },
    })

    const result = await useAuthStore.getState().login('admin@minerva.local', 'pw')

    expect(result.success).toBe(true)
    const s = useAuthStore.getState()
    expect(s.isAuthenticated).toBe(true)
    expect(s.user.email).toBe('admin@minerva.local')
    expect(s.accessToken).toBe('access-abc')
    expect(s.refreshToken).toBe('refresh-xyz')
    expect(s.isLoading).toBe(false)
    expect(s.error).toBeNull()
  })

  it('login success sets Authorization header on api instance', async () => {
    api.post.mockResolvedValueOnce({
      data: { user: { id: 1 }, access_token: 'tok-1', refresh_token: 'r-1' },
    })

    await useAuthStore.getState().login('a@b.c', 'pw')

    expect(api.defaults.headers.common['Authorization']).toBe('Bearer tok-1')
  })

  it('login failure surfaces the server error message', async () => {
    api.post.mockRejectedValueOnce({
      response: { data: { error: 'Invalid credentials' } },
    })

    const result = await useAuthStore.getState().login('bad@user.com', 'wrong')

    expect(result.success).toBe(false)
    expect(result.error).toBe('Invalid credentials')
    const s = useAuthStore.getState()
    expect(s.isAuthenticated).toBe(false)
    expect(s.user).toBeNull()
    expect(s.error).toBe('Invalid credentials')
    expect(s.isLoading).toBe(false)
  })

  it('login failure with no error message uses a generic fallback', async () => {
    api.post.mockRejectedValueOnce({})  // no response object at all

    const result = await useAuthStore.getState().login('a@b.c', 'pw')

    expect(result.success).toBe(false)
    expect(result.error).toBe('Login failed')
  })
})


describe('authStore — logout', () => {
  beforeEach(() => {
    resetStore()
    api.post.mockReset()
    api.defaults.headers.common = { Authorization: 'Bearer existing' }
    useAuthStore.setState({
      user: { id: 1, role: 'admin' },
      accessToken: 'tok',
      refreshToken: 'ref',
      isAuthenticated: true,
    })
  })

  it('logout clears user, tokens, and auth header', async () => {
    api.post.mockResolvedValueOnce({})

    await useAuthStore.getState().logout()

    const s = useAuthStore.getState()
    expect(s.user).toBeNull()
    expect(s.accessToken).toBeNull()
    expect(s.refreshToken).toBeNull()
    expect(s.isAuthenticated).toBe(false)
    expect(api.defaults.headers.common['Authorization']).toBeUndefined()
  })

  it('logout still clears state when the API call fails', async () => {
    api.post.mockRejectedValueOnce(new Error('network down'))

    await useAuthStore.getState().logout()

    expect(useAuthStore.getState().isAuthenticated).toBe(false)
    expect(useAuthStore.getState().user).toBeNull()
  })
})


describe('authStore — updateUser', () => {
  beforeEach(() => {
    resetStore()
    useAuthStore.setState({
      user: { id: 1, email: 'a@b.c', role: 'analyst', name: 'Alice' },
    })
  })

  it('updateUser merges new fields without losing existing ones', () => {
    useAuthStore.getState().updateUser({ name: 'Alice K.' })
    const u = useAuthStore.getState().user
    expect(u.name).toBe('Alice K.')
    expect(u.email).toBe('a@b.c')
    expect(u.role).toBe('analyst')
  })
})


describe('authStore — checkAuth', () => {
  beforeEach(() => {
    resetStore()
    api.defaults.headers.common = {}
  })

  it('returns true and sets auth header when a token exists', () => {
    useAuthStore.setState({ accessToken: 'persisted-tok' })
    expect(useAuthStore.getState().checkAuth()).toBe(true)
    expect(api.defaults.headers.common['Authorization']).toBe('Bearer persisted-tok')
  })

  it('returns false when no token is present', () => {
    expect(useAuthStore.getState().checkAuth()).toBe(false)
  })
})
