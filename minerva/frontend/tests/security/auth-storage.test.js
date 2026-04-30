/**
 * Frontend auth-storage security tests.
 *
 * The Zustand auth store uses the `persist` middleware to keep users
 * logged in across reloads. We need to be sure:
 *   1. The persisted snapshot only includes declared fields — never
 *      transient state like `error` or `isLoading`.
 *   2. Logout clears the persisted state so a returning user has no
 *      orphaned tokens in localStorage.
 *   3. Tokens are not exposed in window.location or document.cookie
 *      (they should live in the JS-only Zustand store + localStorage).
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'

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


// The Zustand persist middleware uses this localStorage key.
const PERSIST_KEY = 'aegis-auth'


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


describe('auth storage — persist middleware only saves declared fields', () => {
  beforeEach(() => {
    resetStore()
    api.post.mockReset()
    api.defaults.headers.common = {}
    localStorage.clear()
  })

  it('after a successful login, only user/tokens/isAuthenticated are persisted', async () => {
    api.post.mockResolvedValueOnce({
      data: {
        user: { id: 1, email: 'a@b.c', role: 'admin' },
        access_token: 'tok-A',
        refresh_token: 'tok-R',
      },
    })

    await useAuthStore.getState().login('a@b.c', 'pw')

    const raw = localStorage.getItem(PERSIST_KEY)
    expect(raw).toBeTruthy()
    const persisted = JSON.parse(raw).state

    // Declared fields are present.
    expect(persisted.user).toBeTruthy()
    expect(persisted.accessToken).toBe('tok-A')
    expect(persisted.refreshToken).toBe('tok-R')
    expect(persisted.isAuthenticated).toBe(true)

    // Transient fields must NOT be persisted.
    expect(persisted).not.toHaveProperty('isLoading')
    expect(persisted).not.toHaveProperty('error')
  })

  it('a failed login does not put a token in localStorage', async () => {
    api.post.mockRejectedValueOnce({
      response: { data: { error: 'Invalid credentials' } },
    })

    await useAuthStore.getState().login('bad@user.com', 'pw')

    const raw = localStorage.getItem(PERSIST_KEY)
    if (raw) {
      const persisted = JSON.parse(raw).state
      expect(persisted.accessToken).toBeFalsy()
      expect(persisted.refreshToken).toBeFalsy()
      expect(persisted.isAuthenticated).not.toBe(true)
    }
  })
})


describe('auth storage — logout fully clears tokens', () => {
  beforeEach(() => {
    resetStore()
    api.post.mockReset()
    api.defaults.headers.common = { Authorization: 'Bearer existing' }
    useAuthStore.setState({
      user: { id: 1, role: 'admin' },
      accessToken: 'live-token',
      refreshToken: 'live-refresh',
      isAuthenticated: true,
    })
  })

  it('logout removes Authorization header from the api instance', async () => {
    api.post.mockResolvedValueOnce({})
    await useAuthStore.getState().logout()
    expect(api.defaults.headers.common['Authorization']).toBeUndefined()
  })

  it('logout sets accessToken / refreshToken / user to null', async () => {
    api.post.mockResolvedValueOnce({})
    await useAuthStore.getState().logout()
    const s = useAuthStore.getState()
    expect(s.accessToken).toBeNull()
    expect(s.refreshToken).toBeNull()
    expect(s.user).toBeNull()
    expect(s.isAuthenticated).toBe(false)
  })

  it('logout still clears in-memory state when the API call fails', async () => {
    api.post.mockRejectedValueOnce(new Error('network down'))
    await useAuthStore.getState().logout()
    const s = useAuthStore.getState()
    expect(s.accessToken).toBeNull()
    expect(s.isAuthenticated).toBe(false)
  })
})


describe('auth storage — tokens never leak to global state', () => {
  beforeEach(() => {
    resetStore()
    api.post.mockReset()
    localStorage.clear()
  })

  it('tokens do not appear in window.location after login', async () => {
    api.post.mockResolvedValueOnce({
      data: {
        user: { id: 1, email: 'a@b.c', role: 'admin' },
        access_token: 'super-secret-token',
        refresh_token: 'super-secret-refresh',
      },
    })

    await useAuthStore.getState().login('a@b.c', 'pw')

    expect(window.location.href).not.toContain('super-secret-token')
    expect(window.location.search).not.toContain('super-secret-token')
    expect(window.location.hash).not.toContain('super-secret-token')
  })

  it('tokens do not appear in document.cookie after login', async () => {
    api.post.mockResolvedValueOnce({
      data: {
        user: { id: 1, email: 'a@b.c', role: 'admin' },
        access_token: 'cookie-test-token',
        refresh_token: 'cookie-test-refresh',
      },
    })

    await useAuthStore.getState().login('a@b.c', 'pw')

    expect(document.cookie).not.toContain('cookie-test-token')
    expect(document.cookie).not.toContain('cookie-test-refresh')
  })
})
