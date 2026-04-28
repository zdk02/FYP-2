import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import api from '../services/api'

export const useAuthStore = create(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      login: async (email, password) => {
        set({ isLoading: true, error: null })
        try {
          const response = await api.post('/auth/login', { email, password })
          const { user, access_token, refresh_token } = response.data
          
          set({
            user,
            accessToken: access_token,
            refreshToken: refresh_token,
            isAuthenticated: true,
            isLoading: false,
          })
          
          // Set token in API instance
          api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`
          
          return { success: true }
        } catch (error) {
          const message = error.response?.data?.error || 'Login failed'
          set({ error: message, isLoading: false })
          return { success: false, error: message }
        }
      },

      logout: async () => {
        try {
          await api.post('/auth/logout')
        } catch (error) {
          // Ignore logout errors
        }
        
        set({
          user: null,
          accessToken: null,
          refreshToken: null,
          isAuthenticated: false,
        })
        
        delete api.defaults.headers.common['Authorization']
      },

      refreshAccessToken: async () => {
        const { refreshToken } = get()
        if (!refreshToken) return false

        try {
          const response = await api.post('/auth/refresh', null, {
            headers: { Authorization: `Bearer ${refreshToken}` }
          })
          const { access_token } = response.data
          
          set({ accessToken: access_token })
          api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`
          
          return true
        } catch (error) {
          get().logout()
          return false
        }
      },

      updateUser: (userData) => {
        set({ user: { ...get().user, ...userData } })
      },

      checkAuth: () => {
        const { accessToken } = get()
        if (accessToken) {
          api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`
          return true
        }
        return false
      },

      hasRole: (roles) => {
        const { user } = get()
        if (!user) return false
        if (typeof roles === 'string') return user.role === roles
        return roles.includes(user.role)
      },

      isAdmin: () => get().user?.role === 'admin',
      isManager: () => ['admin', 'manager'].includes(get().user?.role),
    }),
    {
      name: 'aegis-auth',
      partialize: (state) => ({
        user: state.user,
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
)
