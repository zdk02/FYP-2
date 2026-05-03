import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { engagementsApi } from '../services/api'

export const useEngagementStore = create(
  persist(
    (set, get) => ({
      active: null,
      list: [],
      isLoading: false,
      error: null,

      load: async () => {
        set({ isLoading: true, error: null })
        try {
          const items = await engagementsApi.list()
          const active = items.find((e) => e.is_active_default && e.status === 'active') || null
          set({ list: items, active, isLoading: false })
          return { items, active }
        } catch (e) {
          set({ error: e.message, isLoading: false })
          return { items: [], active: null }
        }
      },

      refreshActive: async () => {
        try {
          const r = await engagementsApi.active()
          set({ active: r.engagement || null })
          return r.engagement
        } catch (e) {
          return null
        }
      },

      activate: async (id) => {
        await engagementsApi.activate(id)
        return get().load()
      },

      kill: async (id) => {
        await engagementsApi.kill(id)
        return get().load()
      },

      revive: async (id) => {
        await engagementsApi.revive(id)
        return get().load()
      },

      resetQuota: async (id) => {
        await engagementsApi.resetQuota(id)
        return get().load()
      },
    }),
    {
      name: 'minerva-engagement',
      partialize: (s) => ({ active: s.active }),
    }
  )
)
