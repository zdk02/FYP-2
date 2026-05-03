import axios from 'axios'

// Works everywhere:
//   - native dev: Vite proxies /api/* to 127.0.0.1:5000 (vite.config.js)
//   - docker:     nginx proxies /api/* to backend:5000 (nginx.conf)
//   - override:   set VITE_API_URL in frontend/.env.local (e.g. http://localhost:5000/api/v1)
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Long-running endpoints (attack runs, campaign starts, full scanner runs,
// MCP stdio handshakes) can legitimately take many minutes. Bump their
// per-request timeout so the browser doesn't give up on a still-running
// backend. Everything else keeps the default 30s.
api.interceptors.request.use((config) => {
  const url = config.url || ''
  if (/\/attacks\/.+\/test/.test(url)
      || /\/scanners\/.+\/run/.test(url)
      || /\/targets\/.+\/test-mcp/.test(url)
      || /\/campaigns\/.+\/start/.test(url)
      || /\/reports\/generate/.test(url)) {
    config.timeout = 15 * 60 * 1000    // 15 minutes
  }
  return config
})

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // Token is managed by the auth store
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    // Handle 401 errors (token expired)
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      // Try to refresh token
      const { useAuthStore } = await import('../stores/authStore')
      const refreshed = await useAuthStore.getState().refreshAccessToken()
      
      if (refreshed) {
        const token = useAuthStore.getState().accessToken
        originalRequest.headers.Authorization = `Bearer ${token}`
        return api(originalRequest)
      } else {
        // Redirect to login
        window.location.href = '/login'
      }
    }

    return Promise.reject(error)
  }
)

export default api

// Categories API
export const categoriesApi = {
  getAll: (withSubcategories = true) => 
    api.get(`/categories${withSubcategories ? '?include_subcategories=true' : ''}`).then(r => r.data),
  get: (id) => api.get(`/categories/${id}`).then(r => r.data),
  create: (data) => api.post('/categories', data).then(r => r.data),
  update: (id, data) => api.put(`/categories/${id}`, data).then(r => r.data),
  delete: (id) => api.delete(`/categories/${id}`).then(r => r.data),
}

// Subcategories API
export const subcategoriesApi = {
  getAll: (categoryId) => api.get(`/categories/${categoryId}/subcategories`).then(r => r.data),
  get: (id) => api.get(`/subcategories/${id}`).then(r => r.data),
  create: (categoryId, data) => api.post(`/categories/${categoryId}/subcategories`, data).then(r => r.data),
  update: (id, data) => api.put(`/subcategories/${id}`, data).then(r => r.data),
  delete: (id) => api.delete(`/subcategories/${id}`).then(r => r.data),
}

// Attacks API
export const attacksApi = {
  getAll: (params) => api.get('/attacks', { params }).then(r => r.data),
  get: (id) => api.get(`/attacks/${id}`).then(r => r.data),
  create: (data) => api.post('/attacks', data).then(r => r.data),
  update: (id, data) => api.put(`/attacks/${id}`, data).then(r => r.data),
  delete: (id) => api.delete(`/attacks/${id}`).then(r => r.data),
  clone: (id) => api.post(`/attacks/${id}/clone`).then(r => r.data),
  verify: (id) => api.post(`/attacks/${id}/verify`).then(r => r.data),
  test: (id, data) => api.post(`/attacks/${id}/test`, data).then(r => r.data),
  getSeverities: () => api.get('/attacks/severities').then(r => r.data),
  getTypes: () => api.get('/attacks/types').then(r => r.data),
}

// Targets API
export const targetsApi = {
  getAll: (params) => api.get('/targets', { params }).then(r => r.data),
  get: (id) => api.get(`/targets/${id}`).then(r => r.data),
  create: (data) => api.post('/targets', data).then(r => r.data),
  update: (id, data) => api.put(`/targets/${id}`, data).then(r => r.data),
  delete: (id) => api.delete(`/targets/${id}`).then(r => r.data),
  // Low-level TCP reachability only
  testConnection: (id) => api.post(`/targets/${id}/test-connection`).then(r => r.data),
  // Real MCP initialize + tools/list + resources/list discovery
  testMcp: (id) => api.post(`/targets/${id}/test-mcp`).then(r => r.data),
  // Legacy alias: default "Test" button calls the richer MCP discovery
  test: (id) => api.post(`/targets/${id}/test-mcp`).then(r => r.data),
}

// Campaigns API
export const campaignsApi = {
  getAll: (params) => api.get('/campaigns', { params }).then(r => r.data),
  get: (id) => api.get(`/campaigns/${id}`).then(r => r.data),
  create: (data) => api.post('/campaigns', data).then(r => r.data),
  update: (id, data) => api.put(`/campaigns/${id}`, data).then(r => r.data),
  delete: (id) => api.delete(`/campaigns/${id}`).then(r => r.data),
  start: (id) => api.post(`/campaigns/${id}/start`).then(r => r.data),
  pause: (id) => api.post(`/campaigns/${id}/pause`).then(r => r.data),
  resume: (id) => api.post(`/campaigns/${id}/resume`).then(r => r.data),
  stop: (id) => api.post(`/campaigns/${id}/stop`).then(r => r.data),
  getStats: (id) => api.get(`/campaigns/${id}/stats`).then(r => r.data),
  getExecutions: (id, params) => api.get(`/campaigns/${id}/executions`, { params }).then(r => r.data),
}

// Executions API
export const executionsApi = {
  getAll: (params) => api.get('/executions', { params }).then(r => r.data),
  get: (id) => api.get(`/executions/${id}`).then(r => r.data),
  retry: (id) => api.post(`/executions/${id}/retry`).then(r => r.data),
  cancel: (id) => api.post(`/executions/${id}/cancel`).then(r => r.data),
}

// Reports API — pro pentest reports (HTML / PDF / JSON / SARIF)
export const reportsApi = {
  getAll: (params) => api.get('/reports', { params }).then(r => r.data),
  get: (id) => api.get(`/reports/${id}`).then(r => r.data),
  generate: (body) => api.post(`/reports/generate`, body).then(r => r.data),
  preview: (body) => api.post(`/reports/preview`, body).then(r => r.data),
  update: (id, body) => api.put(`/reports/${id}`, body).then(r => r.data),
  download: (id, format = 'html') => api.get(`/reports/${id}/download`, {
    params: { format },
    responseType: 'blob',
  }),
  delete: (id) => api.delete(`/reports/${id}`).then(r => r.data),
}

// Scanners API (YAML-backed vulnerability scanner plugins)
export const scannersApi = {
  list: () => api.get('/scanners').then(r => r.data),
  get: (pluginId) => api.get(`/scanners/${pluginId}`).then(r => r.data),
  run: (pluginId, body) => api.post(`/scanners/${pluginId}/run`, body).then(r => r.data),

  listCves: (pluginId, params) => api.get(`/scanners/${pluginId}/cves`, { params }).then(r => r.data),

  listClients: (pluginId) => api.get(`/scanners/${pluginId}/clients`).then(r => r.data),
  getClient: (pluginId, key) => api.get(`/scanners/${pluginId}/clients/${key}`).then(r => r.data),
  createClient: (pluginId, data) => api.post(`/scanners/${pluginId}/clients`, data).then(r => r.data),
  updateClient: (pluginId, key, data) => api.put(`/scanners/${pluginId}/clients/${key}`, data).then(r => r.data),
  deleteClient: (pluginId, key) => api.delete(`/scanners/${pluginId}/clients/${key}`).then(r => r.data),

  getCve: (pluginId, key, cveId) => api.get(`/scanners/${pluginId}/clients/${key}/cves/${cveId}`).then(r => r.data),
  createCve: (pluginId, key, data) => api.post(`/scanners/${pluginId}/clients/${key}/cves`, data).then(r => r.data),
  updateCve: (pluginId, key, cveId, data) => api.put(`/scanners/${pluginId}/clients/${key}/cves/${cveId}`, data).then(r => r.data),
  deleteCve: (pluginId, key, cveId) => api.delete(`/scanners/${pluginId}/clients/${key}/cves/${cveId}`).then(r => r.data),

  getGlobals: (pluginId) => api.get(`/scanners/${pluginId}/globals`).then(r => r.data),
  updateGlobals: (pluginId, data) => api.put(`/scanners/${pluginId}/globals`, data).then(r => r.data),

  checkTypes: (pluginId) => api.get(`/scanners/${pluginId}/check-types`).then(r => r.data),

  listBackups: (pluginId) => api.get(`/scanners/${pluginId}/backups`).then(r => r.data),
  restore: (pluginId, filename) => api.post(`/scanners/${pluginId}/restore`, { filename }).then(r => r.data),
}

// Scans API
export const scansApi = {
  getAll: (params) => api.get('/scans', { params }).then(r => r.data),
  get: (id) => api.get(`/scans/${id}`).then(r => r.data),
  create: (data) => api.post('/scans', data).then(r => r.data),
  start: (id) => api.post(`/scans/${id}/start`).then(r => r.data),
  stop: (id) => api.post(`/scans/${id}/stop`).then(r => r.data),
  delete: (id) => api.delete(`/scans/${id}`).then(r => r.data),
  importResults: (id, data) => api.post(`/scans/${id}/import`, data).then(r => r.data),
}

// Users API
export const usersApi = {
  getAll: () => api.get('/users').then(r => r.data),
  get: (id) => api.get(`/users/${id}`).then(r => r.data),
  create: (data) => api.post('/users', data).then(r => r.data),
  update: (id, data) => api.put(`/users/${id}`, data).then(r => r.data),
  delete: (id) => api.delete(`/users/${id}`).then(r => r.data),
  changePassword: (id, data) => api.put(`/users/${id}/password`, data).then(r => r.data),
}

// Payloads API
export const payloadsApi = {
  getAll: (params) => api.get('/payloads', { params }).then(r => r.data),
  get: (id) => api.get(`/payloads/${id}`).then(r => r.data),
  create: (data) => api.post('/payloads', data).then(r => r.data),
  update: (id, data) => api.put(`/payloads/${id}`, data).then(r => r.data),
  delete: (id) => api.delete(`/payloads/${id}`).then(r => r.data),
}

// Techniques API
export const techniquesApi = {
  getAll: (params) => api.get('/techniques', { params }).then(r => r.data),
  get: (id) => api.get(`/techniques/${id}`).then(r => r.data),
  create: (data) => api.post('/techniques', data).then(r => r.data),
  update: (id, data) => api.put(`/techniques/${id}`, data).then(r => r.data),
  delete: (id) => api.delete(`/techniques/${id}`).then(r => r.data),
  getTactics: () => api.get('/techniques/tactics').then(r => r.data),
}

// Connections API
export const connectionsApi = {
  getAll: (params) => api.get('/connections', { params }).then(r => r.data),
  get: (id) => api.get(`/connections/${id}`).then(r => r.data),
  create: (data) => api.post('/connections', data).then(r => r.data),
  update: (id, data) => api.put(`/connections/${id}`, data).then(r => r.data),
  delete: (id) => api.delete(`/connections/${id}`).then(r => r.data),
  test: (id) => api.post(`/connections/${id}/test`).then(r => r.data),
  getServerTypes: () => api.get('/connections/server-types').then(r => r.data),
}

// Settings API
export const settingsApi = {
  getAll: () => api.get('/settings').then(r => r.data),
  get: (key) => api.get(`/settings/${key}`).then(r => r.data),
  update: (data) => api.put('/settings', data).then(r => r.data),
  updateOne: (key, value) => api.put(`/settings/${key}`, { value }).then(r => r.data),
}

// Dashboard API
export const dashboardApi = {
  getStats: () => api.get('/dashboard/stats').then(r => r.data),
  getRecentActivity: () => api.get('/dashboard/activity').then(r => r.data),
}

// Auth API
export const authApi = {
  login: (credentials) => api.post('/auth/login', credentials).then(r => r.data),
  logout: () => api.post('/auth/logout').then(r => r.data),
  refresh: (refreshToken) => api.post('/auth/refresh', { refresh_token: refreshToken }).then(r => r.data),
  me: () => api.get('/auth/me').then(r => r.data),
}

// Engagements API
export const engagementsApi = {
  list: () => api.get('/engagements').then(r => r.data),
  active: () => api.get('/engagements/active').then(r => r.data),
  get: (id) => api.get(`/engagements/${id}`).then(r => r.data),
  create: (data) => api.post('/engagements', data).then(r => r.data),
  update: (id, data) => api.put(`/engagements/${id}`, data).then(r => r.data),
  delete: (id) => api.delete(`/engagements/${id}`).then(r => r.data),
  activate: (id) => api.post(`/engagements/${id}/activate`).then(r => r.data),
  kill: (id) => api.post(`/engagements/${id}/kill`).then(r => r.data),
  revive: (id) => api.post(`/engagements/${id}/revive`).then(r => r.data),
  resetQuota: (id) => api.post(`/engagements/${id}/reset_quota`).then(r => r.data),
  uploadSow: (id, file) => {
    const fd = new FormData()
    fd.append('file', file)
    return api.post(`/engagements/${id}/sow`, fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }).then(r => r.data)
  },
  checkScope: (id, host) => api.post(`/engagements/${id}/check_scope`, { host }).then(r => r.data),
}

// Audit log API
export const auditApi = {
  list: (params) => api.get('/audit', { params }).then(r => r.data),
  verify: () => api.post('/audit/verify').then(r => r.data),
}

// Findings triage / dedup / diff
export const triageApi = {
  list: (params) => api.get('/findings/triage', { params }).then(r => r.data),
  upsert: (data) => api.post('/findings/triage', data).then(r => r.data),
  setStatus: (id, status, note) => api.post(`/findings/triage/${id}/status`, { status, note }).then(r => r.data),
  diff: (run_a_id, run_b_id) => api.post('/findings/diff', { run_a_id, run_b_id }).then(r => r.data),
}

// Compliance API
export const complianceApi = {
  mappings: () => api.get('/compliance/mappings').then(r => r.data),
  forAttack: (attackId) => api.get(`/compliance/attack/${attackId}`).then(r => r.data),
}

// Replay API
export const replayApi = {
  fromFinding: (executionId, findingId) =>
    api.post(`/executions/${executionId}/replay`, { finding_id: findingId }).then(r => r.data),
}
